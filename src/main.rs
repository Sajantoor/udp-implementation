use etherparse::{Ipv4HeaderSlice, UdpHeaderSlice};
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
};
use tun_tap::{Iface, Mode};

const MAX_IP_PACKET_SIZE: usize = 65535;
const BUFFER_SIZE: usize = 4096;
const IPV4_PROTCOL: u16 = 0x0800;
const UDP_PROTOCOL: u8 = 17;
const TUN_BYTES: usize = 4;
const UDP_HEADER_SIZE: usize = 8;

struct FragmentedPacket {
    buffer: [u8; MAX_IP_PACKET_SIZE],
    size: usize,
    is_ready: bool,
}

fn check_network_layer_packet(buffer: [u8; BUFFER_SIZE]) -> bool {
    // By tuntap docs: https://docs.kernel.org/networking/tuntap.html
    // the first 2 bytes are flags and the next 2 bytes are protocol
    // let flags = u16::from_be_bytes([buffer[0], buffer[1]]);
    let ether_protocol = u16::from_be_bytes([buffer[2], buffer[3]]);

    // After that is the raw protocol(IP, IPv6, etc) frame.
    // Ignore any non-IPv4 packets
    // TODO: Support ipv6 as well
    if ether_protocol != IPV4_PROTCOL {
        return false;
    }

    return true;
}

fn handle_ttl(header: &Ipv4HeaderSlice) {
    let ttl = header.ttl();
    if ttl != 0 {
        return;
    }

    // TODO: According to RFC 791, we should send an ICMP packet back
    // to the sender to let them know the packet has expired
    println!("TTL is 0");
}

fn validate_ip_checksum(header: &Ipv4HeaderSlice) {
    // RFC 791 specification:
    // The checksum field is the 16 bit one's complement of the one's
    // complement sum of all 16 bit words in the header.  For purposes of
    // computing the checksum, the value of the checksum field is zero.

    // Validate the checksum of the IP header
    // let ip_checksum = header.header_checksum();
    // if ip_checksum != 0 {
    //     println!("Invalid IP checksum");
    //     continue;
    // }
}

fn handle_fragmented_packet<'a>(
    header: &'a Ipv4HeaderSlice<'a>,
    buffer: &'a [u8],
    nbytes: usize,
    ip_header_size: usize,
    fragmented_packets: &'a mut HashMap<u16, FragmentedPacket>,
) -> &'a mut FragmentedPacket {
    println!("Got a fragmented packet: ");
    // add fragmented packets to the buffer
    let offset = header.fragments_offset() as usize;
    let identification_number = header.identification();

    // Check if we already have a fragmented packet with this identification number
    let frag = match fragmented_packets.entry(identification_number) {
        Entry::Occupied(o) => o.into_mut(),
        Entry::Vacant(v) => v.insert(FragmentedPacket {
            buffer: [0u8; 65535],
            size: 0,
            is_ready: false,
        }),
    };

    if offset == 0 {
        // This is the first fragment, we need to include the header in the buffer as well
        let payload_start = ip_header_size + TUN_BYTES;
        frag.buffer[..(nbytes - payload_start)].copy_from_slice(&buffer[payload_start..nbytes]);
        frag.size = nbytes;
    } else {
        let payload_size = header.payload_len() as usize;
        let offset_index = offset * 8;
        let payload_start_index = ip_header_size + TUN_BYTES;
        let payload_end_index = payload_start_index + payload_size;

        let payload: &[u8] = &buffer[payload_start_index..payload_end_index];

        let offset_end = offset_index + payload_size;

        // Copy the payload at the correct offset
        frag.buffer[offset_index..offset_end].copy_from_slice(payload);

        frag.is_ready = header.more_fragments() == false;

        if frag.size < offset_end {
            frag.size = offset_index + payload_size;
        }
    }

    return frag;
}

fn main() -> io::Result<()> {
    println!("Starting TUN device...");
    let nic = Iface::new("tun", Mode::Tun).expect("Failed to create a TUN device");
    let mut buffer = [0u8; BUFFER_SIZE];

    // Store the fragmented packet along with their identification number
    let mut fragmented_packets = HashMap::new();

    loop {
        let nbytes = nic.recv(&mut buffer[..])?;

        if !check_network_layer_packet(buffer) {
            continue;
        }

        // We've got an IPv4 packet, need to find the protocol and make sure its UDP
        let ip_header = Ipv4HeaderSlice::from_slice(&buffer[4..nbytes]);

        match ip_header {
            Ok(header) => {
                let protocol = header.protocol();
                let source = header.source_addr();
                let destination = header.destination_addr();
                let ip_header_size = header.slice().len();

                println!(
                    "Packet: {} -> {}; Length: {}b Protocol: {}",
                    source,
                    destination,
                    header.payload_len(),
                    protocol,
                );

                // Get the protcol from the IPv4 header
                if protocol != UDP_PROTOCOL {
                    continue;
                }

                validate_ip_checksum(&header);
                handle_ttl(&header);
                // Handle fragmented packets
                let is_fragmented = header.is_fragmenting_payload();

                if is_fragmented {
                    let fragmented_packet = handle_fragmented_packet(
                        &header,
                        &buffer,
                        nbytes,
                        ip_header_size,
                        &mut fragmented_packets,
                    );

                    if fragmented_packet.is_ready {
                        println!("Fragmented packet is ready {}", fragmented_packet.size);
                        handle_udp_packet(&fragmented_packet.buffer);
                        fragmented_packets.remove(&header.identification());
                    }
                } else {
                    let udp_packet_start = ip_header_size + TUN_BYTES;
                    handle_udp_packet(&buffer[udp_packet_start..nbytes]);
                }
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_udp_packet(packet: &[u8]) {
    // UDP header is 8 bytes
    let header = match UdpHeaderSlice::from_slice(&packet[..8]) {
        Err(e) => {
            println!("Got bad UDP packet: {}", e);
            return;
        }

        Ok(h) => h,
    };

    // RFC 768 specification of UDP header
    // 0      7 8     15 16    23 24    31
    // +--------+--------+--------+--------+
    // |     Source      |   Destination   |
    // |      Port       |      Port       |
    // +--------+--------+--------+--------+
    // |                 |                 |
    // |     Length      |    Checksum     |
    // +--------+--------+--------+--------+
    // |
    // |          data octets ...
    // +---------------- ...

    let checksum_value = header.checksum();

    // TODO: Validate checksum, this header.checksum() function seems wrong
    let udp_length = header.length();
    let source_port = header.source_port();
    let destination_port = header.destination_port();

    println!(
        "UDP Packet: {} -> {}; Length: {}b Checksum: {}",
        source_port, destination_port, udp_length, checksum_value
    );

    // Read the data from the packet
    let data = &packet[8..udp_length as usize];

    // Parse the data as a string
    let data_string = match std::str::from_utf8(data) {
        Ok(v) => v,
        Err(e) => {
            println!("Invalid UTF-8 sequence: {}", e);
            return;
        }
    };

    println!("Data: {}", data_string);
}
