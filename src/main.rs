use etherparse::{icmpv4::TimeExceededCode, Ipv4HeaderSlice, UdpHeaderSlice};
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
};
use tun_tap::{Iface, Mode};

const MAX_IP_PACKET_SIZE: usize = 65535;
// All hosts should be able to recieve datagrams of at least 576 bytes in length
const BUFFER_SIZE: usize = 4096;
const UDP_PROTOCOL: u8 = 17;
const UDP_HEADER_SIZE: usize = 8;
const DEFAULT_TTL: u8 = 64;
const FRAGMENTATION_TIMEOUT: u8 = 15; // seconds

struct FragmentedPacket {
    buffer: [u8; MAX_IP_PACKET_SIZE],
    size: usize,
    is_ready: bool,
}

fn check_and_handle_ttl(header: &Ipv4HeaderSlice, packet: &[u8], nic: &Iface) -> bool {
    let ttl = header.ttl();
    if ttl != 0 {
        return true;
    }

    // Send ICMP time exceeded message back to the sender
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |     Type      |     Code      |          Checksum             |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                             unused                            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |      Internet Header + 64 bits of Original Data Datagram      |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let source = header.source_addr().octets();
    let destination = header.destination_addr().octets();

    // 64 bits of the original data datagram therefore we need to copy the first 8 bytes
    let data_start = header.slice().len() + UDP_HEADER_SIZE;
    let data_end = data_start + 8;
    let data = &packet[data_start..data_end];

    let original_ip_header = header.slice();
    let icmp_payload = [original_ip_header, data].concat();

    // Send this packet back to the sender
    eprintln!("TTL is 0, dropping packet...");
    println!("Sending ICMP packet back to the sender...");

    let packet_builder = etherparse::PacketBuilder::ipv4(destination, source, DEFAULT_TTL).icmpv4(
        etherparse::Icmpv4Type::TimeExceeded(TimeExceededCode::TtlExceededInTransit),
    );

    let mut result = Vec::<u8>::with_capacity(packet_builder.size(icmp_payload.len()));
    packet_builder.write(&mut result, &icmp_payload).unwrap();
    // Send the packet
    nic.send(&result[..]).unwrap();
    return false;
}

fn is_ipv4_checksum_valid(header: &[u8]) -> bool {
    // RFC 791 specification:
    // The checksum field is the 16 bit one's complement of the one's
    // complement sum of all 16 bit words in the header.  For purposes of
    // computing the checksum, the value of the checksum field is zero.

    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Ver= 4 |IHL= 5 |Type of Service|        Total Length = 21      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Identification = 111     |Flg=0|   Fragment Offset = 0   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Time = 123  |  Protocol = 1 |        header checksum        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         source address                        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                      destination address                      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let mut checksum: u32 = 0;

    // Iterate over 16-bit words in the header
    for chunk in header.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        checksum = checksum.wrapping_add(u32::from(word));
    }

    // Fold any carry bits
    while (checksum >> 16) != 0 {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    // Calculate one's complement
    let checksum = !checksum as u16;

    // The result should be 0 if the checksum is valid
    return checksum == 0;
}

fn handle_fragmented_packet<'a>(
    header: &'a Ipv4HeaderSlice<'a>,
    buffer: &'a [u8],
    nbytes: usize,
    ip_header_size: usize,
    fragmented_packets: &'a mut HashMap<u16, FragmentedPacket>,
) -> &'a mut FragmentedPacket {
    // add fragmented packets to the buffer
    let identification_number = header.identification();
    let offset = header.fragments_offset() as usize;

    // Check if we already have a fragmented packet with this identification number
    let frag = match fragmented_packets.entry(identification_number) {
        Entry::Occupied(o) => o.into_mut(),

        // TODO: Only create a new fragmented packet if the offset is 0, otherwise we should
        // return an error
        Entry::Vacant(v) => v.insert(FragmentedPacket {
            buffer: [0u8; 65535],
            size: 0,
            is_ready: false,
        }),
    };

    if offset == 0 {
        // This is the first fragment, we need to include the header in the buffer as well
        let payload_start = ip_header_size;
        frag.buffer[..(nbytes - payload_start)].copy_from_slice(&buffer[payload_start..nbytes]);
        frag.size = nbytes;
    } else {
        let payload_size = header.payload_len() as usize;
        let offset_index = offset * 8;
        let payload_start_index = ip_header_size;
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
    let nic = Iface::without_packet_info("tun", Mode::Tun).expect("Failed to create a TUN device");
    println!("Started tun device: {:?}", nic.name());

    let mut buffer = [0u8; BUFFER_SIZE];

    // Store the fragmented packet along with their identification number
    let mut fragmented_packets = HashMap::new();

    loop {
        let nbytes = nic.recv(&mut buffer[..])?;

        // We've got an IPv4 packet, need to find the protocol and make sure its UDP
        let ip_header = Ipv4HeaderSlice::from_slice(&buffer[..nbytes]);

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

                if !is_ipv4_checksum_valid(header.slice()) {
                    eprintln!("Invalid IPv4 checksum, dropping packet...");
                    continue;
                }

                if !check_and_handle_ttl(&header, &buffer[..nbytes], &nic) {
                    continue;
                }
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
                        handle_udp_packet(&fragmented_packet.buffer, ip_header_size);
                        fragmented_packets.remove(&header.identification());
                    }
                } else {
                    handle_udp_packet(&buffer[..nbytes], ip_header_size);
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }
}

fn is_udp_checksum_valid(header: &[u8], ip_header_size: usize) -> bool {
    // RFC 768 specification for UDP checksum:
    // Checksum is the 16-bit one's complement of the one's complement sum of a
    // pseudo header of information from the IP header, the UDP header, and the
    // data,  padded  with zero octets  at the end (if  necessary)  to  make  a
    // multiple of two octets.

    let mut checksum: u32 = 0;

    // Calculate checksum for the pseudo header which is part of the IP header
    // The pseudo header typically includes the following fields from the IPv4 header:

    // Source IP Address: 32 bits
    // Destination IP Address: 32 bits
    // Zero field (reserved): 8 bits
    // Protocol (UDP): 8 bits
    // UDP Length: 16 bits

    // 0      7 8     15 16    23 24    31
    // +--------+--------+--------+--------+
    // |          source address           |
    // +--------+--------+--------+--------+
    // |        destination address        |
    // +--------+--------+--------+--------+
    // |  zero  |protocol|   UDP length    |
    // +--------+--------+--------+--------+

    // Source address
    checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([header[12], header[13]])));
    checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([header[14], header[15]])));

    // Destination address
    checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([header[16], header[17]])));
    checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([header[18], header[19]])));

    // Zero field
    checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([0, 0])));

    // Protocol
    checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([0, header[9]])));

    // UDP Length
    checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([header[24], header[25]])));

    // Calculate checksum for the UDP header and data
    let udp_packet = &header[ip_header_size..];

    // Iterate over 16-bit words in the header
    for chunk in udp_packet.chunks(2) {
        let word: u16;

        if chunk.len() == 1 {
            // If the last chunk is only 1 byte, we need to pad it with 0
            word = u16::from_be_bytes([chunk[0], 0]);
        } else {
            word = u16::from_be_bytes([chunk[0], chunk[1]]);
        }

        checksum = checksum.wrapping_add(u32::from(word));
    }

    // Fold any carry bits
    while (checksum >> 16) != 0 {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    // Calculate one's complement
    let checksum = !checksum as u16;

    // The result should be 0 if the checksum is valid
    return checksum == 0;
}

fn handle_udp_packet(packet: &[u8], ip_header_size: usize) {
    // UDP header is 8 bytes
    let header =
        match UdpHeaderSlice::from_slice(&packet[ip_header_size..ip_header_size + UDP_HEADER_SIZE])
        {
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

    if !is_udp_checksum_valid(&packet, ip_header_size) {
        println!("Invalid UDP checksum, dropping packet...");
        return;
    }

    let udp_length = header.length();
    let source_port = header.source_port();
    let destination_port = header.destination_port();

    println!(
        "UDP Packet: {} -> {}; Length: {}b",
        source_port, destination_port, udp_length
    );

    // Read the data from the packet
    let data = &packet[ip_header_size + UDP_HEADER_SIZE..];

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
