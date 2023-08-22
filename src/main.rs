use etherparse::{Ipv4HeaderSlice, UdpHeaderSlice};
use std::io;
use tun_tap::{Iface, Mode};

fn main() -> io::Result<()> {
    let nic = Iface::new("tun", Mode::Tun).expect("Failed to create a TUN device");
    let mut buffer = [0u8; 4096];
    let ipv4_protocol = 0x0800;

    let mut ip_fragmentation_buffer = [0u8; 65535];
    let mut fragment_ready = false;
    let mut fragmented_packet_size = 0;

    loop {
        let nbytes = nic.recv(&mut buffer[..])?;

        // By tuntap docs: https://docs.kernel.org/networking/tuntap.html
        // the first 2 bytes are flags and the next 2 bytes are protocol
        // let flags = u16::from_be_bytes([buffer[0], buffer[1]]);
        let ether_protocol = u16::from_be_bytes([buffer[2], buffer[3]]);
        let udp_protocol = 17;

        // After that is the raw protocol(IP, IPv6, etc) frame.
        // Ignore any non-IPv4 packets
        // TODO: Support ipv6 as well
        if ether_protocol != ipv4_protocol {
            continue;
        }

        // We've got an IPv4 packet, need to find the protocol and make sure its UDP
        let ip_header = Ipv4HeaderSlice::from_slice(&buffer[4..nbytes]);

        match ip_header {
            Ok(header) => {
                let protocol = header.protocol();
                let source = header.source_addr();
                let destination = header.destination_addr();

                println!(
                    "Packet: {} -> {}; Length: {}b Protocol: {}",
                    source,
                    destination,
                    header.payload_len(),
                    protocol,
                );

                // Get the protcol from the IPv4 header
                if protocol != udp_protocol {
                    continue;
                }

                // Validate the checksum of the IP header
                let ip_checksum = header.header_checksum();
                if ip_checksum != 0 {
                    println!("Invalid IP checksum");
                    continue;
                }

                // Handle TTL
                let ttl = header.ttl();
                if ttl == 0 {
                    println!("TTL is 0");
                    // TODO: According to RFC 791, we should send an ICMP packet back
                    // to the sender to let them know the packet has expired
                    continue;
                }

                // Handle fragmented packets
                // TODO: this is wrong!
                let is_fragmented = header.is_fragmenting_payload();

                if is_fragmented {
                    // add fragmented packets to the buffer
                    let offset = header.fragments_offset();
                    if offset == 0 {
                        // This is the first fragment, we need to include the buffer in the size as well
                        ip_fragmentation_buffer[..nbytes].copy_from_slice(&buffer[..nbytes]);
                        fragmented_packet_size = nbytes;
                    } else {
                        let fragment_size = header.payload_len();
                        let ip_header_size = header.slice().len();

                        let fragment_start = ip_header_size + 4 + offset as usize;
                        let fragment_end = fragment_start + fragment_size as usize;

                        let fragment = &buffer[fragment_start..fragment_end];
                        ip_fragmentation_buffer[fragmented_packet_size..fragment_end]
                            .copy_from_slice(fragment);

                        fragment_ready = header.more_fragments() == false;
                        fragmented_packet_size = fragment_end;
                    }
                }

                // Handle rest of IP protcol
                if fragment_ready {
                    handle_udp_packet(&ip_fragmentation_buffer[..fragmented_packet_size]);
                    fragment_ready = false;
                    fragmented_packet_size = 0;
                } else if !is_fragmented {
                    let ip_header_size = header.slice().len();
                    let udp_packet_start = ip_header_size + 4;
                    // Get the UDP packet and handle it
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
