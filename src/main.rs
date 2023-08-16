use etherparse::Ipv4HeaderSlice;
use std::io;
use tun_tap::{Iface, Mode};

fn main() -> io::Result<()> {
    let nic = Iface::new("tun", Mode::Tun).expect("Failed to create a TUN device");
    let mut buffer = [0u8; 4096];
    let ipv4_protocol = 0x0800;

    loop {
        let nbytes = nic.recv(&mut buffer[..])?;

        // By tuntap docs: https://docs.kernel.org/networking/tuntap.html
        // the first 2 bytes are flags and the next 2 bytes are protocol
        let flags = u16::from_be_bytes([buffer[0], buffer[1]]);
        let ether_protocol = u16::from_be_bytes([buffer[2], buffer[3]]);
        let udp_protocol = 17;

        // After that is the raw protocol(IP, IPv6, etc) frame.
        // Ignore any non-IPv4 packets
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
                // Get the protc ol from the IPv4 header
                if protocol != udp_protocol {
                    continue;
                }

                // TOOD: Implement IPv4 packet handling here, validate checksum,
                // check for fragmentation, etc

                let ip_header_size = header.slice().len();
                let udp_packet_start = ip_header_size + 4;
                // Get the UDP packet and handle it
                handle_udp_packet(&buffer[udp_packet_start..nbytes]);
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

fn handle_udp_packet(buffer: &[u8]) {
    println!("UDP Packet: {:?}", buffer);
}
