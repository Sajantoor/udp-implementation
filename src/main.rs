mod ip;
mod udp;

use etherparse::Ipv4HeaderSlice;
use std::{collections::HashMap, io, sync, time};
use tun_tap::{Iface, Mode};
use udp::handle_udp_packet;

use crate::ip::{
    check_and_handle_ttl, check_expired_packets, handle_fragmented_packet, is_ipv4_checksum_valid,
};

// All hosts should be able to recieve datagrams of at least 576 bytes in length
const BUFFER_SIZE: usize = 4096;
const UDP_PROTOCOL: u8 = 17;

fn main() -> io::Result<()> {
    let nic = Iface::without_packet_info("tun", Mode::Tun).expect("Failed to create a TUN device");
    println!("Started tun device: {:?}", nic.name());

    let mut buffer = [0u8; BUFFER_SIZE];

    // Store the fragmented packet along with their identification number
    let mut fragmented_packets = HashMap::new();
    let (send_expired_frags, recv_expired_frags) = sync::mpsc::channel::<u16>();
    let (sender_current_frags, recv_curent_frags) = sync::mpsc::channel::<(u16, time::Instant)>();

    let _ = std::thread::spawn(|| {
        // use reference counter to share the fragmented_packets
        check_expired_packets(send_expired_frags, recv_curent_frags);
    });

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
                        &sender_current_frags,
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

        // Check for expired packets in the reciever channel, if there are any, remove them from the fragmented packets
        let expired_packet = recv_expired_frags.try_recv();
        match expired_packet {
            Ok(identification_number) => {
                // TOOD: Send ICMP packet back to the sender
                fragmented_packets.remove(&identification_number);
            }
            Err(_) => {}
        }
    }
}
