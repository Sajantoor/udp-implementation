use std::{fmt, io, net::Ipv4Addr, sync::mpsc};

use etherparse::{Ipv4HeaderSlice, PacketBuilder, UdpHeaderSlice};
use tun_tap::Iface;

use crate::{ip::DEFAULT_TTL, IpPort};

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Box<[u8]>,
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub(crate) destination_ip: Ipv4Addr,
    pub(crate) destination_port: u16,
}

impl fmt::Display for UdpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}:{} -> {}:{}: Sent: {:?})",
            self.source_ip, self.source_port, self.destination_ip, self.destination_port, self.data
        )
    }
}

/// UDP header is 8 bytes
pub(crate) const UDP_HEADER_SIZE: usize = 8;

/// Determine if the UDP checksum is valid, returns true if valid, false otherwise
///
/// RFC 768 specification for UDP checksum:
/// Checksum is the 16-bit one's complement of the one's complement sum of a
/// pseudo header of information from the IP header, the UDP header, and the
/// data,  padded  with zero octets  at the end (if  necessary)  to  make  a
/// multiple of two octets.
///
/// # Arguments
///
/// * `header` - The packet header as a byte slice
/// * `ip_header_size` - The size of the IP header
fn is_udp_checksum_valid(header: &[u8], ip_header_size: usize) -> bool {
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

    // Calculate checksum for the UDP header and data, UDP header is after the IP header
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

/// Handle a UDP packet
/// # Arguments
/// * `packet` - The packet as a byte slice starting from the IP header
/// * `ip_header_size` - The size of the IP header
pub(crate) fn handle_udp_packet(
    packet: &[u8],
    ip_header_size: usize,
    udp_packet_sender: &mpsc::Sender<UdpPacket>,
) {
    // UDP header is 8 bytes
    let udp_header =
        match UdpHeaderSlice::from_slice(&packet[ip_header_size..ip_header_size + UDP_HEADER_SIZE])
        {
            Err(e) => {
                eprintln!("Got bad UDP packet: {}", e);
                return;
            }

            Ok(h) => h,
        };

    if !is_udp_checksum_valid(&packet, ip_header_size) {
        eprintln!("Invalid UDP checksum, dropping packet...");
        return;
    }

    let ip_header = match Ipv4HeaderSlice::from_slice(&packet[..ip_header_size]) {
        Ok(header) => header,
        Err(e) => {
            eprintln!("Invalid IPv4 header: {}", e);
            return;
        }
    };

    let source_ip = ip_header.source_addr();
    let destination_ip = ip_header.destination_addr();

    let source_port = udp_header.source_port();
    let destination_port = udp_header.destination_port();

    // Read the data from the packet
    let data = &packet[ip_header_size + UDP_HEADER_SIZE..];

    // Send the data to the main thread
    let _ = udp_packet_sender.send(UdpPacket {
        data: data.to_vec().into_boxed_slice(),
        source_ip,
        source_port,
        destination_ip,
        destination_port,
    });
}

pub(crate) fn send_udp_packet(
    nic: &Iface,
    destination: IpPort,
    source: IpPort,
    payload: &[u8],
) -> io::Result<usize> {
    let packet_builder =
        PacketBuilder::ipv4(source.ip.octets(), destination.ip.octets(), DEFAULT_TTL)
            .udp(source.port, destination.port);

    let mut result = Vec::<u8>::with_capacity(packet_builder.size(payload.len()));
    packet_builder.write(&mut result, &payload).unwrap();

    // Send the packet
    return nic.send(&result[..]);
}
