use etherparse::UdpHeaderSlice;

pub(crate) const UDP_HEADER_SIZE: usize = 8;

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

pub(crate) fn handle_udp_packet(packet: &[u8], ip_header_size: usize) {
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
