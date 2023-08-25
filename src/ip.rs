use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync, thread, time,
};

use etherparse::{icmpv4::TimeExceededCode, Ipv4HeaderSlice};
use tun_tap::Iface;

use crate::udp::UDP_HEADER_SIZE;
const DEFAULT_TTL: u8 = 64;

const MAX_IP_PACKET_SIZE: usize = 65535;
const FRAGMENTATION_TIMEOUT: u64 = 15; // seconds

pub(crate) struct FragmentedPacket {
    pub(crate) buffer: [u8; MAX_IP_PACKET_SIZE],
    pub(crate) size: usize,
    pub(crate) is_ready: bool,
    pub(crate) last_updated: time::Instant,
}

pub(crate) fn check_expired_packets(
    sender_channel: sync::mpsc::Sender<u16>,
    recv_channel: sync::mpsc::Receiver<(u16, time::Instant)>,
) {
    loop {
        let mut expired_packets = HashSet::new();
        let now = time::Instant::now();

        let mut current_frag = recv_channel.try_recv();

        while current_frag.is_ok() {
            let (identification_number, last_updated) = current_frag.unwrap();
            let duration = now.duration_since(last_updated);
            let is_in_set = expired_packets.contains(&identification_number);

            if !is_in_set && duration.as_secs() > FRAGMENTATION_TIMEOUT {
                expired_packets.insert(identification_number);
            } else if is_in_set && duration.as_secs() > FRAGMENTATION_TIMEOUT {
                expired_packets.remove(&identification_number);
            }

            current_frag = recv_channel.try_recv();
        }

        for identification_number in expired_packets {
            sender_channel.send(identification_number).unwrap();
        }

        thread::sleep(time::Duration::from_secs(1));
    }
}

pub(crate) fn check_and_handle_ttl(header: &Ipv4HeaderSlice, packet: &[u8], nic: &Iface) -> bool {
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

pub(crate) fn handle_fragmented_packet<'a>(
    header: &'a Ipv4HeaderSlice<'a>,
    buffer: &'a [u8],
    nbytes: usize,
    ip_header_size: usize,
    fragmented_packets: &'a mut HashMap<u16, FragmentedPacket>,
    sender_channel: &'a sync::mpsc::Sender<(u16, time::Instant)>,
) -> &'a mut FragmentedPacket {
    // add fragmented packets to the buffer
    let identification_number = header.identification();
    let offset = header.fragments_offset() as usize;

    // If offset is 0, then we must create a new fragmented packet, otherwise if offset is not 0,
    // then we must check if we already have a fragmented packet with this identification number
    // if not, then this is the first fragment that came in

    // Check if we already have a fragmented packet with this identification number
    let frag = match fragmented_packets.entry(identification_number) {
        Entry::Occupied(o) => o.into_mut(),
        Entry::Vacant(v) => v.insert(FragmentedPacket {
            buffer: [0u8; 65535],
            size: 0,
            is_ready: false,
            last_updated: time::Instant::now(),
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

    let now = time::Instant::now();
    sender_channel.send((identification_number, now)).unwrap();

    frag.last_updated = now;
    return frag;
}

pub(crate) fn is_ipv4_checksum_valid(header: &[u8]) -> bool {
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
