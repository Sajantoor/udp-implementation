mod ip;
mod udp;

use etherparse::Ipv4HeaderSlice;
use std::{
    collections::HashMap,
    io,
    net::Ipv4Addr,
    sync::{mpsc, Arc},
    thread, time,
};
use tun_tap::{Iface, Mode};
use udp::UdpPacket;

/// All hosts should be able to recieve datagrams of at least 576 bytes in length
const BUFFER_SIZE: usize = 4096;
/// UDP protocol number
const UDP_PROTOCOL: u8 = 17;

pub struct UdpSocket {
    binded_ip_port: Option<IpPort>,
    nic: Arc<Iface>,
    reciever: mpsc::Receiver<UdpPacket>,
}

#[derive(Clone)]
pub struct IpPort {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl UdpSocket {
    /// Create a new socket that can be used to send and recieve UDP packets
    /// The socket is not binded to any ip or port.
    pub fn new() -> UdpSocket {
        let nic = Arc::new(
            Iface::without_packet_info("tun", Mode::Tun).expect("Failed to create a TUN device"),
        );

        let nic_clone = nic.clone();
        let (udp_packet_sender, udp_packet_reciever) = mpsc::channel::<UdpPacket>();
        let udp_packet_sender_clone = udp_packet_sender.clone();

        let _ = thread::spawn(move || {
            let _ = packet_loop(&nic_clone, udp_packet_sender_clone);
        });

        return UdpSocket {
            binded_ip_port: None,
            nic: nic.clone(),
            reciever: udp_packet_reciever,
        };
    }

    /// Create a new socket that can be used to send and recieve UDP packets and
    /// bind it to the ip and port specified
    ///
    /// # Arguments
    ///
    /// * `ip` - The ip to bind the socket to
    /// * `port` - The port to bind the socket to
    pub fn new_with_ip(ip: Ipv4Addr, port: u16) -> UdpSocket {
        let mut socket = UdpSocket::new();
        socket.bind(ip, port);
        return socket;
    }

    /// Bind the socket to the ip and port specified
    ///
    /// # Arguments
    ///
    /// * `ip` - The ip to bind the socket to
    /// * `port` - The port to bind the socket to
    pub fn bind(&mut self, ip: Ipv4Addr, port: u16) {
        println!("Listening on ip: {} and port: {}", ip, port);
        self.binded_ip_port = Some(IpPort { ip, port });
    }

    /// Send a UDP packet to the ip and port specified with the data provided
    ///
    /// # Panics
    /// Warning: This function will panic if the socket is not binded to an ip and port. Use the
    /// `bind` function to bind the socket to an ip and port.
    ///
    /// # Arguments
    ///
    /// * `ip` - The ip to send the packet to
    /// * `port` - The port to send the packet to
    /// * `data` - The data to send
    ///
    /// # Returns
    ///
    /// The number of bytes sent
    pub fn send_to(&mut self, ip: Ipv4Addr, port: u16, data: &[u8]) -> io::Result<usize> {
        let destination = IpPort { ip, port };
        let source = match &self.binded_ip_port {
            Some(ip_port) => ip_port,
            None => panic!("Socket not binded to an ip and port"),
        };

        return udp::send_udp_packet(&self.nic, destination, source.clone(), data);
    }

    /// Recieve a UDP packet from any ip and port and returns the packet.
    /// This function will block until a packet is recieved.
    ///
    /// # Returns
    ///
    /// The UDP packet recieved
    pub fn recv_any(&mut self) -> UdpPacket {
        let mut udp_packet = self.reciever.recv();

        // If there is no packet, need to wait for one...
        while udp_packet.is_err() {
            udp_packet = self.reciever.recv();
        }

        // Add the packet to the list of recieved packets
        let udp_packet = udp_packet.unwrap();
        return udp_packet;
    }

    /// Recieve a UDP packet from the ip and port specified and returns the packet.
    /// This function will block until a packet is recieved.
    ///
    /// # Arguments
    ///
    /// * `ip` - The ip to recieve the packet from
    /// * `port` - The port to recieve the packet from
    ///
    ///
    /// # Returns
    ///
    /// The UDP packet recieved
    pub fn recv_from(&mut self, ip: Ipv4Addr, port: u16) -> UdpPacket {
        let udp_packet = self.recv();

        if udp_packet.source_ip != ip || udp_packet.source_port != port {
            return self.recv_from(ip, port);
        }

        return udp_packet;
    }

    /// Recieve a UDP packet sent to the binded ip and port specified and returns the packet.
    ///
    ///
    /// # Panics
    ///
    /// Warning: This function will panic if the socket is not binded to an ip and port. Use the
    /// `bind` function to bind the socket to an ip and port.
    ///
    /// # Arguments
    ///
    /// * `ip` - The ip to recieve the packet from
    /// * `port` - The port to recieve the packet from
    ///
    /// # Returns
    ///
    ///
    /// The UDP packet recieved
    pub fn recv(&mut self) -> UdpPacket {
        let udp_packet = self.recv_any();

        // Verify that the packet is sent to the correct IP and port, if not, repeat the process.
        let binded_ip_port = match &self.binded_ip_port {
            Some(ip_port) => ip_port,
            None => panic!("Socket not binded to an ip and port"),
        };

        if udp_packet.destination_ip != binded_ip_port.ip
            || udp_packet.destination_port != binded_ip_port.port
        {
            return self.recv();
        }

        return udp_packet;
    }
}

/// The main packet loop that handles all incoming packets
///
/// # Arguments
///
/// * `nic` - The network interface to listen on
/// * `udp_packet_sender` - The channel to send the UDP packets to
fn packet_loop(nic: &Iface, udp_packet_sender: mpsc::Sender<UdpPacket>) -> io::Result<()> {
    // Store the fragmented packet along with their identification number
    let mut fragmented_packets = HashMap::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    let (send_expired_frags, recv_expired_frags) = mpsc::channel::<u16>();
    let (sender_current_frags, recv_curent_frags) = mpsc::channel::<(u16, time::Instant)>();

    let _ = thread::spawn(|| {
        // use reference counter to share the fragmented_packets
        ip::check_expired_packets(send_expired_frags, recv_curent_frags);
    });

    loop {
        let nbytes = nic.recv(&mut buffer[..])?;

        // We've got an IPv4 packet, need to find the protocol and make sure its UDP
        let ip_header = Ipv4HeaderSlice::from_slice(&buffer[..nbytes]);

        match ip_header {
            Ok(header) => {
                let protocol = header.protocol();
                let ip_header_size = header.slice().len();

                // Get the protcol from the IPv4 header
                if protocol != UDP_PROTOCOL {
                    continue;
                }

                if !ip::is_ipv4_checksum_valid(header.slice()) {
                    eprintln!("Invalid IPv4 checksum, dropping packet...");
                    continue;
                }

                if !ip::check_and_handle_ttl(&header, &buffer[..nbytes], &nic) {
                    continue;
                }

                // Handle fragmented packets
                let is_fragmented = header.is_fragmenting_payload();

                if is_fragmented {
                    let fragmented_packet = ip::handle_fragmented_packet(
                        &header,
                        &buffer,
                        nbytes,
                        ip_header_size,
                        &mut fragmented_packets,
                        &sender_current_frags,
                    );

                    if fragmented_packet.is_ready {
                        udp::handle_udp_packet(
                            &fragmented_packet.buffer,
                            ip_header_size,
                            &udp_packet_sender,
                        );
                        fragmented_packets.remove(&header.identification());
                    }
                } else {
                    udp::handle_udp_packet(&buffer[..nbytes], ip_header_size, &udp_packet_sender);
                }
            }
            Err(e) => {
                continue;
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
