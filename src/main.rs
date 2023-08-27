use std::net::Ipv4Addr;

fn main() {
    let mut socket = udp_implementation::UdpSocket::new();
    socket.bind(Ipv4Addr::new(127, 0, 0, 1), 8080);

    let udp_packet = socket.recv_any();

    let data_string = match std::str::from_utf8(udp_packet.data.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid UTF-8 sequence: {}", e);
            return;
        }
    };

    println!("Data: {}", data_string);

    let _ = socket.send_to(
        udp_packet.source_ip,
        udp_packet.source_port,
        b"Hello from custom UDP implementation!",
    );
}
