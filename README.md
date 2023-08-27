# Low Level UDP Implementation in Rust

Implementation of a low level UDP and IPv4 protocols in Rust using tun/tap devices.

## Setup

Need to set capacity on the executable:

`sudo setcap cap_net_admin+ep ./target/debug/udp-implementation`

Add IP address to the tun device:

`sudo ip addr add 192.168.0.1/24 dev tun`

Bring up the tun device, allow it to send and receive packets:

`sudo ip link set up dev tun`

or this can all be done wit the script: 

`./run.sh`

## Testing

The address above can be changed to anything on the 192.168.0.1/24 subnet.

Test it by pinging: `ping -I tun 192.168.0.2`

Look at packets with tshark: `tshark -i tun` (or Wireshark)

Send UDP packet to tun device: `echo "Hello, UDP server!" | nc -u 192.168.0.2 161`


## API

`udp_implementation::new() -> UdpSocket`

Creates a new UdpSocket.

`udp_implementation::bind(&mut self, ip: Ipv4Addr, port: u16)`

Binds the socket to the given address.


`udp_implementation::new_with_ip(ip: Ipv4Addr, port: u16) -> UdpSocket` 

Creates a new UdpSocket and binds it to the given address.

`udp_implementation::send_to(&mut self, ip: Ipv4Addr, port: u16, data: &[u8]) -> io::Result<usize>` 

Sends data to the given address. 

`udp_implementation::recv_any(&mut self) -> UdpPacket` 

Receives data from any address.

`udp_implementation::recv_from(&mut self, ip: Ipv4Addr, port: u16) -> UdpPacket` 

Receives data from the given address.


`udp_implementation::recv(&mut self) -> UdpPacket` 

Receives data from the binded address.


See example in [main.rs](src/main.rs) for usage. 


# References: 

* [RFC-786](https://datatracker.ietf.org/doc/html/rfc786)
* [RFC-791](https://datatracker.ietf.org/doc/html/rfc791)
* [RFC-792](https://datatracker.ietf.org/doc/html/rfc792)
* [RFC-4963](https://datatracker.ietf.org/doc/html/rfc4963)
