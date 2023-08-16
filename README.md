# Low Level UDP Implementation in Rust

Only works on Linux.

## Setup

Need to set capacity on the executable:

`sudo setcap cap_net_admin+ep ./target/debug/udp-implementation`

Add IP address to the tun device:

`sudo ip addr add 192.168.0.1/24 dev tun`

Bring up the tun device, allow it to send and receive packets:

`sudo ip link set up dev tun`

## Testing

The address can be changed to anything on the 192.168.0.1/24 subnet.

Test it by pinging: `ping -I tun 192.168.0.2`

Look at packets with tshark: `tshark -i tun`

Send UDP packet to tun device: `echo "Hello, UDP server!" | nc -u 192.168.0.2 161`
