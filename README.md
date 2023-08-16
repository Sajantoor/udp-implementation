# Low Level UDP Implementation in Rust

Only works on Linux.

Need to set capacity on the executable:

`sudo setcap cap_net_admin+ep ./target/debug/udp-implementation`

Add IP address to the tun device:

`sudo ip addr add 192.168.0.1/24 dev tun`

Bring up the tun device, allow it to send and receive packets:

`sudo ip link set up dev tun`
