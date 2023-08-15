# Low Level UDP Implementation in Rust

Only works on Linux.

Need to set capacity on the executable:

`sudo setcap cap_net_admin+ep ./target/debug/udp-implementation`

Add IP address to the tun device:

`sudo ip addr add 192.168.0.1/24 dev mytun`
`sudo ip link set up dev mytun`
