# Shell script to easily run the program 
cargo build

# If there's an error, stop 
if [ $? -ne 0 ]; then
    exit 1
fi

# Give it network capabilities
sudo setcap cap_net_admin+ep ./target/debug/udp-implementation

# Run the program
./target/debug/udp-implementation &
pid=$!
sleep 1
# Add address to the tun interface
sudo ip addr add 192.168.0.1/24 dev tun
sudo ip link set up dev tun
trap "kill $pid" INT TERM
wait $pid