TARGET="./target/debug/udp-implementation"
TUN_NAME="tun"

# Shell script to easily run the program 
cargo build

# If there's an error, stop 
if [ $? -ne 0 ]; then
    exit 1
fi

# Give it network capabilities
sudo setcap cap_net_admin+ep $TARGET

# Run the program
$TARGET &
pid=$!
# Add address to the tun interface
sudo ip addr add 192.168.0.1/24 dev $TUN_NAME
sudo ip link set up dev $TUN_NAME
trap "kill $pid" INT TERM
wait $pid