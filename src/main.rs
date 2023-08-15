use std::io;
use tun_tap::Iface;
use tun_tap::Mode;

fn main() -> io::Result<()> {
    let nic = Iface::new("mytun", Mode::Tun).expect("Failed to create a TUN device");
    let mut buf = [0u8; 4096];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        println!("Read {} bytes: {:?}", nbytes, &buf[..nbytes]);
    }

    Ok(())
}
