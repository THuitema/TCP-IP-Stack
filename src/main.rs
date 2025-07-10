mod ethernet;
mod ip;
use ethernet::{capture_ethernet_frames};
use ip::IPv4Packet;
use pcap::{Capture, Device};

fn main() {
    let device = Device::lookup().unwrap().unwrap();
    println!("Name: {:?}", device.name);
    if let Some(desc) = &device.desc {
        println!("Desc: {:?}", desc);
    }

    let mut cap: Capture<pcap::Active> = device.open().expect("Failed to open device");
    let ethernet_frames = capture_ethernet_frames(&mut cap, 2);

    for frame in ethernet_frames {
        println!("{}", frame);
        match frame.header.ethertype_to_protocol_name().as_str() {
            "IPv4" => match IPv4Packet::from_bytes(&frame.payload) {
                Ok(ip_packet) => {
                    println!("{}", ip_packet)
                }
                Err(e) => eprintln!("{}", e),
            },
            s => {
                println!("{} packets not yet supported", s);
            }
        };
    }
}

fn get_devices() {
    let devices = Device::list().unwrap();
    println!("{} devices found!", devices.len());

    for device in &devices {
        println!("Name: {:?}", device.name);
        if let Some(desc) = &device.desc {
            println!("Desc: {:?}", desc);
        }

        for addr in &device.addresses {
            println!("  IP: {:?}", addr.addr);
            println!("  Netmask: {:?}", addr.netmask);
        }
    }
}

/*
Device {
    name: String
    desc: Option<String>
    addresses: Vec<Address>
    tags: DeviceFlags
}
*/
