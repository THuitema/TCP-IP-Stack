mod ethernet;
mod ip;
use ethernet::EthernetHeader;
use pcap::{Capture, Device};

fn main() {
    let device = Device::lookup().unwrap().unwrap();
    println!("Name: {:?}", device.name);
    if let Some(desc) = &device.desc {
        println!("Desc: {:?}", desc);
    }

    let mut cap = device.open().expect("Failed to open device");
    let mut count = 0;
    while let Ok(packet) = cap.next_packet() {
        if let Some(ethernet_header) = EthernetHeader::from_bytes(packet.data) {
            println!("{}", ethernet_header);
        } else {
            println!("Packet received, but error parsing the ethernet header");
        }
        count += 1;
        if count == 3 {
            break;
        }

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