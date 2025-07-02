use pcap::Device;

fn main() {
    let device = Device::lookup().unwrap().unwrap();
    println!("Name: {:?}", device.name);
    if let Some(desc) = &device.desc {
        println!("Desc: {:?}", desc);
    }

    for addr in &device.addresses {
        println!("  IP: {:?}", addr.addr);
        println!("  Netmask: {:?}", addr.netmask);
    }

    let mut cap = device.open().expect("Failed to open device");
    let mut count = 0;
    while let Ok(packet) = cap.next_packet() {
        println!("received packet {:?}", packet);
        count += 1;
        println!("that is the {:?} packet sniffed!", count);
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