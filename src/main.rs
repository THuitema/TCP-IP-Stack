use pcap::Device;

fn main() {
    let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
    
    // while let Ok(packet) = cap.next_packet() {
    //     println!("received packet {:?}", packet);
    // }
}

fn get_device_info() {
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