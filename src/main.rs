#![allow(dead_code)]
mod ethernet;
mod ip;
mod icmp;
mod parse;
use parse::parse;
use pcap::{Active, Capture, Device};

fn main() {
    let device = Device::lookup().unwrap().unwrap();
    println!("Name: {:?}", device.name);
    if let Some(desc) = &device.desc {
        println!("Desc: {:?}", desc);
    }

    let mut cap: Capture<pcap::Active> = device.open().expect("Failed to open device");
    capture_loop(&mut cap, 50);
}

fn capture_loop(capture: &mut Capture<Active>, size: usize) {
    let mut count = 0;

    // TODO: implement some sort of multithreading to parse each packet asynchronously
    while let Ok(captured_frame) = capture.next_packet() {
        count += 1;

        match parse(captured_frame) {
            Ok(packet) => {
                // print some log
                println!("{}", packet);
            },
            Err(e) => eprintln!("{}", e)
        } 

        if count > size {
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
