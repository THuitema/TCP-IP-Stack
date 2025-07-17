#![allow(dead_code)]

mod ethernet;
mod ip;
mod icmp;
use ip::IPv4Packet;
use pcap::{Active, Capture, Device};

use crate::{ethernet::EthernetFrame, icmp::ICMPPacket};

fn main() {
    let device = Device::lookup().unwrap().unwrap();
    println!("Name: {:?}", device.name);
    if let Some(desc) = &device.desc {
        println!("Desc: {:?}", desc);
    }

    let mut cap: Capture<pcap::Active> = device.open().expect("Failed to open device");
    capture_loop(&mut cap, 1000);
}

fn capture_loop(capture: &mut Capture<Active>, size: usize) {
    let mut count = 0;

    while let Ok(packet) = capture.next_packet() {
        count += 1;
        match EthernetFrame::from_bytes(packet.data) {
            Ok(ethernet_frame) => match ethernet_frame.header.ethertype_to_protocol_name().as_str() {
                "IPv4" => handle_ip_packet(&ethernet_frame),
                s => {
                    println!("{} packets not yet supported", s);
                }
            },    
            Err(e) => eprintln!("{}", e),
        }

        if count > size {
            break;
        }
    }
}

fn handle_ip_packet(frame: &EthernetFrame) {
    match IPv4Packet::from_bytes(&frame.payload) {
        Ok(ip_packet) => match ip_packet.header.get_protocol_name().as_str() {
            "ICMP" => {
                println!("{}", ip_packet);
                handle_icmp_packet(&ip_packet);
            },
            _ => ()//println!("{} packet read", s)
        }
        Err(e) => eprintln!("{}", e),
    }
}

fn handle_icmp_packet(packet: &IPv4Packet) {
    match ICMPPacket::from_bytes(&packet.payload) {
        Ok(icmp_packet) => println!("{}", icmp_packet),
        Err(e) => eprintln!("{}", e),
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
