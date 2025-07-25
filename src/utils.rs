use pcap::{Active, Capture, Device, Error};

use crate::ethernet::{self, EthernetFrame, MACAddress};
use crate::icmp::{self, process_icmp, ICMPPacket};
use crate::ip::{IPProtocol, IPv4Address, IPv4Packet};
use crate::parse::{parse, Transport};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub fn ping(dest_ip: IPv4Address, dest_mac: MACAddress, size: u16) -> () {
    // ICMP Packet
    let identifier: u16 = 12345; // probably needs to be some random number
    let mut content = (identifier as u32) << 16;
    let icmp_payload: Vec<u8> = vec![0x41; 56];
    let mut icmp_packet = ICMPPacket::new(8, 0, content, icmp_payload);

    // IPv4 Packet
    let src_ip = IPv4Address::new(192, 168, 1, 41); // TODO: resolve the current computer's IP address instead of hardcoding
    let protocol = match IPProtocol::from_str("ICMP") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    let ip_payload: Vec<u8> = match icmp_packet.to_bytes() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    let ip_packet = IPv4Packet::new(src_ip, dest_ip, protocol, ip_payload);

    // Ethernet Frame
    let src_mac = MACAddress::from_slice([108, 126, 103, 204, 17, 197]);
    let ethertype: u16 = 0x0800;
    let ethernet_payload: Vec<u8> = match ip_packet.to_bytes() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    let ethernet_frame = EthernetFrame::new(src_mac, dest_mac, ethertype, ethernet_payload);
    let mut ethernet_bytes = match ethernet_frame.to_bytes() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    let recv_cap: Capture<pcap::Active> = Capture::from_device("en0")
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();
    let mut send_cap: Capture<pcap::Active> = Capture::from_device("en0")
        .unwrap()
        .immediate_mode(true) 
        .open()
        .unwrap();

    thread::spawn(move || {
        let mut cap = recv_cap;
        loop {
            if let Ok(captured_frame) = cap.next_packet() {
                match parse(captured_frame) {
                    Ok(packet) => {

                        if let Transport::ICMP(icmp_packet) = &packet.transport {
                            match icmp_packet.icmp_type() {
                                0 => {
                                    // process echo reply
                                    let identifier: u16 = (icmp_packet.content() >> 16) as u16;
                                    let seq_num: u16 = (icmp_packet.content() & 0xFF) as u16;

                                    println!("[time] Ping reply from {}: icmp_seq={} identifier={}", packet.ipv4.src_addr(), seq_num, identifier);
                                    
                                    // Check if we received last ping reply
                                    if (icmp_packet.content() & 0xFF) as u16 == (size - 1) {
                                        break;
                                    }
                                },
                                _ => ()
                            }

                           
                        }
                    }
                    Err(e) => ()
                }
            }
        }
    });

    // Send ICMP packets
    for seq_num in 0..size {
        // Update the sequence number in the packet bytes and re-compute ICMP checksum
        content = ((identifier as u32) << 16) | (seq_num as u32);
        icmp_packet.set_content(content);
        icmp_packet.set_checksum();

        match icmp_packet.to_bytes() {
            Ok(payload) => ethernet_bytes.splice(34.., payload),
            Err(e) => {
                eprintln!("{e}");
                return;
            }
        };

        match send_cap.sendpacket(ethernet_bytes.clone()) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("{e}");
                return;
            }
        }

        // sleep for 1 second between pings
        thread::sleep(Duration::from_secs(1));
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
