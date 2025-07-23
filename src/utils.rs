use pcap::{Active, Capture, Device, Error};

use crate::ethernet::{EthernetFrame, MACAddress};
use crate::icmp::{process_icmp, ICMPPacket};
use crate::ip::{IPProtocol, IPv4Address, IPv4Packet};
use crate::parse::{parse, Transport};


pub fn ping(capture: &mut Capture<Active>, dest_ip: IPv4Address, dest_mac: MACAddress, seq_num: usize) {
    // ICMP Packet
    let identifier: u16 = 12345; // probably needs to be some random number
    let mut seq_num: u16 = 0; // increment for every request sent
    let mut content: u32 = ((identifier as u32) << 16) | (seq_num as u32);
    let icmp_payload: Vec<u8> = vec![0x41; 56];
    let icmp_packet = ICMPPacket::new(8, 0, content, icmp_payload);

    // IPv4 Packet
    let src_ip = IPv4Address::new(192, 168, 1, 41); // TODO: resolve the current computer's IP address instead of hardcoding
    let protocol = match IPProtocol::from_str("ICMP") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return
        }
    };
    let ip_payload: Vec<u8> = match icmp_packet.to_bytes() {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("{e}");
            return
        }
    };

    let ip_packet = IPv4Packet::new(src_ip, dest_ip, protocol, ip_payload);

    // Ethernet Frame
    let src_mac = MACAddress::from_slice([108, 126, 103, 204, 17, 197]); 
    let ethertype: u16 = 0x0800;
    let ethernet_payload: Vec<u8> = match ip_packet.to_bytes() {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("{e}");
            return
        }
    };

    let ethernet_frame = EthernetFrame::new(src_mac, dest_mac, ethertype, ethernet_payload);

    let hex_string = ethernet_frame.to_bytes().unwrap().iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join(" ");

    println!("{}", hex_string);

    // SEND
    match ethernet_frame.send_frame(capture) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{e}");
            return
        }
    };

    println!("IP packet created: {}", ip_packet);
    println!("ICMP packet:{}", icmp_packet);
    
    println!("SENDING AGAIN");
    match ethernet_frame.send_frame(capture) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{e}");
            return
        }
    };

    // loop & wait for response
    // START LISTENER IN A DIFFERENT THREAD
    println!("Capturing packets...");
    while let Ok(captured_frame) = capture.next_packet() {
        println!("Packet captured!");
        match parse(captured_frame) {
            Ok(packet) => {
                // print some log
                println!("{}", packet);
                
                if let Transport::ICMP(_) = &packet.transport {
                    match process_icmp(&packet) {
                        Ok(_) => (),
                        Err(e) => eprintln!("{}", e)
                    }
                }
                
            },
            Err(e) => eprintln!("{}", e)
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