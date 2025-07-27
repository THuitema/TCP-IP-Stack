use pcap::{Device};
use crate::addr_info::{AddrInfo, setup_capture};
use crate::ethernet::{EthernetFrame};
use crate::icmp::ICMPPacket;
use crate::ip::{IPProtocol, IPv4Address, IPv4Packet};
use crate::parse::{parse, Transport};
use std::thread;
use std::time::Duration;

/**
 * Pings dest_ip a certain number of times, specified by size
 */
pub fn ping(dest_ip: IPv4Address, addr_info: &mut AddrInfo, size: u16) -> () {
    // ICMP Packet
    let identifier: u16 = 12345; // probably needs to be some random number
    let mut content = (identifier as u32) << 16;
    let icmp_payload: Vec<u8> = vec![0x41; 56];
    let mut icmp_packet = ICMPPacket::new(8, 0, content, icmp_payload);

    // IPv4 Packet
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

    let ip_packet = IPv4Packet::new(addr_info.addr_ipv4, dest_ip, protocol, ip_payload);

    // Ethernet Frame
    let ethertype: u16 = 0x0800;
    let ethernet_payload: Vec<u8> = match ip_packet.to_bytes() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    let ethernet_frame = EthernetFrame::new(addr_info.addr_mac, addr_info.router_mac, ethertype, ethernet_payload);
    let mut ethernet_bytes = match ethernet_frame.to_bytes() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    let recv_cap = setup_capture(&addr_info.interface);

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
                                    let seq_num: u16 = (icmp_packet.content() & 0xFF) as u16;
                                    
                                    if let Some(sent_time) = icmp_packet.get_timestamp() {
                                        let duration = packet.timestamp.signed_duration_since(sent_time);
                                        println!("{} bytes from {}: icmp_seq={} ttl={} time={}ms", icmp_packet.size(), packet.ipv4.src_addr(), seq_num, packet.ipv4.ttl(), duration.num_milliseconds());
                                    
                                    } else {
                                        println!("{} bytes from {}: icmp_seq={} ttl={}", icmp_packet.size(), packet.ipv4.src_addr(), seq_num, packet.ipv4.ttl());
                                    }
             
                                    // Check if we received last ping reply
                                    if (icmp_packet.content() & 0xFF) as u16 == (size - 1) {
                                        break;
                                    }
                                },
                                _ => ()
                            }
                        }
                    }
                    Err(_) => ()
                }
            }
        }
    });

    // Send ICMP packets
    println!("PING {} ({}): {} data bytes", ip_packet.dest_addr(), ip_packet.dest_addr(), icmp_packet.payload_size());
    
    for seq_num in 0..size {
        // Update the sequence number in the packet bytes and re-compute ICMP checksum
        content = ((identifier as u32) << 16) | (seq_num as u32);
        icmp_packet.set_content(content);
        icmp_packet.set_timestamp();
        icmp_packet.set_checksum();

        match icmp_packet.to_bytes() {
            Ok(payload) => ethernet_bytes.splice(34.., payload),
            Err(e) => {
                eprintln!("{e}");
                return;
            }
        };

        match addr_info.capture.sendpacket(ethernet_bytes.clone()) {
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

/**
 * Prints the devices/interfaces found on the computer
 * Outputs information including name, IP address, and netmask
 */
pub fn get_devices() {
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

