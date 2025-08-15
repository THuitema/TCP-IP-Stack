#![allow(dead_code)]

use tcpip_stack::parse::{ParsedPacket, Transport};
use tcpip_stack::utils::{ping, test_udp_send};
use tcpip_stack::icmp::process_icmp;
use tcpip_stack::addr_info::{AddrInfo, setup_addr_info};
use tcpip_stack::udp::{process_udp};

fn main() {
    let mut addr_info: AddrInfo = match setup_addr_info(Some("en0"), 2048) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    println!("{} {} {}", addr_info.addr_ipv4, addr_info.addr_mac, addr_info.router_mac);
    // capture_loop(&mut addr_info, 100);
    test_udp_send(&mut addr_info);
}

fn capture_loop(addr_info: &mut AddrInfo, size: usize) {
    let mut count = 0;

    // TODO: implement some sort of multithreading to parse each packet asynchronously
    while let Ok(captured_frame) = addr_info.capture.next_packet() {
        count += 1;

        if let Ok(packet) = ParsedPacket::from_ethernet(captured_frame) {
            match &packet.transport {
                Transport::ICMP(_) => {
                    match process_icmp(packet, addr_info) {
                        Ok(_) => (),
                        Err(e) => eprintln!("{}", e)
                    }
                },
                Transport::UDP(_) => {
                    match process_udp(packet) {
                        Ok(_) => (),
                        Err(e) => eprintln!("{}", e)
                    }
                },
                _ => ()
            }                
        } 

        if count > size {
            break;
        }
    }
}
