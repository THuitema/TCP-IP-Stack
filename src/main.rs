#![allow(dead_code)]

use tcpip_stack::ethernet::MACAddress;
use tcpip_stack::ip::IPv4Address;
use tcpip_stack::parse::{ParsedPacket, Transport};
use tcpip_stack::utils::{ping, test_udp_send};
use tcpip_stack::icmp::process_icmp;
use tcpip_stack::addr_info::{AddrInfo, setup_addr_info};
use tcpip_stack::udp::{process_udp, UDPSocket};

fn main() {
    // Need to hardcode MAC address of router until we implement ARP
    let router_mac = MACAddress::new(0xc8, 0xa7, 0xa, 0x90, 0x9, 0x48);

    let addr_info: AddrInfo = match setup_addr_info(Some("en0"), 54456, router_mac) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };
    // capture_loop(&mut addr_info, 100);
    // test_udp_send(&mut addr_info);

    let sock = UDPSocket::bind(addr_info).unwrap();
    
    for _ in 0..10 {
        let packet = sock.recv().unwrap();
        if let Transport::UDP(datagram) = &packet.transport {
            println!("{} (port {})", packet, datagram.dest_port());
            println!("{}", datagram);
        }
        
    }
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
