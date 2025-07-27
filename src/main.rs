#![allow(dead_code)]
mod ethernet;
mod ip;
mod icmp;
mod parse;
mod utils;
mod addr_info;

use ethernet::MACAddress;
use ip::IPv4Address;
use parse::parse;
use utils::ping;
use icmp::process_icmp;
use addr_info::{AddrInfo, setup_addr_info};

fn main() {
    let mut addr_info: AddrInfo = match setup_addr_info(Some("en0")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    println!("MAC: {}, IP: {}", addr_info.addr_mac, addr_info.addr_ipv4);

    capture_loop(&mut addr_info, 100);
}

fn capture_loop(addr_info: &mut AddrInfo, size: usize) {
    let mut count = 0;

    // TODO: implement some sort of multithreading to parse each packet asynchronously
    while let Ok(captured_frame) = addr_info.capture.next_packet() {
        count += 1;

        match parse(captured_frame) {
            Ok(packet) => {
                // print some log
                println!("{}", packet);
                
                match process_icmp(&packet) {
                    Ok(_) => (),
                    Err(e) => eprintln!("{}", e)
                }
            },
            Err(e) => eprintln!("{}", e)
        } 

        if count > size {
            break;
        }
    }
}
