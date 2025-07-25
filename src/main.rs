#![allow(dead_code)]
mod ethernet;
mod ip;
mod icmp;
mod parse;
mod utils;

use ethernet::MACAddress;
use ip::IPv4Address;
use parse::parse;
use pcap::{Active, Capture};
use utils::ping;
use icmp::process_icmp;

fn main() {
    let dest_ip = IPv4Address::new(8, 8, 8, 8);
    let dest_mac = MACAddress::from_slice([200, 167, 10, 144, 9, 72]); 
    ping(dest_ip, dest_mac, 10);
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
