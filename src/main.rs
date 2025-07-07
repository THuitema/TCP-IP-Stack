use pcap::{Capture, Device};
use std::convert::TryInto;

struct EthernetHeader {
    dest_addr: [u8; 6],
    src_addr: [u8; 6],
    ethertype: u16 // specifies the protocol used in the packet payload (e.g. IPv4)
}

/**
 * Allows us to do "let e = EthernetHeader::from_bytes(foo)"
 */
impl EthernetHeader {
    /**
     * Converts raw bytes to an EthernetHeader, if the bytes are valid
     */
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 14 {
            return None;
        }

        let mut ethertype_bytes = [0u8; 2];
        ethertype_bytes.copy_from_slice(&bytes[12..14]);

        Some(EthernetHeader { 
            dest_addr: bytes[0..6].try_into().unwrap(), 
            src_addr: bytes[6..12].try_into().unwrap(),
            ethertype: u16::from_be_bytes(ethertype_bytes) 
        })
    }

    fn get_ethertype(ethertype_bytes: &u16) -> String{
        match ethertype_bytes {
            0x0800 => "IPv4".to_string(),
            0x86DD => "IPv6".to_string(),
            _ => ethertype_bytes.to_string()
        }
    }
}


fn main() {
    let device = Device::lookup().unwrap().unwrap();
    println!("Name: {:?}", device.name);
    if let Some(desc) = &device.desc {
        println!("Desc: {:?}", desc);
    }

    let mut cap = device.open().expect("Failed to open device");
    while let Ok(packet) = cap.next_packet() {
        // println!("received packet {:?}", packet);
        if let Some(ethernet_header) = EthernetHeader::from_bytes(packet.data) {
            let ethertype = EthernetHeader::get_ethertype(&ethernet_header.ethertype);
            println!("Packet with {:?} protocol received from {:?} to {:?}", ethertype, ethernet_header.src_addr, ethernet_header.dest_addr);
        } else {
            println!("Packet received, but error parsing the ethernet header");
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