use pcap::{Capture, Device};
use std::convert::TryInto;
use std::fmt;

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

    /**
     * Returns the protocol name (if available) of the ethertype
     * Full list is available here: https://en.wikipedia.org/wiki/EtherType
     */
    fn ethertype_to_protocol_name(&self) -> String{
        match self.ethertype {
            0x0800 => "IPv4".to_string(),
            0x86DD => "IPv6".to_string(),
            n => format!("{:X}", n) // returns the hexadecimal string of the ethertype
        }
    }
}

impl fmt::Display for EthernetHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let dest_str = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
            self.dest_addr[0], self.dest_addr[1], self.dest_addr[2], self.dest_addr[3], self.dest_addr[4], self.dest_addr[5]);
        
        let src_str = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
            self.src_addr[0], self.src_addr[1], self.src_addr[2], self.src_addr[3], self.src_addr[4], self.src_addr[5]);

        write!(
            f,
            "EthernetHeader {{ ethertype: {}, dest: {:?}, src: {:?} }}",
            self.ethertype_to_protocol_name(),
            dest_str,
            src_str
        )
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
            println!("{}", ethernet_header);
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