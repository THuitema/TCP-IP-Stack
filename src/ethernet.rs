use pcap::{Active, Capture, Error};
use core::str;
use std::{collections::HashMap, convert::TryInto};
use std::fmt;
use std::process::Command;
use crate::ip::IPv4Address;
use crate::{addr_info::AddrInfo};

#[derive(Clone)]
pub struct EthernetFrame {
    header: EthernetHeader,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct EthernetHeader {
    dest_addr: MACAddress, // destination MAC address (6 bytes)
    src_addr: MACAddress,  // source MAC address (6 bytes)
    ethertype: u16,        // protocol used in the packet payload (e.g. IPv4) (2 bytes)
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct MACAddress {
    octets: [u8; 6]
}

pub struct ARPEntries {
    entries: HashMap<IPv4Address, MACAddress>
}

impl EthernetFrame {
    /**
     * Returns a new EthernetFrame
     */
    pub fn new(src_addr: MACAddress, dest_addr: MACAddress, ethertype: u16, payload: &[u8]) -> Self {
        let header = EthernetHeader {
            dest_addr,
            src_addr,
            ethertype
        };

        Self {
            header,
            payload: payload.to_vec()
        }
    }

    /**
     * Converts raw bytes to an EthernetFrame, if the bytes are valid
     */
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 14 {
            return Err(Error::PcapError(String::from("Invalid ethernet frame")));
        }

        let mut ethertype_bytes = [0u8; 2];
        ethertype_bytes.copy_from_slice(&data[12..14]);

        let header = EthernetHeader {
            dest_addr: MACAddress::from_slice(data[0..6].try_into().unwrap()),
            src_addr: MACAddress::from_slice(data[6..12].try_into().unwrap()),
            ethertype: u16::from_be_bytes(ethertype_bytes),
        };

        let payload = data[14..].to_vec();

        Ok(EthernetFrame {
            header,
            payload,
        })
    }

    /**
     * Returns bytes of EthernetFrame
     * Error returned if payload exceeds 1500 bytes
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = self.header.to_bytes().unwrap();

        // verify payload is under 1500 bytes
        if self.payload.len() > 1500 {
            return Err(Error::PcapError(String::from("Cannot convert ethernet frame to bytes. Payload exceeds 1500 bytes")));
        }

        buf.extend(&self.payload);

        Ok(buf)
    }

    /**
     * Sends EthernetFrame to dest_addr (MAC address of destination)
     */
    pub fn send_frame(&self, capture: &mut Capture<Active>) -> Result<(), Error> {
        match self.to_bytes() {
            Ok(buffer) => capture.sendpacket(buffer),
            Err(e) => Err(e)
        }
    }

    /**
     * Sends EthernetFrame already in byte form to dest_addr
     * Useful if sending multiple EthernetFrames and only changing a few bytes between each one, to avoid calling to_bytes() every time
     */
    pub fn send_frame_bytes(&self, capture: &mut Capture<Active>, bytes: Vec<u8>) -> Result<(), Error> {
        capture.sendpacket(bytes)
    }

    /**
     * Getter for destination MAC address
     */
    pub fn dest_addr(&self) -> &MACAddress {
        &self.header.dest_addr
    }

    /**
     * Setter for destination MAC address
     */
    pub fn set_dest_addr(&mut self, addr: MACAddress) {
        self.header.dest_addr = addr
    }

    /**
     * Getter for source MAC address
     */
    pub fn src_addr(&self) -> &MACAddress {
        &self.header.src_addr
    }

    /**
     * Setter for source MAC address
     */
    pub fn set_src_addr(&mut self, addr: MACAddress) {
        self.header.src_addr = addr
    }

    /**
     * Getter for ethertype
     */
    pub fn ethertype(&self) -> u16 {
        self.header.ethertype
    }

    /**
     * Setter for ethertype
     */
    pub fn set_ethertype(&mut self, ethertype: u16) {
        self.header.ethertype = ethertype
    }

    /**
     * Returns the protocol name (if available) of the ethertype
     * Full list is available here: https://en.wikipedia.org/wiki/EtherType
     */
    pub fn ethertype_to_protocol_name(&self) -> String {
        self.header.ethertype_to_protocol_name()
    }

    /**
     * Getter for payload
     */
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /**
     * Setter for payload
     */
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }
}

/**
 * Allows us to do "let e = EthernetHeader::from_bytes(foo)"
 */
impl EthernetHeader {
    /**
     * Returns the protocol name (if available) of the ethertype
     * Full list is available here: https://en.wikipedia.org/wiki/EtherType
     */
    fn ethertype_to_protocol_name(&self) -> String {
        match self.ethertype {
            0x0800 => "IPv4".to_string(),
            0x86DD => "IPv6".to_string(),
            0x0806 => "ARP".to_string(),
            n => format!("{:X}", n), // returns the hexadecimal string of the ethertype
        }
    }

    /**
     * Returns bytes of EthernetHeader
     */
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&self.dest_addr.octets);
        buf.extend_from_slice(&self.src_addr.octets);
        buf.extend_from_slice(&self.ethertype.to_be_bytes());

        Ok(buf)
    }
}

impl MACAddress {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self { octets: [a, b, c, d, e, f] }
    }

    pub fn from_slice(slice: [u8; 6]) -> Self {
        Self {octets: slice}
    }

    /**
     * Converts string in hexadecimal format "XX:XX:XX:XX:XX:XX" to MACAddress
     * 
     */
    pub fn from_hex_str(str: &str) -> Option<Self> {
        let str_toks: Vec<&str> = str.split(":").collect();
        if str_toks.len() != 6 {
            return None;
        }

        let octets_u8: Option<Vec<u8>> = str_toks
            .iter()
            .map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if let Some(octets) = octets_u8 {
            return Some(Self::from_slice(octets.try_into().unwrap()))
        }
        return None
    }
}

impl ARPEntries {
    /**
     * Parses the response of "arp -a" to fetch hosts' IP and MAC addresses in local network
     */
    pub fn new() -> Result<Self, Error> {
        let output = Command::new("arp")
            .arg("-a")
            .output()
            .expect("Failed to run ARP");
        
        if !output.status.success() {
            return Err(Error::PcapError(String::from_utf8(output.stderr).unwrap()));
        }

        let stdout = str::from_utf8(&output.stdout).unwrap();
        let lines: Vec<&str> = stdout.lines().collect();

        // parse IPv4Address and MAC address from each line
        let mut entries: HashMap<IPv4Address, MACAddress> = HashMap::new();

        for line in lines {
            let line_toks: Vec<&str> = line.split_whitespace().collect();
            if line_toks.len() >= 4 {
                let ip_str = &line_toks[1][1..line_toks[1].len() - 1]; // removes parentheses
                let mac_str = line_toks[3];
                
                if let (Some(ipv4), Some(mac)) = (IPv4Address::from_str(ip_str), MACAddress::from_hex_str(mac_str)) {
                    entries.insert(ipv4, mac);
                }
            }
        }

        Ok(Self { entries: HashMap::new() })
    }
}

impl fmt::Display for EthernetFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EthernetFrame {{\n{} \n  Payload: {} bytes \n}}",
            self.header,
            self.payload.len()
        )
    }
}

impl fmt::Display for EthernetHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "  Ethertype: {},\n  Destination: {},\n  Source: {}",
            self.ethertype_to_protocol_name(),
            self.dest_addr,
            self.src_addr
        )
    }
}

impl fmt::Display for MACAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}

/**
 * Constructs and sends ethernet frame
 * dest_mac: MACAddress, typically your device's router MAC address if buffer represents an IP packet
 * addr_info: &mut AddrInfo, contains your device's network info
 * buffer: &[u8], bytes to send
 */
pub fn send(dest_mac: MACAddress, addr_info: &mut AddrInfo, buffer: &[u8]) -> Result<(), Error> {
    let ethertype = 0x0800; // default ipv4 for now
    let ethernet = EthernetFrame::new(addr_info.addr_mac, dest_mac, ethertype, buffer);
    ethernet.send_frame(&mut addr_info.capture)
}

pub fn capture_ethernet_frames(capture: &mut Capture<Active>, count: usize) -> Vec<EthernetFrame> {
    let mut frames: Vec<EthernetFrame> = Vec::new();

    while let Ok(packet) = capture.next_packet() {
        match EthernetFrame::from_bytes(packet.data) {
            Ok(ethernet_frame) => frames.push(ethernet_frame),
            Err(e) => eprintln!("{}", e),
        }

        if frames.len() >= count {
            break;
        }
    }

    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    /**
     * Verify converting frame to bytes and back does not change the frame
     */
    #[test]
    fn test_frame_bytes() {
        let header = EthernetHeader {
                dest_addr: MACAddress::new(108, 126, 103, 204, 17, 197),
                src_addr: MACAddress::new(200, 167, 10, 144, 9, 72),
                ethertype: 0x0800 as u16
        };

        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let frame = EthernetFrame {
            header: header,
            payload: payload
        };

        println!("{}", frame);

        let frame_bytes = frame.to_bytes().unwrap();

        let frame2 = EthernetFrame::from_bytes(&frame_bytes).unwrap();
        println!("{}", frame2);

        assert_eq!(frame.payload, frame2.payload);
        assert_eq!(frame.dest_addr(), frame2.dest_addr());
        assert_eq!(frame.src_addr(), frame2.src_addr());
        assert_eq!(frame.header.ethertype, frame2.header.ethertype);
    }
}
