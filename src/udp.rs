use pcap::Error;
use std::fmt;
use crate::{addr_info::AddrInfo, ip::{IPv4Address, IPProtocol, self}, parse::{ParsedPacket, Transport}};
use chrono::{DateTime, Local};
use std::sync::mpsc;
use std::thread;

pub struct UDPDatagram {
    header: UDPHeader,
    data: Vec<u8>
}

struct UDPHeader {
    src_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16
}

pub struct UDPSocket {
    recv_queue: mpsc::Receiver<ParsedPacket>
}

impl UDPDatagram {
    /**
     * Returns a new UDPDatagram by specifying the required fields
     * Calculates and sets the checksum and length fields
     */
    pub fn new(src_port: u16, dest_port: u16, src_addr: &IPv4Address, dest_addr: &IPv4Address, data: &[u8]) -> Self {
        let header = UDPHeader {
            src_port,
            dest_port,
            length: 8 + data.len() as u16,
            checksum: 0
        };

        let mut packet = Self {
            header,
            data: data.to_vec()
        };

        packet.set_checksum(src_addr, dest_addr);
        packet
    }

    /**
     * Converts raw bytes to a UDPPacket, if the bytes are valid
     */
    pub fn from_bytes(data: &[u8], src_addr: &IPv4Address, dest_addr: &IPv4Address) -> Result<Self, Error> {
        if data.len() < 8 {
            return Err(Error::PcapError(format!("UDP packet has insufficient length ({} bytes)", data.len())));
        }

        let header = UDPHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dest_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        };

        let packet = UDPDatagram {
            header,
            data: data[8..].to_vec()
        };

        if !packet.verify_checksum(src_addr, dest_addr) {
            return Err(Error::PcapError("UDPDatagram checksum mismatch".to_string()))
        }

        Ok(packet)
    }

    /**
     * Returns bytes of UDP Datagram
     * Assumes checksum has already been calculated with self.set_checksum() or UDPDatagram::new()
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = self.header.to_bytes()?;
        buf.extend(&self.data);
        Ok(buf)
    }

    /** 
     * Getter for source port
     */
    pub fn src_port(&self) -> u16 {
        self.header.src_port
    }

    /** 
     * Setter for source port
     */
    pub fn set_src_port(&mut self, src_port: u16) {
        self.header.src_port = src_port
    }

    /** 
     * Getter for destination port
     */
    pub fn dest_port(&self) -> u16 {
        self.header.dest_port
    }

    /** 
     * Getter for datagram length
     */
    pub fn length(&self) -> u16 {
        self.header.length
    }

    /** 
     * Setter for destination port
     */
    pub fn set_dest_port(&mut self, dest_port: u16) {
        self.header.dest_port = dest_port
    }

    /**
     * Getter for checksum
     */
    pub fn checksum(&self) -> u16 {
        self.header.checksum
    }

    /**
     * Internally calculates, sets, and returns checksum
     */
    pub fn set_checksum(&mut self, src_addr: &IPv4Address, dest_addr: &IPv4Address) -> u16 {
        self.header.checksum = self.calculate_checksum(src_addr, dest_addr);
        self.header.checksum
    }

    /**
     * Calculates checksum of the UDPDatagram and returns true if it matches the checksum field
     */
    fn verify_checksum(&self, src_addr: &IPv4Address, dest_addr: &IPv4Address) -> bool {
        self.calculate_checksum(src_addr, dest_addr) == self.header.checksum
    }

    /**
     * Returns the checksum of the UDP datagram
     */
    fn calculate_checksum(&self, src_addr: &IPv4Address, dest_addr: &IPv4Address) -> u16 {
        let mut checksum: u32 = 0;

        // Pseudo-header
        let src_addr_bytes = src_addr.octects();
        let word = u16::from_be_bytes([src_addr_bytes[0], src_addr_bytes[1]]);
        checksum = checksum.wrapping_add(word as u32);
        let word = u16::from_be_bytes([src_addr_bytes[2], src_addr_bytes[3]]);
        checksum = checksum.wrapping_add(word as u32);

        let dest_addr_bytes = dest_addr.octects();
        let word = u16::from_be_bytes([dest_addr_bytes[0], dest_addr_bytes[1]]);
        checksum = checksum.wrapping_add(word as u32);
        let word = u16::from_be_bytes([dest_addr_bytes[2], dest_addr_bytes[3]]);
        checksum = checksum.wrapping_add(word as u32);

        checksum = checksum.wrapping_add(17); // protocol = 17 (UDP)
        checksum = checksum.wrapping_add(self.header.length as u32);

        // UDP header
        checksum = checksum.wrapping_add(self.header.src_port as u32);
        checksum = checksum.wrapping_add(self.header.dest_port as u32);
        checksum = checksum.wrapping_add(self.header.length as u32);

        // UDP data
        for i in (0..self.data.len() / 2 * 2).step_by(2) {
            let word = u16::from_be_bytes([self.data[i], self.data[i+1]]);
            checksum = checksum.wrapping_add(word as u32) // add one's complement of word
        } 

        // Check if we need to add last byte
        if self.data.len() % 2 == 1 {
            let last_byte = self.data[self.data.len() - 1];
            let word = u16::from_be_bytes([last_byte, 0]);
            checksum = checksum.wrapping_add(word as u32);
        }

        // add back the overflow bits
        while (checksum >> 16) != 0 {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        !(checksum as u16)
    }

    /** 
     * Getter for datagram data
     */
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /** 
     * Setter for datagram data
     */
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.header.length = 8 + data.len() as u16;
        self.data = data;
    }

}

impl UDPHeader {
    /**
     * Returns bytes of UDP datagram header
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&u16::to_be_bytes(self.src_port));
        buf.extend_from_slice(&u16::to_be_bytes(self.dest_port));
        buf.extend_from_slice(&u16::to_be_bytes(self.length));
        buf.extend_from_slice(&u16::to_be_bytes(self.checksum));
        Ok(buf)
    }
}

impl fmt::Display for UDPDatagram {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UDP Datagram \n{{\n{}\n  Data: {} bytes \n}}",
            self.header,
            self.data.len()
        )
    }
}

impl fmt::Display for UDPHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "  Source port: {},\n  Destination port: {},\n  Length: {},\n  Checksum: {},",
            self.src_port,
            self.dest_port,
            self.length,
            self.checksum
        )
    }
}

pub fn process_udp(packet: ParsedPacket) -> Result<(), Error> {
    let udp_datagram = match packet.transport {
        Transport::UDP(pack) => pack,
        _ => return Err(Error::PcapError("(process_udp) invalid ParsedPacked provided. Transport protocol is not UDP".to_string()))
    };

    let datetime: DateTime<Local> = packet.timestamp;
    let time_formatted = datetime.format("%H:%M").to_string();

    println!("[{}] UDP datagram from {}:{} to {}:{} ({} bytes)", time_formatted, packet.ipv4.src_addr(), udp_datagram.src_port(), packet.ipv4.dest_addr(), udp_datagram.dest_port(), udp_datagram.length());
    Ok(())
}

/**
 * Constructs and sends UDP datagram to destination IP address and port
 * dest_ipv4: IPv4Address, destination IP address
 * dest_port: u16, port to deliver datagram to at destination
 * addr_info: &mut AddrInfo, contains your device's network info
 * buffer: &[u8], bytes to send in payload
 */
pub fn send(dest_ipv4: IPv4Address, dest_port: u16, addr_info: &mut AddrInfo, buffer: &[u8]) -> Result<(), Error> {
    let udp = UDPDatagram::new(addr_info.port, dest_port, &addr_info.addr_ipv4, &dest_ipv4, buffer);
    let udp_bytes = udp.to_bytes()?;
    ip::send(dest_ipv4, addr_info, IPProtocol::UDP, &udp_bytes)
}

impl UDPSocket {
    /**
     * Starts a listening thread on port specified in addr_info for host
     * addr_info: AddrInfo, contains your device's network info
     */
    pub fn bind(addr_info: AddrInfo) -> Result<Self, Error> {
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let mut cap = addr_info.capture;
            loop {
                if let Ok(captured_frame) = cap.next_packet() {
                    if let Ok(packet) = ParsedPacket::from_ethernet(captured_frame) {
                        if let Transport::UDP(datagram) = &packet.transport {
                            if datagram.dest_port() == addr_info.port && tx.send(packet).is_err() {
                                break;
                            }
                        }                
                    } 
                }
            }
        });

        Ok(UDPSocket { recv_queue: rx })
    }

    /**
     * Returns next parsed UDP packet received on port set in bind()
     * Blocks if no packets received
     */
    pub fn recv(&self) -> Result<ParsedPacket, Error> {
        match self.recv_queue.recv() {
            Ok(packet) => Ok(packet),
            Err(e) => Err(Error::PcapError(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /**
     * Verify converting packet to bytes and back does not change it
     */
    #[test]
    fn test_udp_packet() {
        let src_addr = IPv4Address::new(192, 168, 1, 45);
        let dest_addr = IPv4Address::new(192, 168, 5, 87);
        let data = vec![0x54, 0x29, 0x03, 0x04];

        let datagram = UDPDatagram::new(1080, 4200, &src_addr, &dest_addr, &data);
        println!("{}", datagram);

        let datagram_bytes = datagram.to_bytes().unwrap();
        let datagram2 = UDPDatagram::from_bytes(&datagram_bytes, &src_addr, &dest_addr).unwrap();

        println!("{}", datagram2);

        assert!(datagram2.verify_checksum(&src_addr, &dest_addr));
        assert_eq!(datagram.src_port(), datagram2.src_port());
        assert_eq!(datagram.dest_port(), datagram2.dest_port());
        assert_eq!(datagram.length(), datagram2.length());
        assert_eq!(datagram.data(), datagram2.data());
    }
}
