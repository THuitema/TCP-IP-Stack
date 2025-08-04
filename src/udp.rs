use pcap::Error;
use std::fmt;

use crate::ip::IPv4Address;

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

impl UDPDatagram {
    /**
     * Returns a new UDPDatagram by specifying the required fields
     */
    pub fn new(src_port: u16, dest_port: u16, src_addr: IPv4Address, dest_addr: IPv4Address, data: Vec<u8>) -> Self {
        let header = UDPHeader {
            src_port: src_port,
            dest_port: dest_port,
            length: 8 + data.len() as u16,
            checksum: 0
        };

        let mut packet = Self {
            header: header,
            data: data
        };

        packet.set_checksum(17, src_addr, dest_addr);
        packet
    }

    /**
     * Converts raw bytes to a UDPPacket, if the bytes are valid
     */
    pub fn from_bytes(data: &Vec<u8>) -> Result<UDPDatagram, Error> {
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
            header: header,
            data: data[8..].to_vec()
        };

        Ok(packet)
    }

    /**
     * Returns bytes of UDP Datagram
     * Assumes checksum has already been calculated with self.set_checksum() 
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
    pub fn set_checksum(&mut self, protocol: u8, src_addr: IPv4Address, dest_addr: IPv4Address) -> u16 {
        self.header.checksum = self.calculate_checksum(protocol, src_addr, dest_addr);
        self.header.checksum
    }

    /**
     * Verify checksum after receiving a datagram with from_bytes()
     */
    pub fn verify_checksum(&self, protocol: u8, src_addr: IPv4Address, dest_addr: IPv4Address) -> Result<(), Error> {
        if self.header.checksum != self.calculate_checksum(protocol, src_addr, dest_addr) {
            return Err(Error::PcapError("UDP datagram checksum mismatch".to_string()));
        }
        Ok(())
    }

    /**
     * Returns the checksum of the UDP datagram
     */
    fn calculate_checksum(&self, protocol: u8, src_addr: IPv4Address, dest_addr: IPv4Address) -> u16 {
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

        checksum = checksum.wrapping_add(protocol as u32);
        checksum = checksum.wrapping_add(self.header.length as u32);

        // UDP header
        checksum = checksum.wrapping_add(self.header.src_port as u32);
        checksum = checksum.wrapping_add(self.header.dest_port as u32);
        checksum = checksum.wrapping_add(self.header.length as u32);

        // UDP data
        for i in (0..self.data.len()).step_by(2) {
            let word = u16::from_be_bytes([self.data[i], self.data[i+1]]);
            checksum = checksum.wrapping_add(word as u32) // add one's complement of word
        } 

        // Check if we need to add last byte
        if self.data.len() % 2 == 1 {
            checksum = checksum.wrapping_add(*self.data.last().unwrap() as u32);
        }

        // add back the overflow bits
        while (checksum >> 16) != 0 {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        let result = !(checksum as u16);

        result
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
            "UDP Datagram, {{\n{} \n  Data: {} bytes \n}}",
            self.header,
            self.data.len()
        )
    }
}

impl fmt::Display for UDPHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "  Source port: {},\nDestination port: {},\nLength: {},\nChecksum: {}",
            self.src_port,
            self.dest_port,
            self.length,
            self.checksum
        )
    }
}