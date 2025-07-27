use pcap::Error;
use std::fmt;
use crate::{addr_info::AddrInfo, parse::{ParsedPacket, Transport}};
use chrono::{DateTime, Local, LocalResult, TimeZone};

#[derive(Clone)]
pub struct ICMPPacket {
    header: ICMPHeader,
    payload: Vec<u8>
}

#[derive(Clone)]
struct ICMPHeader {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    content: u32
}

impl ICMPPacket {
    /**
     * Returns a default ICMPPacket, given the required fields
     */
    pub fn new(icmp_type: u8, code: u8, content: u32, payload: Vec<u8>) -> Self {
        let header = ICMPHeader {
            icmp_type: icmp_type,
            code: code,
            checksum: 0,
            content: content
        };

        let mut packet = Self {
            header: header,
            payload: payload
        };

        packet.header.checksum = packet.calculate_checksum();
        packet
    }

    /**
     * Converts raw bytes to an ICMPPacket
     */
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 8 {
            return Err(Error::PcapError(format!("ICMP packet has insufficient length ({} bytes)", data.len())))
        }

        let header = ICMPHeader {
            icmp_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            content: u32::from_be_bytes([data[4], data[5], data[6], data[7]])
        };

        let packet = ICMPPacket { 
            header: header, 
            payload: data[8..].to_vec()
        };

        if packet.header.checksum != packet.calculate_checksum() {
            return Err(Error::PcapError("ICMP packet checksum mismatch".to_string()));
        }

        Ok(packet)
    }

    /**
     * Returns bytes of ICMP Packet
     * Assumes checksum has already been calculated with self.set_checksum() 
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = self.header.to_bytes().unwrap();
        buf.extend(&self.payload);
        Ok(buf)
    }

    /** 
     * Getter for ICMP type
     */
    pub fn icmp_type(&self) -> u8 {
        self.header.icmp_type
    }

    /** 
     * Setter for ICMP type
     */
    pub fn set_icmp_type(&mut self, icmp_type: u8) {
        self.header.icmp_type = icmp_type
    }

    /** 
     * Getter for code
     */
    pub fn code(&self) -> u8 {
        self.header.code
    }

    /** 
     * Setter for code
     */
    pub fn set_code(&mut self, code: u8) {
        self.header.code = code
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
    pub fn set_checksum(&mut self) -> u16 {
        self.header.checksum = self.calculate_checksum();
        self.header.checksum
    }

    /**
     * Returns the checksum of the ICMP packet
     */
    fn calculate_checksum(&self) -> u16 {
        let mut checksum: u32 = 0;

        let mut word = u16::from_be_bytes([self.header.icmp_type, self.header.code]);
        checksum = checksum.wrapping_add(word as u32);

        let content_bytes = u32::to_be_bytes(self.header.content);

        word = u16::from_be_bytes([content_bytes[0], content_bytes[1]]);
        checksum = checksum.wrapping_add(word as u32);

        word = u16::from_be_bytes([content_bytes[2], content_bytes[3]]);
        checksum = checksum.wrapping_add(word as u32);

        // add each 16-bit word in payload
        for i in (0..self.payload.len()).step_by(2) {
            word = u16::from_be_bytes([self.payload[i], self.payload[i+1]]);
            checksum = checksum.wrapping_add(word as u32) // add one's complement of word
        }   

        // add back the overflow bits
        while (checksum >> 16) != 0 {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        let result = !(checksum as u16);

        result
    }

    pub fn content(&self) -> u32 {
        self.header.content
    }
    
    pub fn set_content(&mut self, content: u32) {
        self.header.content = content;
    }

    /**
     * Getter for payload
     */
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /**
     * Returns number of bytes in payload
     */
    pub fn payload_size(&self) -> usize {
        self.payload.len()
    }

    /**
     * Setter for payload
     */
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload
    }

    /**
     * Sets first 8 bytes of payload to current time in milliseconds
     */
    pub fn set_timestamp(&mut self) {
        let time_millis = Local::now().timestamp_millis();
        self.payload[..8].copy_from_slice(&time_millis.to_be_bytes());
    }

    /**
     * Attempts to extract timestamp in milliseconds from first 8 bytes of payload
     */
    pub fn get_timestamp(&self) -> Option<DateTime<Local>> {
        if self.payload.len() < 8 {
            return None;
        }

        let timestamp_bytes = i64::from_be_bytes(self.payload[..8].try_into().unwrap());
        if let LocalResult::Single(t) = Local.timestamp_millis_opt(timestamp_bytes) {
            return Some(t);
        }
        None
    }

    /**
     * Returns number of bytes in packet
     */
    pub fn size(&self) -> usize {
        return 8 + self.payload.len()
    }
}

impl ICMPHeader {
    /**
     * Returns bytes of ICMP Header
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(self.icmp_type);
        buf.push(self.code);
        buf.extend_from_slice(&u16::to_be_bytes(self.checksum));
        buf.extend_from_slice(&u32::to_be_bytes(self.content));
        Ok(buf)
    }

    /**
     * Translate common protocol names
     */
    pub fn get_type_name(&self) -> String {
        match self.icmp_type {
            0 => "0 - Echo Reply".to_string(),
            3 => "3 - Destination Unreachable".to_string(),
            5 => "5 - Source Quench".to_string(),
            8 => "8 - Echo Request".to_string(),
            n => format!("{}", n),
        }
    }
}

impl fmt::Display for ICMPPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ICMP Packet {{\n{} \n  Payload: {} bytes \n}}",
            self.header,
            self.payload.len()
        )
    }
}

impl fmt::Display for ICMPHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "  Type: {},\nCode: {},\nChecksum: {},\nContent: {}",
            self.get_type_name(),
            self.code,
            self.checksum,
            self.content
        )
    }
}

pub fn process_icmp(packet: &ParsedPacket) -> Result<(), Error> {
    // check type for echo reply & request --> parse content & payload
    let icmp_packet = match &packet.transport {
        Transport::ICMP(pack) => pack,
        _ => return Err(Error::PcapError("(process_icmp) invalid ParsedPacket provided. Transport protocol is not ICMP".to_string()))
    };
    // let Transport::ICMP(icmp_packet) = &packet.transport;
    let datetime: DateTime<Local> = packet.timestamp.into();
    let time_formatted = datetime.format("%H:%M").to_string();


    match icmp_packet.header.icmp_type {
        0 => {
            // echo reply (you sent the ping)
            let identifier: u16 = (icmp_packet.header.content >> 16) as u16;
            let seq_num: u16 = (icmp_packet.header.content & 0xFF) as u16;

            println!("[{}] Ping reply from {}: icmp_seq={} identifier={}", time_formatted, packet.ipv4.src_addr(), seq_num, identifier);
            Ok(())
        },
        8 => {
            // echo request (they sent the ping)
            let identifier: u16 = (icmp_packet.header.content >> 16) as u16;
            let seq_num: u16 = (icmp_packet.header.content & 0xFF) as u16;
            println!("[{}] Ping request from {}: icmp_seq={} identifier={}", time_formatted, packet.ipv4.src_addr(), seq_num, identifier);
            Ok(())
        },
        n => {
            println!("[{}] ICMP packet received from {}: type={} code={}", time_formatted, packet.ipv4.src_addr(), n, icmp_packet.header.code);
            Ok(())
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
    fn test_icmp_packet() {
        let header = ICMPHeader {
            icmp_type: 8,
            code: 0,
            checksum: 0,
            content: 987654321
        };

        let mut packet = ICMPPacket {
            header: header,
            payload: vec![0x01, 0x02, 0x03, 0x04]
        };

        packet.header.checksum = packet.calculate_checksum();
        let packet_bytes = packet.to_bytes().unwrap();

        let packet2 = ICMPPacket::from_bytes(&packet_bytes).unwrap();

        println!("Packet 1:\n{}", packet);
        println!("Packet 2:\n{}", packet2);
        
        assert_eq!(packet.payload, packet2.payload);
        assert_eq!(packet.header.icmp_type, packet2.header.icmp_type);
        assert_eq!(packet.header.code, packet2.header.code);
        assert_eq!(packet.header.checksum, packet2.header.checksum);
        assert_eq!(packet.header.content, packet2.header.content);
    }
}
