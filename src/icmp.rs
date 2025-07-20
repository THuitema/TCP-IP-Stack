use pcap::Error;
use std::fmt;
use crate::parse::{ParsedPacket, Transport};
use chrono::{DateTime, Local};

pub struct ICMPPacket {
    header: ICMPHeader,
    payload: Vec<u8>
}

pub struct ICMPHeader {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    content: u32
}

impl ICMPPacket {
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
        })
    }

    /**
     * Returns bytes of ICMP Packet
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = self.header.to_bytes().unwrap();
        buf.extend(&self.payload);
        Ok(buf)
    }

    pub fn calculate_checksum(&self) -> u16 {
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
            if i != 10 {
                word = u16::from_be_bytes([self.payload[i], self.payload[i+1]]);
                checksum = checksum.wrapping_add(word as u32) // add one's complement of word
            }
        }   

        // add back the overflow bits
        while (checksum >> 16) != 0 {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        let result = !(checksum as u16);

        result
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
            "  Type: {},\n  Code: {},",
            self.get_type_name(),
            self.code
        )
    }
}

pub fn process_icmp(packet: &ParsedPacket) -> Result<(), Error> {
    // check type for echo reply & request --> parse content & payload
    let Transport::ICMP(tcmp_packet) = &packet.transport;
    let datetime: DateTime<Local> = packet.timestamp.into();
    let time_formatted = datetime.format("%H:%M").to_string();

    match tcmp_packet.header.icmp_type {
        0 => {
            // echo reply (you sent the ping)
            let identifier: u16 = (tcmp_packet.header.content >> 16) as u16;
            let seq_num: u16 = (tcmp_packet.header.content & 0xFF) as u16;

            println!("[{}] Ping reply from {}: icmp_seq={} identifier={}", time_formatted, packet.ipv4.header.src_addr, seq_num, identifier);
            Ok(())
        },
        8 => {
            // echo request (they sent the ping)
            let identifier: u16 = (tcmp_packet.header.content >> 16) as u16;
            let seq_num: u16 = (tcmp_packet.header.content & 0xFF) as u16;
            println!("[{}] Ping request from {}: icmp_seq={} identifier={}", time_formatted, packet.ipv4.header.src_addr, seq_num, identifier);
            Ok(())
        },
        n => {
            println!("[{}] ICMP packet received from {}: type={} code={}", time_formatted, packet.ipv4.header.src_addr, n, tcmp_packet.header.code);
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
