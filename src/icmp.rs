use pcap::Error;
use std::fmt;

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

        // todo verify checksum like IPv4 packets
        Ok(ICMPPacket { 
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

