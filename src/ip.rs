

use pcap::Error;
use std::fmt;


pub struct IPv4Packet {
    pub header: IPv4Header,
    pub payload: Vec<u8>,
}

pub struct IPv4Header {
    version: u8,              // IP version (4 bits)
    ihl: u8,                  // length of header in 32-bit words (4 bits)
    dscp: u8,                 // Differentiated Services Code Point (6 bits)
    ecn: u8,                  // Explicit Congestion Notification (2 bits)
    packet_length: u16,       // length of packet, including header (16 bits)
    identification: u16,      // ID to reassemble packet, if fragmented (16 bits)
    flags: u8,                // 3 bits
    offset: u16,              // offset (number of bytes divided by 8) from where this data starts in reassembled packet (13 bits)
    ttl: u8,                  // time to live (8 bits)
    protocol: u8,             // higher-level protocol used (8 bits)
    checksum: u16,            // 16 bits
    src_addr: IPv4Address,    // IP address of source (32 bits)
    dest_addr: IPv4Address,   // IP address of destination (32 bits)
    options: Option<Vec<u8>>  // optional
}

pub struct IPv4Address {
    octets: [u8; 4]
}

impl IPv4Packet {
    pub fn from_bytes(payload: &Vec<u8>) -> Result<IPv4Packet, Error> {
        // Header is at least 20 bytes
        if payload.len() < 20 {
            return Err(Error::PcapError(format!("IPv4 packet has insufficient length ({} bytes)", payload.len())))
        }
        let version = payload[0] >> 4; // first 4 bits

        if version != 4 {
            return Err(Error::PcapError(String::from("Packet is not IPv4")));
        }

        let ihl = payload[0] & 0x0F; // last 4 bits
        let dcsp = payload[1] >> 2;
        let ecn = payload[1] & 0x03;
        let packet_length = u16::from_be_bytes([payload[2], payload[3]]);
        let identification = u16::from_be_bytes([payload[4], payload[5]]);
        let flags = payload[6] >> 5;
        let offset = u16::from_be_bytes([payload[6] & 0x1F, payload[7]]); // bottom 5 bits of byte 6 plus byte 7
        let ttl = payload[8];
        let protocol = payload[9];
        let checksum = u16::from_be_bytes([payload[10], payload[11]]);

        let src_addr_u32 = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let dest_addr_u32 = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let src_addr_ip = IPv4Address::from_u32(src_addr_u32);
        let dest_addr_ip = IPv4Address::from_u32(dest_addr_u32);
        

        // Check if there are options and padding
        let options: Option<Vec<u8>>;
        let ip_payload: Vec<u8>;

        let options_len = ihl * 4 - 20;
        if options_len > 0 {
            options = Some(payload[20..(20 + options_len) as usize].to_vec());
            ip_payload = payload[(20 + options_len) as usize..].to_vec();
        } else {
            options = None;
            ip_payload = payload[20..].to_vec();
        }

        let header = IPv4Header {
            version: version,
            ihl: ihl,
            dscp: dcsp,
            ecn: ecn,
            packet_length: packet_length,
            identification: identification,
            flags: flags,
            offset: offset,
            ttl: ttl,
            protocol: protocol,
            checksum: checksum,
            src_addr: src_addr_ip,
            dest_addr: dest_addr_ip,
            options: options
        };

        let packet = IPv4Packet {
            header: header,
            payload: ip_payload,
        };

        match IPv4Packet::verify_checksum(&packet) {
            true => Ok(packet),
            false => Err(Error::PcapError(String::from("IPv4 packet rejected (checksum mismatch)"))) // TODO: send ICMP packet back to sender
        }

        // TODO: check that TTL is not 0 (send ICMP packet if it is)

    }

    /**
     * Returns bytes of IPv4 Packet
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = self.header.to_bytes().unwrap();
        buf.extend(&self.payload);

        Ok(buf)
    }

    fn verify_checksum(&self) -> bool {
        let calculated_checksum = self.header.calculate_checksum();
        calculated_checksum == self.header.checksum
    }
}

impl IPv4Header {
    /**
     * Returns bytes of IPv4 Header
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = Vec::new();

        // version is first 4 bits, ihl is bottom 4
        buf.push((self.version & 0x0F) << 4 | (self.ihl & 0x0F));

        // dscp is first 6 bits, ecn is bottom 2
        buf.push((self.dscp & 0x3F) << 2 | (self.ecn & 0x03));

        // packet length, break into 2 bytes
        buf.extend_from_slice(&u16::to_be_bytes(self.packet_length));

        // identification, break into 2 bytes
        buf.extend_from_slice(&u16::to_be_bytes(self.identification));

        // flags and offset (2 bytes)
        let offset_bytes = u16::to_be_bytes(self.offset);

        buf.push((self.flags & 0x07) << 5 | (offset_bytes[0] & 0x1F));
        buf.push(offset_bytes[1]);

        buf.push(self.ttl);
        buf.push(self.protocol);
        buf.extend_from_slice(&u16::to_be_bytes(self.checksum));

        buf.extend_from_slice(&self.src_addr.octets);
        buf.extend_from_slice(&self.dest_addr.octets);

        if let Some(options) = &self.options {
            buf.extend(options);
        }

        Ok(buf)
    }

    /**
     * Calculate checksum of header
     */
    pub fn calculate_checksum(&self) -> u16 {
        let mut checksum: u32 = 0;

        let mut word = u16::from_be_bytes([(self.version & 0x0F) << 4 | (self.ihl & 0x0F), (self.dscp & 0x3F) << 2 | (self.ecn & 0x03)]);
        checksum = checksum.wrapping_add(word as u32);

        checksum = checksum.wrapping_add(self.packet_length as u32);

        checksum = checksum.wrapping_add(self.identification as u32);

        // flags and offset
        let offset_bytes = u16::to_be_bytes(self.offset);

        word = u16::from_be_bytes([(self.flags & 0x07) << 5 | (offset_bytes[0] & 0x1F), offset_bytes[1]]);
        checksum = checksum.wrapping_add(word as u32);

        word = u16::from_be_bytes([self.ttl, self.protocol]);
        checksum = checksum.wrapping_add(word as u32);

        // Source and Destination IP addresses
        word = u16::from_be_bytes([self.src_addr.octets[0], self.src_addr.octets[1]]);
        checksum = checksum.wrapping_add(word as u32);

        word = u16::from_be_bytes([self.src_addr.octets[2], self.src_addr.octets[3]]);
        checksum = checksum.wrapping_add(word as u32);

        word = u16::from_be_bytes([self.dest_addr.octets[0], self.dest_addr.octets[1]]);
        checksum = checksum.wrapping_add(word as u32);

        word = u16::from_be_bytes([self.dest_addr.octets[2], self.dest_addr.octets[3]]);
        checksum = checksum.wrapping_add(word as u32);

        // add options
        if let Some(options) = &self.options {
            for i in (0..usize::from(options.len())).step_by(2) {
                if i != 10 {
                    let word = u16::from_be_bytes([options[i], options[i+1]]);
                    checksum = checksum.wrapping_add(word as u32) // add one's complement of word
                }
            }
        }

        // add back the overflow bits
        while (checksum >> 16) != 0 {
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        }

        let result = !(checksum as u16);

        result
    }

    /**
     * Translate common protocol names
     */
    pub fn get_protocol_name(&self) -> String {
        match self.protocol {
            1 => "ICMP".to_string(),
            2 => "IGMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            41 => "ENCAP".to_string(),
            89 => "OSPF".to_string(),
            132 => "SCTP".to_string(),
            n => format!("Other ({})", n),
        }
    }
}

impl IPv4Address {
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self { octets: [a, b, c, d] }
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.octets)
    }

    pub fn from_u32(ip: u32) -> Self {
        Self { octets: ip.to_be_bytes() }
    }
}

impl fmt::Display for IPv4Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IPv4 Packet {{\n{} \n  Payload: {} bytes \n}}",
            self.header,
            self.payload.len()
        )
    }
}

impl fmt::Display for IPv4Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let options = match self.options.clone() {
            Some(o) => format!("{} bytes", o.len()),
            None => "None".to_string()
        };

        write!(
            f,
            "  Version: {},\n  Header Length (in 32-bit words): {} words,\n  Differentiated Services Code Point (DSCP): {},\n  Explicit Congestion Notification (ECN): {},\n  Packet Length: {} bytes,\n  Identification: {},\n  Flags: {},\n  Offset: {} bytes,\n  Time to Live: {} seconds,\n  Protocol: {},\n  Checksum: {},\n  Source Address: {},\n  Destination Address: {},\n  Options: {}",
            self.version, 
            self.ihl, 
            self.dscp, 
            self.ecn, 
            self.packet_length, 
            self.identification, 
            self.flags,
            self.offset * 8,
            self.ttl,
            self.get_protocol_name(),
            self.checksum,
            self.src_addr,
            self.dest_addr,
            options
        )
    }
}

impl fmt::Display for IPv4Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3]
        )
    }
}

mod tests {
    use super::*;

    /**
     * Verify converting packet to bytes and back does not change the packet
     */
    #[test]
    fn test_packet_bytes() {
        let mut header = IPv4Header {
            version: 4,
            ihl: 5,
            dscp: 1,
            ecn: 2,
            packet_length: 20 as u16,
            identification: 1 as u16,
            flags: 1,
            offset: 2,
            ttl: 60,
            protocol: 17,
            checksum: 0, // calculated later
            src_addr: IPv4Address { octets: [127, 0, 0, 1] },
            dest_addr: IPv4Address { octets: [255, 255, 255, 255] },
            options: None
        };

        header.checksum = header.calculate_checksum();
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let packet = IPv4Packet {
            header: header,
            payload: payload
        };

        println!("BEFORE\n{}", packet);

        let packet_bytes = packet.to_bytes().unwrap();
        let packet2 = IPv4Packet::from_bytes(&packet_bytes).unwrap();

        println!("AFTER\n{}", packet2);
    }
}