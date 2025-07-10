use pcap::Error;
use std::fmt;

pub struct IPv4Packet {
    header: IPv4Header,
    payload: Vec<u8>,
}

pub struct IPv4Header {
    version: u8,          // IP version (4 bits)
    header_length: u8,    // length of header in 32-bit words (4 bits)
    dscp: u8,             // Differentiated Services Code Point (6 bits)
    ecn: u8,              // Explicit Congestion Notification (2 bits)
    packet_length: u16,   // length of packet, including header (16 bits)
    identification: u16,  // ID to reassemble packet, if fragmented (16 bits)
    flags: u8,            // 3 bits
    offset: u16,          // offset (number of bytes divided by 8) from where this data starts in reassembled packet (13 bits)
    ttl: u8,              // time to live (8 bits)
    protocol: u8,         // higher-level protocol used (8 bits)
    checksum: u16,        // 16 bits
    src_addr: IPv4Address,    // IP address of source (32 bits)
    dest_addr: IPv4Address,   // IP address of destination (32 bits)
    options: Option<u32>, // optional (padding added if necessary to make it 32 bits)
}



impl IPv4Packet {
    pub fn from_bytes(payload: &Vec<u8>) -> Result<IPv4Packet, Error> {
        let version = payload[0] >> 4; // first 4 bits

        if version != 4 {
            return Err(Error::PcapError(String::from("Packet is not IPv4")));
        }

        let header_len = payload[0] & 0x0F; // last 4 bits
        let dcsp = payload[1] >> 2;
        let ecn = payload[1] & 0x03;
        let packet_length = u16::from_be_bytes([payload[2], payload[3]]);
        let identification = u16::from_be_bytes([payload[4], payload[5]]);
        let flags = payload[6] >> 5;
        let offset = u16::from_be_bytes([payload[6] & 0x07, payload[7]]); // last 3 bits of byte 6 plus byte 7
        let ttl = payload[8];
        let protocol = payload[9];
        let checksum = u16::from_be_bytes([payload[10], payload[11]]);

        let src_addr_u32 = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let dest_addr_u32 = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let src_addr_ip = IPv4Address::from_u32(src_addr_u32);
        let dest_addr_ip = IPv4Address::from_u32(dest_addr_u32);
        

        // Check if there are options and padding
        let options: Option<u32>;
        let ip_payload: Vec<u8>;

        if header_len > 5 {
            options = Some(u32::from_be_bytes([
                payload[20],
                payload[21],
                payload[22],
                payload[23],
            ]));
            ip_payload = payload[24..].to_vec();
        } else {
            options = None;
            ip_payload = payload[20..].to_vec();
        }

        let header = IPv4Header {
            version: version,
            header_length: header_len,
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

        Ok(IPv4Packet {
            header: header,
            payload: ip_payload,
        })
    }

    // TODO*
    pub fn verify_checksum(&self) -> bool {
        true
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

        // translate common protocol names
        let protocol = match self.protocol {
            1 => "ICMP".to_string(),
            2 => "IGMP".to_string(),
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            41 => "ENCAP".to_string(),
            89 => "OSPF".to_string(),
            132 => "SCTP".to_string(),
            n => format!("Other ({})", n),
        };

        let options = match self.options {
            Some(o) => o.to_string(),
            None => "None".to_string()
        };

        write!(
            f,
            "  Version: {},\n  Header Length (in 32-bit words): {} words,\n  Differentiated Services Code Point (DSCP): {},\n  Explicit Congestion Notification (ECN): {},\n  Packet Length: {} bytes,\n  Identification: {},\n  Flags: {},\n  Offset: {},\n  Time to Live: {} seconds,\n  Protocol: {},\n  Checksum: {},\n  Source Address: {},\n  Destination Address: {},\n  Options: {}",
            self.version, 
            self.header_length, 
            self.dscp, 
            self.ecn, 
            self.packet_length, 
            self.identification, 
            self.flags,
            self.offset,
            self.ttl,
            protocol,
            self.checksum,
            self.src_addr,
            self.dest_addr,
            options
        )
    }
}


pub struct IPv4Address {
    octets: [u8; 4]
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