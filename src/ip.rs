use pcap::{Error};
use std::fmt;
use crate::{addr_info::AddrInfo, ethernet};

pub struct IPv4Packet {
    header: IPv4Header,
    payload: Vec<u8>,
}

struct IPv4Header {
    version: u8,              // IP version (4 bits)
    ihl: u8,                  // length of header in 32-bit words (4 bits)
    dscp: u8,                 // Differentiated Services Code Point (6 bits)
    ecn: u8,                  // Explicit Congestion Notification (2 bits)
    packet_length: u16,       // length of packet, including header (16 bits)
    identification: u16,      // ID to reassemble packet, if fragmented (16 bits)
    flags: u8,                // 3 bits
    offset: u16,              // offset (number of bytes divided by 8) from where this data starts in reassembled packet (13 bits)
    ttl: u8,                  // time to live (8 bits)
    protocol: IPProtocol,     // higher-level protocol used (8 bits)
    checksum: u16,            // 16 bits
    src_addr: IPv4Address,    // IP address of source (32 bits)
    dest_addr: IPv4Address,   // IP address of destination (32 bits)
    options: Option<Vec<u8>>  // optional
}

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct IPv4Address {
    octets: [u8; 4]
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone)]
pub enum IPProtocol {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    ENCAP = 41,
    OSPF = 89,
    SCTP = 132
}

impl IPv4Packet {
    /**
     * Returns a default IPv4 packet given the minimum required fields
     */
    pub fn new(src_addr: IPv4Address, dest_addr: IPv4Address, protocol: IPProtocol, payload: &[u8]) -> Self {
        let mut header = IPv4Header {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            packet_length: 20 + payload.len() as u16,
            identification: 0,
            flags: 0,
            offset: 0,
            ttl: 64,
            protocol,
            checksum: 0,
            src_addr,
            dest_addr,
            options: None
        };
        header.checksum = header.calculate_checksum();

        Self {
            header,
            payload: payload.to_vec()
        }
    }

    /**
     * Converts raw bytes to a IPv4Packet, if the bytes are valid
     */
    pub fn from_bytes(payload: Vec<u8>) -> Result<IPv4Packet, Error> {
        // Header is at least 20 bytes
        if payload.len() < 20 {
            return Err(Error::PcapError(format!("IPv4 packet has insufficient length ({} bytes)", payload.len())))
        }
        let version = payload[0] >> 4; // first 4 bits

        if version != 4 {
            return Err(Error::PcapError(String::from("Packet is not IPv4")));
        }

        let ihl = payload[0] & 0x0F; // last 4 bits
        let dscp = payload[1] >> 2;
        let ecn = payload[1] & 0x03;
        let packet_length = u16::from_be_bytes([payload[2], payload[3]]);
        let identification = u16::from_be_bytes([payload[4], payload[5]]);
        let flags = payload[6] >> 5;
        let offset = u16::from_be_bytes([payload[6] & 0x1F, payload[7]]); // bottom 5 bits of byte 6 plus byte 7
        let ttl = payload[8];
        let protocol = IPProtocol::from_u8(payload[9])?;
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
            version,
            ihl,
            dscp,
            ecn,
            packet_length,
            identification,
            flags,
            offset,
            ttl,
            protocol,
            checksum,
            src_addr: src_addr_ip,
            dest_addr: dest_addr_ip,
            options
        };

        let packet = IPv4Packet {
            header,
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
     * Assumes checksum has already been calculated with self.set_checksum()
     */
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf = self.header.to_bytes().unwrap();
        buf.extend(&self.payload);

        Ok(buf)
    }

    /**
     * Getter for Internet Header Length (IHL)
     * Length of header in 32-bit words
     * 4 bits
     */
    pub fn ihl(&self) -> u8 {
        self.header.ihl
    }

    /**
     * Getter for Differentiated Services Code Point (DSCP)
     * 6 bits
     */
    pub fn dscp(&self) -> u8 {
        self.header.dscp
    }

    /**
     * Setter for Differentiated Services Code Point (DSCP)
     * 6 bits
     */
    pub fn set_dscp(&mut self, dscp: u8) {
        self.header.dscp = dscp
    }

    /**
     * Getter for Explicit Congestion Notification (ECN)
     * 2 bits
     */
    pub fn ecn(&self) -> u8 {
        self.header.ecn
    }

    /**
     * Setter for Explicit Congestion Notification (ECN)
     * 2 bits
     */
    pub fn set_ecn(&mut self, ecn: u8) {
        self.header.ecn = ecn
    }

    /**
     * Getter for packet length
     * 16 bits
     */
    pub fn packet_length(&self) -> u16 {
        (self.header.ihl as u16) * 4 + (self.payload.len() as u16)
    }

    /**
     * Getter for identification
     * 16 bits
     */
    pub fn identification(&self) -> u16 {
        self.header.identification
    }

    /**
     * Setter for identification
     * 16 bits
     */
    pub fn set_identification(&mut self, id: u16) {
        self.header.identification = id
    }

    /**
     * Getter for flags
     * 3 bits
     */
    pub fn flags(&self) -> u8 {
        self.header.flags
    }

    /**
     * Setter for flags
     * 3 bits
     */
    pub fn set_flags(&mut self, flags: u8) {
        self.header.flags = flags
    }

    /**
     * Getter for offset (number of bytes divided by 8)
     * 13 bits
     */
    pub fn offset(&self) -> u16 {
        self.header.offset
    }

    /**
     * Getter for time to live (ttl)
     * 8 bits
     */
    pub fn ttl(&self) -> u8 {
        self.header.ttl
    }

    /**
     * Setter for time to live (ttl)
     */
    pub fn set_ttl(&mut self, ttl: u8) {
        self.header.ttl = ttl
    }

    /**
     * Getter for protocol
     */
    pub fn protocol(&self) -> &IPProtocol {
        &self.header.protocol
    }

    /**
     * Returns protocol name
     */
    pub fn protocol_name(&self) -> String {
        self.header.protocol.to_string()
    }

    /**
     * Setter for protocol
     */
    pub fn set_protocol(&mut self, protocol: IPProtocol) {
        self.header.protocol = protocol
    }

    /**
     * Returns checksum
     */
    pub fn checksum(&self) -> u16 {
        self.header.checksum
    }

    /**
     * Internally calculates, sets, and returns checksum
     */
    pub fn set_checksum(&mut self) -> u16 {
        self.header.checksum = self.header.calculate_checksum();
        self.header.checksum
    }

    /**
     * Getter for source address
     */
    pub fn src_addr(&self) -> &IPv4Address {
        &self.header.src_addr
    }

    /**
     * Setter for source address
     */
    pub fn set_src_addr(&mut self, addr: IPv4Address) {
        self.header.src_addr = addr
    }

    /**
     * Getter for destination address
     */
    pub fn dest_addr(&self) -> &IPv4Address {
        &self.header.dest_addr
    }

    /**
     * Setter for destination address
     */
    pub fn set_dest_addr(&mut self, addr: IPv4Address) {
        self.header.dest_addr = addr
    }

    /**
     * Getter for options
     */
    pub fn options(&self) -> Option<&[u8]> {
        if let Some(o) = &self.header.options {
            return Some(o)
        }
        None
    }

    /**
     * Getter for payload
     */
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /**
     * Setter for payload
     * Updates packet length field
     */
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        let old_payload_length = self.payload.len();
        self.header.packet_length += (payload.len() - old_payload_length) as u16;
        self.payload = payload;
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
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
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
        buf.push(self.protocol.to_u8());
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
    fn calculate_checksum(&self) -> u16 {
        let mut checksum: u32 = 0;

        let mut word = u16::from_be_bytes([(self.version & 0x0F) << 4 | (self.ihl & 0x0F), (self.dscp & 0x3F) << 2 | (self.ecn & 0x03)]);
        checksum = checksum.wrapping_add(word as u32);

        checksum = checksum.wrapping_add(self.packet_length as u32);

        checksum = checksum.wrapping_add(self.identification as u32);

        // flags and offset
        let offset_bytes = u16::to_be_bytes(self.offset);

        word = u16::from_be_bytes([(self.flags & 0x07) << 5 | (offset_bytes[0] & 0x1F), offset_bytes[1]]);
        checksum = checksum.wrapping_add(word as u32);

        word = u16::from_be_bytes([self.ttl, self.protocol.to_u8()]);
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
            for i in (0..options.len()).step_by(2) {
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

        !(checksum as u16)
    }
}

impl IPv4Address {
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self { octets: [a, b, c, d] }
    }

    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.octets)
    }

    pub fn octects(&self) -> [u8; 4] {
        self.octets
    }

    pub fn from_u32(ip: u32) -> Self {
        Self { octets: ip.to_be_bytes() }
    }

    pub fn from_slice(slice: [u8; 4]) -> Self {
        Self {octets: slice}
    }

    /**
     * Converts string formatted as "XXX.XXX.XXX.XXX" to IPv4Address
     */
    pub fn from_str(str: &str) -> Option<Self> {
        let str_toks: Vec<&str> = str.split(".").collect();
        if str_toks.len() != 4 {
            return None;
        }

        let octets_u8: Option<Vec<u8>> = str_toks
            .iter()
            .map(|s| s.parse::<u8>().ok())
            .collect();

        if let Some(octets) = octets_u8 {
            return Some(Self::from_slice(octets.try_into().unwrap()))
        }
        return None
    }
}

impl IPProtocol {
    pub fn from_u8(n: u8) -> Result<Self, Error> {
        match n {
            1 => Ok(IPProtocol::ICMP),
            2 => Ok(IPProtocol::IGMP),
            6 => Ok(IPProtocol::TCP),
            17 => Ok(IPProtocol::UDP),
            41 => Ok(IPProtocol::ENCAP),
            89 => Ok(IPProtocol::OSPF),
            132 => Ok(IPProtocol::SCTP),
            n => Err(Error::PcapError(format!("Unknown IPv4 protocol specified: {}", n))), 
        }
    }

    pub fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "ICMP" => Ok(IPProtocol::ICMP),
            "IGMP" => Ok(IPProtocol::IGMP),
            "TCP" => Ok(IPProtocol::TCP),
            "UDP" => Ok(IPProtocol::UDP),
            "ENCAP" => Ok(IPProtocol::ENCAP),
            "OSPF" => Ok(IPProtocol::OSPF),
            "SCTP" => Ok(IPProtocol::SCTP),
            s => Err(Error::PcapError(format!("Unknown IPv4 protocol specified: {}", s))), 
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            IPProtocol::ICMP => 1,
            IPProtocol::IGMP => 2,
            IPProtocol::TCP => 6,
            IPProtocol::UDP => 17,
            IPProtocol::ENCAP => 41,
            IPProtocol::OSPF => 89,
            IPProtocol::SCTP => 132,
        }
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
        let options = match &self.options {
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
            self.protocol,
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

impl fmt::Display for IPProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IPProtocol::ICMP => write!(f, "ICMP"),
            IPProtocol::IGMP => write!(f, "IGMP"),
            IPProtocol::TCP => write!(f, "TCP"),
            IPProtocol::UDP => write!(f, "UDP"),
            IPProtocol::ENCAP => write!(f, "ENCAP"),
            IPProtocol::OSPF => write!(f, "OSPF"),
            IPProtocol::SCTP => write!(f, "SCTP"),
        }
    }
}

/**
 * Constructs and sends IPv4 packet to destination IP address
 * dest_ipv4: IPv4Address, destination IP address
 * addr_info: &mut AddrInfo, contains your device's network info
 * protocol: IPProtocol, protocol of payload
 * buffer: &[u8], bytes to send in payload
 */
pub fn send(dest_ipv4: IPv4Address, addr_info: &mut AddrInfo, protocol: IPProtocol, buffer: &[u8]) -> Result<(), Error> {
    let ipv4 = IPv4Packet::new(addr_info.addr_ipv4, dest_ipv4, protocol, buffer);
    let ipv4_bytes = ipv4.to_bytes()?;
    ethernet::send(addr_info.router_mac, addr_info, &ipv4_bytes)
}

#[cfg(test)]
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
            protocol: IPProtocol::from_u8(17).unwrap(),
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
        let packet2 = IPv4Packet::from_bytes(packet_bytes).unwrap();

        println!("AFTER\n{}", packet2);
    }
}