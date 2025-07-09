use std::convert::TryInto;
use std::fmt;

pub struct EthernetFrame {
    header: EthernetHeader,
    payload: Vec<u8>
}

pub struct EthernetHeader {
    dest_addr: [u8; 6], // 6 bytes -- destination MAC address
    src_addr: [u8; 6], // 6 bytes -- source MAC address
    ethertype: u16 // 2 bytes -- specifies the protocol used in the packet payload (e.g. IPv4)
}

impl EthernetFrame {
    /**
     * Converts raw bytes to an EthernetFrame, if the bytes are valid
     */
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }

        let mut ethertype_bytes = [0u8; 2];
        ethertype_bytes.copy_from_slice(&data[12..14]);

        let header = EthernetHeader { 
            dest_addr: data[0..6].try_into().unwrap(), 
            src_addr: data[6..12].try_into().unwrap(),
            ethertype: u16::from_be_bytes(ethertype_bytes) 
        };

        let payload = data[14..].to_vec();

        return Some(EthernetFrame { 
            header: header, 
            payload: payload })
    }
}

impl fmt::Display for EthernetFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}", 
            self.header
        )
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