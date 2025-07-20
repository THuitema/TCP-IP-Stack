use pcap::{Active, Capture, Error};
use std::convert::TryInto;
use std::fmt;

pub struct EthernetFrame {
    pub header: EthernetHeader,
    pub payload: Vec<u8>,
}

pub struct EthernetHeader {
    pub dest_addr: [u8; 6], // destination MAC address (6 bytes)
    pub src_addr: [u8; 6],  // source MAC address (6 bytes)
    pub ethertype: u16,     // protocol used in the packet payload (e.g. IPv4) (2 bytes)
}

impl EthernetFrame {
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
            dest_addr: data[0..6].try_into().unwrap(),
            src_addr: data[6..12].try_into().unwrap(),
            ethertype: u16::from_be_bytes(ethertype_bytes),
        };

        let payload = data[14..].to_vec();

        return Ok(EthernetFrame {
            header: header,
            payload: payload,
        });
    }

    /**
     * Returns bytes of EthernetFrame
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
     * Sends frame to dest_addr (MAC address of destination)
     */
    pub fn send_frame(&self, capture: &mut Capture<Active>) -> Result<(), Error> {
         match self.to_bytes() {
            Ok(buffer) => capture.sendpacket(buffer),
            Err(e) => Err(e)
         }
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
    pub fn ethertype_to_protocol_name(&self) -> String {
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
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&self.dest_addr);
        buf.extend_from_slice(&self.src_addr);
        buf.extend_from_slice(&self.ethertype.to_be_bytes());

        Ok(buf)
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
        let dest_str = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.dest_addr[0],
            self.dest_addr[1],
            self.dest_addr[2],
            self.dest_addr[3],
            self.dest_addr[4],
            self.dest_addr[5]
        );

        let src_str = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.src_addr[0],
            self.src_addr[1],
            self.src_addr[2],
            self.src_addr[3],
            self.src_addr[4],
            self.src_addr[5]
        );

        write!(
            f,
            "  Ethertype: {},\n  Destination: {:?},\n  Source: {:?}",
            self.ethertype_to_protocol_name(),
            dest_str,
            src_str
        )
    }
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
                dest_addr: [108, 126, 103, 204, 17, 197],
                src_addr: [200, 167, 10, 144, 9, 72],
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
        assert_eq!(frame.header.dest_addr, frame2.header.dest_addr);
        assert_eq!(frame.header.src_addr, frame2.header.src_addr);
        assert_eq!(frame.header.ethertype, frame2.header.ethertype);
    }
}
