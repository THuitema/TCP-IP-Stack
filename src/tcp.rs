use pcap::Error;
use crate::{ip::IPv4Address};

pub struct TCPSegment {
    header: TCPHeader,
    data: Vec<u8>
}

struct TCPHeader {
    src_port: u16,
    dest_port: u16,
    sequence_num: u32,
    acknowledgement: u32,
    header_len: u8,
    flags: u8,
    advertised_win: u16,
    checksum: u16,
    urgent_ptr: u16,
    options: Option<Vec<u8>>
}

impl TCPSegment {
    /**
     * Returns a new TCPSegment
     * Calculates and sets the checksum field
     */
    pub fn new(src_port: u16, dest_port: u16, sequence_num: u32, acknowledgement: u32, flags: u8, advertised_win: u16, urgent_ptr: u16, src_addr: IPv4Address, dest_addr: IPv4Address, data: &[u8]) -> Self {
        let header = TCPHeader {
            src_port,
            dest_port,
            sequence_num,
            acknowledgement,
            header_len: 5,
            flags,
            advertised_win,
            checksum: 0,
            urgent_ptr,
            options: None
        };

        let mut segment = Self {
            header,
            data: data.to_vec()
        };

        segment.set_checksum(src_addr, dest_addr);
        segment
    }

    /**
     * Converts raw bytes to a UDPPacket, if the bytes are valid
     * User is responsible for verifying checksum with self.verify_checksum()
     */
    pub fn from_bytes(data: &[u8], src_addr: IPv4Address, dest_addr: IPv4Address) -> Result<Self, Error> {
        if data.len() < 20 {
            return Err(Error::PcapError(format!("UDP packet has insufficient length ({} bytes)", data.len())));
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dest_port = u16::from_be_bytes([data[2], data[3]]);
        let sequence_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let acknowledgement = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let header_len = data[12] >> 4; // top 4 bits is header_len, bottom 4 are 0's
        let flags = data[13] & 0x3F; // bottom 6 bits 
        let advertised_win = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

        let options_len = header_len * 4 - 20;
        let options: Option<Vec<u8>>;

        if options_len > 0 {
            options = Some(data[20..(header_len * 4) as usize].to_vec());
        } else {
            options = None;
        }

        let tcp_data: Vec<u8> = data[((header_len * 4) as usize)..].to_vec();

        let header = TCPHeader {
            src_port,
            dest_port,
            sequence_num,
            acknowledgement,
            header_len,
            flags,
            advertised_win,
            checksum,
            urgent_ptr,
            options
        };

        let segment = Self {
            header,
            data: tcp_data
        };

        if !segment.verify_checksum(src_addr, dest_addr) {
            return Err(Error::PcapError("TCPSegment checksum mismatch".to_string()))
        }

        Ok(segment)
    }

    /**
     * Calculates checksum of the TCPSegment and sets its checksum field
     */
    pub fn set_checksum(&mut self, src_addr: IPv4Address, dest_addr: IPv4Address) {
        self.header.checksum = self.calculate_checksum(src_addr, dest_addr)
    }

    /**
     * Calculates checksum of the TCPSegment and returns true if it matches the checksum field
     */
    fn verify_checksum(&self, src_addr: IPv4Address, dest_addr: IPv4Address) -> bool {
        self.calculate_checksum(src_addr, dest_addr) == self.header.checksum 
    }

    /**
     * Calculates the checksum of the TCPSegment
     */
    fn calculate_checksum(&self, src_addr: IPv4Address, dest_addr: IPv4Address) -> u16 {
        0 // TODO
    }
}