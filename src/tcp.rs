use pcap::Error;

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
