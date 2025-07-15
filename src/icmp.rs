pub struct ICMPPacket {
    header: ICMPHeader,
    payload: [u8; 576]
}

pub struct ICMPHeader {
    icmp_type: u8,
    code: u8,
    checksum: u16,
    content: u32
}