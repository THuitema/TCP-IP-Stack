pub struct IPPacket {
    header: IPHeader,
    payload: Vec<u8>
}

pub struct IPHeader {
    version: u8, // IP version (4 bits)
    header_length: u8, // length of header in 32-bit words (4 bits)
    tos: u8, // type of service (4 bits)
    packet_length: u16, // length of packet, including header (16 bits)
    identification: u16, // ID to reassemble packet, if fragmented (16 bits)
    flags: u8, // 3 bits
    offset: u16, // offset (number of bytes divided by 8) from where this data starts in reassembled packet (13 bits)
    ttl: u8, // time to live (8 bits)
    protocol: u8, // higher-level protocol used (8 bits)
    checksum: u16, // 16 bits
    src_addr: [u8; 4], // IP address of source (32 bits)
    dest_addr: [u8; 4], // IP address of destination (32 bits)
    // TODO: add struct to differentiate IPs between IPv4 and IPv6

    options: u32, // optional
    pad: u32, // optional
}