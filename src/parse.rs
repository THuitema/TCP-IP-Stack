use pcap::{Error, Packet};
use crate::{ethernet::EthernetFrame, ip::IPv4Packet, icmp::ICMPPacket};
use std::fmt;
use std::time::{SystemTime};
use chrono::{DateTime, Local};

pub struct ParsedPacket {
    pub timestamp: SystemTime,
    pub ethernet: EthernetFrame,
    pub ipv4: IPv4Packet,
    pub transport: Transport,
}

pub enum Transport {
    ICMP(ICMPPacket)
}

impl fmt::Display for ParsedPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let datetime: DateTime<Local> = self.timestamp.into();
        let time_formatted = datetime.format("%H:%M").to_string();

        write!(
            f,
            "[{}] {} → {} | {} → {} | {}",
            time_formatted,
            self.ethernet.src_addr(),
            self.ethernet.dest_addr(),
            self.ipv4.src_addr(),
            self.ipv4.dest_addr(),
            self.ipv4.protocol_name()
        )
    }
}

pub fn parse(captured_frame: Packet) -> Result<ParsedPacket, Error> {
    let timestamp = SystemTime::now();

    let ethernet_frame = EthernetFrame::from_bytes(captured_frame.data)?;

    let ip_packet;
    let transport_packet;
    let network_protocol = ethernet_frame.ethertype_to_protocol_name();

    if network_protocol == "IPv4" {
        ip_packet = IPv4Packet::from_bytes(&ethernet_frame.payload())?;
    } 
    else {
        return Err(Error::PcapError(format!("(parse) network layer \"{}\" packets not yet supported", network_protocol)))
    }

    let transport_protocol = ip_packet.protocol_name();

    if transport_protocol == "ICMP" {
        transport_packet = Transport::ICMP(ICMPPacket::from_bytes(&ip_packet.payload())?);
    } else {
        return Err(Error::PcapError(format!("(parse) transport layer \"{}\" packets not supported", transport_protocol)))
    }

    Ok(ParsedPacket {
        timestamp: timestamp,
        ethernet: ethernet_frame,
        ipv4: ip_packet,
        transport: transport_packet
    })
}
