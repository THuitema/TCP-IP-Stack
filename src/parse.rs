use pcap::{Error, Packet};
use crate::{ethernet::EthernetFrame, icmp::ICMPPacket, ip::IPv4Packet, udp::UDPDatagram};
use std::fmt;
use chrono::{DateTime, Local};

pub struct ParsedPacket {
    pub timestamp: DateTime<Local>,
    pub ethernet: EthernetFrame,
    pub ipv4: IPv4Packet,
    pub transport: Transport,
}

#[allow(clippy::upper_case_acronyms)]
pub enum Transport {
    ICMP(ICMPPacket),
    UDP(UDPDatagram),
    TCP
}

impl ParsedPacket {
    pub fn from_ethernet(captured_frame: Packet) -> Result<ParsedPacket, Error> {
        let timestamp = Local::now();

        let ethernet_frame = EthernetFrame::from_bytes(captured_frame.data)?;
        let ip_packet;
        let network_protocol = ethernet_frame.ethertype_to_protocol_name();

        if network_protocol == "IPv4" {
            ip_packet = IPv4Packet::from_bytes(ethernet_frame.payload().to_vec())?;
        } 
        else {
            return Err(Error::PcapError(format!("(parse) network layer \"{}\" packets not yet supported", network_protocol)))
        }

        let transport_protocol = ip_packet.protocol_name();

        let transport_packet = match transport_protocol.as_str() {
            "ICMP" => Transport::ICMP(ICMPPacket::from_bytes(ip_packet.payload())?),
            "UDP" => Transport::UDP(UDPDatagram::from_bytes(ip_packet.payload(), ip_packet.src_addr(), ip_packet.dest_addr())?),
            s => return Err(Error::PcapError(format!("(parse) transport layer \"{}\" packets not supported", s)))
        };

        Ok(ParsedPacket {
            timestamp,
            ethernet: ethernet_frame,
            ipv4: ip_packet,
            transport: transport_packet
        })
    }

    /**
     * Returns data of the transport-layer packet
     */
    pub fn data(&self) -> &[u8] {
        match &self.transport {
            Transport::ICMP(icmp_packet) => icmp_packet.payload(),
            Transport::UDP(datagram) => datagram.data(),
            Transport::TCP => &[]
        }
    }
}

impl fmt::Display for ParsedPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let datetime: DateTime<Local> = self.timestamp;
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

