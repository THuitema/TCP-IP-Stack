use crate::{ethernet::{MACAddress}, ip::IPv4Address};
use core::net::{IpAddr};
use core::str;
use pcap::{Active, Capture, Device, Error};
use pnet::datalink;
use std::process::Command;
use std::{collections::HashMap};

/**
 * Designed to store information pertaining to the host device for sending packets
 * Storing router MAC address until we implement ARP
 */
pub struct AddrInfo {
    pub addr_mac: MACAddress,
    pub addr_ipv4: IPv4Address,
    pub port: u16,
    pub capture: Capture<pcap::Active>,
    pub capture_loopback: Capture<pcap::Active>,
    pub interface: String,
    pub arp_entries: ARPEntries,
    pub router_mac: MACAddress
}

pub struct ARPEntries {
    pub entries: HashMap<IPv4Address, MACAddress>
}

impl ARPEntries {
    /**
     * Parses the response of "arp -a" to fetch hosts' IP and MAC addresses in local network
     */
    pub fn new() -> Result<Self, Error> {
        let output = Command::new("arp")
            .arg("-a")
            .output()
            .expect("Failed to run ARP");
        
        if !output.status.success() {
            return Err(Error::PcapError(String::from_utf8(output.stderr).unwrap()));
        }

        let stdout = str::from_utf8(&output.stdout).unwrap();
        let lines: Vec<&str> = stdout.lines().collect();

        // parse IPv4Address and MAC address from each line
        let mut entries: HashMap<IPv4Address, MACAddress> = HashMap::new();

        if lines.len() == 0 {
            return Err(Error::PcapError("ARP had no results".to_string()));
        }

        for line in lines {
            let line_toks: Vec<&str> = line.split_whitespace().collect();
            if line_toks.len() >= 4 {
                let ip_str = &line_toks[1][1..line_toks[1].len() - 1]; // removes parentheses
                let mac_str = line_toks[3];
                
                if let (Some(ipv4), Some(mac)) = (IPv4Address::from_str(ip_str), MACAddress::from_hex_str(mac_str)) {
                    entries.insert(ipv4, mac);
                }
            }
        }

        Ok(Self { entries })
    }
}

/**
 * Returns AddrInfo with device information
 * Must provide router MAC address until we implement ARP
 */
pub fn setup_addr_info(device_name: Option<&str>, port: u16) -> Result<AddrInfo, Error> {
    let addr_mac = get_mac_addr(device_name).unwrap();
    let arp_entries = ARPEntries::new()?;

    // Get router MAC Address
    let mut router_mac: Option<MACAddress> = None;

    for (ipv4, mac) in &arp_entries.entries {
        if ipv4.octects()[3] == 1 {
            router_mac = Some(mac.clone());
        }
    }

    if router_mac.is_none() {
        return Err(Error::PcapError("Router MAC Address not found".to_string()))
    }

    let devices = Device::list().unwrap();

    // Get loopback device for localhost sending/receiving
    let mut device_loopback = None;
    
    for device in &devices {
        if device.flags.is_loopback() {
            device_loopback = Some(device);
        }
    }

    if device_loopback.is_none() {
        return Err(Error::PcapError("No loopback interface found".to_string()))
    }

    let capture_loopback = Capture::from_device(device_loopback.unwrap().name.as_str())
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();
    
    // Look for a specific device name and try to get IPv4 Address for it
    if let Some(name) = device_name {
        for device in &devices {
            if device.name == name {
                let capture = Capture::from_device(name)
                    .unwrap()
                    .immediate_mode(true)
                    .open()
                    .unwrap();
                
                for addr in &device.addresses {
                    if let IpAddr::V4(ip) = addr.addr {
                        let addr_ip = IPv4Address::from_slice(ip.octets());

                        return Ok(AddrInfo { addr_mac, addr_ipv4: addr_ip, port, capture, capture_loopback, interface: name.to_string(), arp_entries, router_mac: router_mac.unwrap() })
                    }
                }
                return Err(Error::PcapError("Device found, but no IPv4 address".to_string()));
            }
        }
        Err(Error::PcapError("Device not found".to_string()))
    } else {
        let device = Device::lookup().unwrap().unwrap();
        let capture = Capture::from_device(device.name.as_str())
            .unwrap()
            .immediate_mode(true)
            .open()
            .unwrap();

        // Find IPv4 address of device
        for addr in &device.addresses {
            if let IpAddr::V4(ip) = addr.addr {
                let addr_ip = IPv4Address::from_slice(ip.octets());

                return Ok(AddrInfo { addr_mac, addr_ipv4: addr_ip, port, capture, capture_loopback, interface: device.name.to_string(), arp_entries, router_mac: router_mac.unwrap() })
            }
        }
        Err(Error::PcapError("Device found, but no IPv4 address".to_string()))
    }
}

pub fn setup_capture(device_name: &str) -> Capture<Active> {
    Capture::from_device(device_name)
        .unwrap()
        .immediate_mode(true) 
        .open()
        .unwrap()
}

fn get_mac_addr(device_name: Option<&str>) -> Result<MACAddress, Error> {
    for iface in datalink::interfaces() {
        if let Some(name) = device_name {
            if iface.name == name {
                match iface.mac {
                    Some(mac) => return Ok(MACAddress::from_slice(mac.octets())),
                    None => return Err(Error::PcapError("MAC address not found for interface".to_string()))
                }
            }
        } else if let Some(mac) = iface.mac {
            return Ok(MACAddress::from_slice(mac.octets()))
        }
    }
    Err(Error::PcapError("No interfaces found when trying to determine MAC address".to_string()))
}