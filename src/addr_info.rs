use crate::{ethernet::MACAddress, ip::IPv4Address};
use core::net::{IpAddr};
use pcap::{Active, Capture, Device, Error};
use pnet::datalink;

/**
 * Designed to store information pertaining to the host device for sending packets
 * Storing router MAC address until we implement ARP
 */
pub struct AddrInfo {
    pub addr_mac: MACAddress,
    pub addr_ipv4: IPv4Address,
    pub port: u16,
    pub capture: Capture<pcap::Active>,
    pub interface: String,
    pub router_mac: MACAddress
}

/**
 * Returns AddrInfo with device information
 * Must provide router MAC address until we implement ARP
 */
pub fn setup_addr_info(device_name: Option<&str>, port: u16, router_mac: MACAddress) -> Result<AddrInfo, Error> {
    let addr_mac = get_mac_addr(device_name).unwrap();
    
    // Look for a specific device name and try to get IPv4 Address for it
    if let Some(name) = device_name {
        let devices = Device::list().unwrap();

        for device in &devices {
            if device.name == name {
                let cap = Capture::from_device(name)
                    .unwrap()
                    .immediate_mode(true)
                    .open()
                    .unwrap();
                
                for addr in &device.addresses {
                    if let IpAddr::V4(ip) = addr.addr {
                        let addr_ip = IPv4Address::from_slice(ip.octets());

                        return Ok(AddrInfo { addr_mac, addr_ipv4: addr_ip, port, capture: cap, interface: name.to_string(), router_mac })
                    }
                }
                return Err(Error::PcapError("Device found, but no IPv4 address".to_string()));
            }
        }
        Err(Error::PcapError("Device not found".to_string()))
    } else {
        let device = Device::lookup().unwrap().unwrap();
        let cap = Capture::from_device(device.name.as_str())
            .unwrap()
            .immediate_mode(true)
            .open()
            .unwrap();

        // Find IPv4 address of device
        for addr in &device.addresses {
            if let IpAddr::V4(ip) = addr.addr {
                let addr_ip = IPv4Address::from_slice(ip.octets());

                return Ok(AddrInfo { addr_mac, addr_ipv4: addr_ip, port, capture: cap, interface: device.name.to_string(), router_mac })
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