# TCP/IP Stack in Rust

Building a custom network from the ground-up as I teach myself computer networks!

Progress:
- [x] Ethernet
- [x] IPv4
- [x] ICMP
- [x] MILESTONE: write ping() to test reachability of the stack 
- [x] UDP datagram construction/deconstruction
- [x] UDP send()
- [x] UDP recv() and bind() using sockets
- [ ] TCP   

## Ping implementation:

https://github.com/user-attachments/assets/58539268-34f7-4e98-a9fc-8af3aca8d3f0

## UDP Client/Server Example
```rust
// client.rs
use tcpip_stack::ip::IPv4Address;
use tcpip_stack::addr_info::setup_addr_info;
use tcpip_stack::udp::send;

fn main() {
    let client_port = 2048;

    // Setup address info for en0 interface and port 2048
    let mut addr_info = match setup_addr_info(Some("en0"), client_port) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    let server_ip = IPv4Address::new(192, 168, 1, 75);
    let server_port = 10420;
    let msg = "Hello server!";
    let buffer = msg.as_bytes();

    // Send message to server
    if let Err(e) = send(server_ip, server_port, &mut addr_info, &buffer) {
        eprintln!("{}", e);
    }
}
```

```rust
// server.rs
use tcpip_stack::addr_info::setup_addr_info;
use tcpip_stack::udp::UDPSocket;

fn main() {
    let server_port = 10420;

    // Setup address info for en0 interface and port 10420
    let mut addr_info = match setup_addr_info(Some("en0"), 10420) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    // Spawns a thread to listen for UDP datagrams received on server_port
    let recv_sock = match bind(addr_info) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            return
        }
    };

    // Listening loop
    loop {
        match recv_sock.recv() {
            Ok(packet) => {
                println!("{}", packet); // timestamp, sender and receiver addresses

                let message = packet.data();
                println!("Message: {}", message);
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }
}
```




