# Test server to listen for UDP datagrams
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 9999))
print("Listening on UDP port 9999")
while True:
    data, addr = sock.recvfrom(2048)
    print(f"Received {data} from {addr}")
