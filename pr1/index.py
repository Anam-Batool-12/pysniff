import socket


HOST = input("Enter the IP address to sniff: ")
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sock.bind((HOST, 0))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

print("[*] Sniffing packets... Press Ctrl+C to stop\n")

try:
    while True:
        data, addr = sock.recvfrom(65565)
        print(f"Packet from {addr}: {data[:20].hex()}")
except KeyboardInterrupt:
    print("\n[!] Stopping...")
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sock.close()
