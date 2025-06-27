from scapy.all import IP, TCP, sr1, send

def syn_scan(target_ip, ports):
    open_ports = []
    for port in ports:
        syn_packet = IP(dst=target_ip) / TCP(dport=port, flags='S')
        try:
            response = sr1(syn_packet, timeout=1, verbose=0)
            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                open_ports.append(port)
               
                rst_packet = IP(dst=target_ip) / TCP(dport=port, flags='R')
                send(rst_packet, verbose=0)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

if __name__ == "__main__":
    target = input("Enter target IP: ")
    ports_input = input("Enter ports to scan (comma-separated): ")
    
    try:
        ports = [int(p.strip()) for p in ports_input.split(",")]
    except ValueError:
        print(" Invalid input. Please enter numeric ports separated by commas.")
        exit()

    print(f"\n Scanning {target} on ports {ports}...\n")
    open_ports = syn_scan(target, ports)

    if open_ports:
        print(f" Open ports on {target}: {open_ports}")
    else:
        print(f" No open ports found on {target}")
