import scapy.all as scapy

def packet_callback(packet):
    print(f"Packet captured: {packet.summary()}")
    
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src  # Source IP address
        ip_dst = packet[scapy.IP].dst  # Destination IP address
        protocol = packet[scapy.IP].proto  # Protocol (TCP/UDP)
        
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        
        if packet.haslayer(scapy.TCP):
            print(f"TCP - Source Port: {packet[scapy.TCP].sport}, Destination Port: {packet[scapy.TCP].dport}")
        
        elif packet.haslayer(scapy.UDP):
            print(f"UDP - Source Port: {packet[scapy.UDP].sport}, Destination Port: {packet[scapy.UDP].dport}")
        
        if packet.haslayer(scapy.Raw):
            payload_data = packet[scapy.Raw].load
            print(f"Payload Data: {payload_data}")

print("Starting packet sniffing...")
scapy.sniff(prn=packet_callback, store=0)
