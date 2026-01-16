from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

packet_count = 0

def get_protocol(packet):
    """
    Identify protocol used in the packet
    """
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"

def analyze_packet(packet):
    """
    Analyze each captured packet and display useful information
    """
    global packet_count
    packet_count += 1

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = get_protocol(packet)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("=" * 60)
        print(f"Packet Number   : {packet_count}")
        print(f"Time Captured   : {timestamp}")
        print(f"Source IP       : {src_ip}")
        print(f"Destination IP  : {dst_ip}")
        print(f"Protocol        : {protocol}")
        print(f"Packet Length   : {len(packet)} bytes")
        print(f"Packet Summary  : {packet.summary()}")

def start_sniffer():
    """
    Start packet sniffing
    """
    print("Starting Advanced Network Sniffer")
    print("Press CTRL + C to stop sniffing\n")

    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    start_sniffer()
