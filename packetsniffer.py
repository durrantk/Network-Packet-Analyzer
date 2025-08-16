from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
from collections import defaultdict
import argparse

# Dictionary to count packets by protocol
packet_counts = defaultdict(int)

# Packet log
packet_log = []

def analyze_packet(packet):
    """
    Analyze each captured packet, log details, and perform analysis.
    """
    global packet_log

    # Basic info
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  # TCP
            packet_counts['TCP'] += 1
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"[TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        elif protocol == 17:  # UDP
            packet_counts['UDP'] += 1
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        elif protocol == 1:  # ICMP
            packet_counts['ICMP'] += 1
            print(f"[ICMP] {src_ip} -> {dst_ip}")
        else:
            packet_counts['Other'] += 1
            print(f"[Other Protocol] {src_ip} -> {dst_ip}")

        # Log packet details
        packet_log.append(packet)

        # Detect suspicious activity
        detect_suspicious_activity(packet)

def detect_suspicious_activity(packet):
    """
    Perform basic anomaly detection for suspicious activity.
    """
    if TCP in packet and packet[TCP].flags == "S":  # SYN flag
        print(f"[!] Potential SYN Scan Detected: {packet[IP].src} -> {packet[IP].dst}")
    if UDP in packet and len(packet[UDP].payload) > 500:  # Large UDP packet
        print(f"[!] Large UDP Packet: {packet[IP].src} -> {packet[IP].dst}")
    if IP in packet and packet[IP].len > 1500:  # Unusually large IP packet
        print(f"[!] Large IP Packet: {packet[IP].src} -> {packet[IP].dst}")

def save_to_pcap(file_name):
    """
    Save captured packets to a .pcap file.
    """
    if packet_log:
        wrpcap(file_name, packet_log)
        print(f"[+] Packets saved to {file_name}")
    else:
        print("[-] No packets captured to save.")

def print_statistics():
    """
    Print packet statistics.
    """
    print("\n[Packet Statistics]")
    for protocol, count in packet_counts.items():
        print(f" - {protocol}: {count}")
    print("\n[Capture Complete]")

def main():
    """
    Main function to handle packet sniffing with user-defined options.
    """
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer with Scapy")
    parser.add_argument("-i", "--interface", type=str, default="eth0", help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF filter string (e.g., 'tcp', 'udp')")
    parser.add_argument("-o", "--output", type=str, default="packets.pcap", help="Output file to save packets")

    args = parser.parse_args()

    try:
        print(f"[+] Starting packet sniffing on interface {args.interface}")
        print(f"    Filter: {args.filter if args.filter else 'None'}")
        sniff(iface=args.interface, filter=args.filter, count=args.count, prn=analyze_packet)
    except KeyboardInterrupt:
        print("\n[!] Sniffing interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        save_to_pcap(args.output)
        print_statistics()

if __name__ == "__main__":
    main()
