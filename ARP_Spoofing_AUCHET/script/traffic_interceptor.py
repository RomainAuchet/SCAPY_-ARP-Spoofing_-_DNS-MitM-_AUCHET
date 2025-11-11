import argparse
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
from collections import Counter
import re

def parse_http_host(raw_payload):
    try:
        payload_str = raw_payload.decode('utf-8', errors='ignore')
        match = re.search(r"Host: (.*?)\r\n", payload_str)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None

def analyze_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] Error: File not found: {pcap_file}")
        return
    except Exception as e:
        print(f"[!] Error reading PCAP file: {e}")
        return
    
    dns_queries = set()
    http_hosts = set()
    protocol_counts = Counter()
    top_talkers = Counter()
    print(f"[*] Analyzing {len(packets)} packets from {pcap_file}...")

    for packet in packets:
        if packet.haslayer(TCP):
            protocol_counts['TCP'] += 1
        elif packet.haslayer(UDP):
            protocol_counts['UDP'] += 1
        if packet.haslayer(IP):
            top_talkers[packet[IP].src] += 1
        if packet.haslayer(DNSQR): 
            if packet[DNS].qr == 0:
                try:
                    qname = packet[DNSQR].qname.decode('utf-8')
                    dns_queries.add(qname)
                except Exception:
                    pass
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            if packet[TCP].dport == 80: 
                host = parse_http_host(packet[Raw].load)
                if host:
                    http_hosts.add(host)

    print("\n......Analysis Results......")

    print("\n[+] Top Talkers (Source IP):")
    for ip, count in top_talkers.most_common(10):
        print(f"    {ip}: {count} packets")

    print("\n[+] Protocol Counts (Simple):")
    for proto, count in protocol_counts.items():
        print(f"    {proto}: {count} packets")

    print("\n[+] DNS Queries Intercepted:")
    if dns_queries:
        for query in sorted(list(dns_queries)):
            print(f"    {query}")
    else:
        print("    No DNS queries found.")

    print("\n[+] HTTP Hosts Visited (via Host Header):")
    if http_hosts:
        for host in sorted(list(http_hosts)):
            print(f"    {host}")
    else:
        print("    No HTTP hosts found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP Traffic Analyzer")
    parser.add_argument("pcap_file", help="The .pcap file to analyze.")
    args = parser.parse_args()
    
    analyze_pcap(args.pcap_file)
