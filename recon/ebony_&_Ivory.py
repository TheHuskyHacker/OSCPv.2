#!/usr/bin/env python3

#install scrapy: pip3 install scapy
import argparse 
import sys 
import logging 

# Shut up Scapy's generic startup warnings 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import IP, TCP, UDP, ICMP, sr1 

# Dante's Arsenal Config 
DEFAULT_TCP_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 139, 143, 443, 445, 389, 636, 3306, 3389, 5985] 
DEFAULT_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 514] 

def ivory_tcp_scan(target, port): 
    """Ivory: TCP SYN 'Half-Open' Scan""" 
    # Craft a TCP SYN packet targeting our specific port 
    syn_packet = IP(dst=target) / TCP(dport=port, flags="S") 
    
    # Send packet and wait for a single response (1-second timeout to keep it fast) 
    response = sr1(syn_packet, timeout=1.0, verbose=False) 
    
    if response: 
        # Check if the target returned a TCP layer 
        if response.haslayer(TCP): 
            flags = response.getlayer(TCP).flags 
            if flags == 0x12: # 0x12 is the hex value for SYN-ACK (Open) 
                # Send a RST packet immediately to close the half-open connection cleanly 
                rst_packet = IP(dst=target) / TCP(dport=port, flags="R") 
                sr1(rst_packet, timeout=0.5, verbose=False) 
                return "OPEN" 
            elif flags == 0x14: # 0x14 is the hex value for RST-ACK (Closed) 
                return "CLOSED" 
    return "FILTERED/NO RESPONSE" 

def ebony_udp_scan(target, port): 
    """Ebony: UDP Port Unreachable Scan""" 
    # Craft a standard UDP packet targeting the port 
    udp_packet = IP(dst=target) / UDP(dport=port) 
    
    # Fire and listen for a response 
    response = sr1(udp_packet, timeout=2.0, verbose=False) 
    
    if response is None: 
        # Connectionless protocols don't acknowledge received data if open 
        return "OPEN | FILTERED (No response)" 
    elif response.haslayer(UDP): 
        # Target actually spoke back in UDP! Port is definitely open 
        return "OPEN" 
    elif response.haslayer(ICMP): 
        # Extract ICMP type and code numbers 
        icmp_type = response.getlayer(ICMP).type 
        icmp_code = response.getlayer(ICMP).code 
        if int(icmp_type) == 3 and int(icmp_code) == 3: 
            return "CLOSED (ICMP Port Unreachable)" 
    return "UNKNOWN" 

def main(): 
    # Devil May Cry Easter Egg Banner 
    print(""" 
    ================================================== 
        EBONY & IVORY: Dual-Protocol Scanner 
              "It's showtime!" - Dante 
    ================================================== 
    """) 
    
    parser = argparse.ArgumentParser(description="Ebony & Ivory: Custom TCP/UDP Scapy Enumerator") 
    parser.add_argument("-t", "--target", required=True, help="Target IP address (e.g., 192.168.1.50)") 
    parser.add_argument("--mode", choices=["ivory", "ebony", "both"], default="both", help="ivory=TCP Only, ebony=UDP Only, both=Full Combo") 
    args = parser.parse_args() 
    
    target = args.target 
    
    # Triggering Ivory 
    if args.mode in ["ivory", "both"]: 
        print(f"[Ivory] Firing TCP SYN shots at {target}...") 
        for port in DEFAULT_TCP_PORTS: 
            result = ivory_tcp_scan(target, port) 
            if result == "OPEN": 
                print(f"   [+] TCP Port {port:<5} OPEN") 
                
    # Triggering Ebony 
    if args.mode in ["ebony", "both"]: 
        print(f"\n[Ebony] Firing UDP probe shots at {target}...") 
        for port in DEFAULT_UDP_PORTS: 
            result = ebony_udp_scan(target, port) 
            if "OPEN" in result: 
                print(f"   [+] UDP Port {port:<5} {result}") 
                
    print("\n[*] Jackpot! Scan sequence completed successfully.") 

if __name__ == "__main__": 
    # Scapy needs raw socket generation privileges, so enforce root execution check 
    import os 
    if os.geteuid() != 0: 
        print("[-] Error: Ebony & Ivory require Smokin' Sexy Style privileges! Run with sudo.") 
        sys.exit(1) 
    main()
