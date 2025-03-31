#!/usr/bin/env python3
import argparse
from scapy.all import sniff, ARP
import subprocess
import re

def get_arp_table():
    # This function retrieves the current ARP table of the host system
    try:
        arp_output = subprocess.check_output(['arp', '-n']).decode('utf-8')
        arp_lines = arp_output.split('\n')[1:]
        arp_table = {}
        for line in arp_lines:
            parts = re.split(r'\s+', line)
            # print(parts)
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[2]
                # print(mac)
                if mac != "<incomplete>":
                    arp_table[ip] = mac
        return arp_table
    except Exception as e:
        print(f"Error reading ARP table: {e}")
        return {}

def monitor_arp_packets(packet):
    # Callback function for Scapy to handle each sniffed ARP packet
    if ARP in packet and packet[ARP].op == 2:  # ARP reply
        source_ip = packet[ARP].psrc
        source_mac = packet[ARP].hwsrc
        if source_ip in initial_arp_table:
            if initial_arp_table[source_ip] != source_mac:
                print(f"WARNING: {source_ip} changed from {initial_arp_table[source_ip]} to {source_mac}")
        else:
            print(f"New device detected: {source_ip} with MAC {source_mac}")
            # initial_arp_table[source_ip]=source_mac


def main():
    parser = argparse.ArgumentParser(description="ARP poisoning attack detector.")
    parser.add_argument("-i", "--interface", help="Specify the network interface.", required=False)
    args = parser.parse_args()

    global initial_arp_table
    initial_arp_table = get_arp_table()
    print(initial_arp_table)
    print("Initial ARP table loaded. Monitoring for ARP poisoning...")
    sniff(iface=args.interface, prn=monitor_arp_packets, filter="arp", store=0)

if __name__ == "__main__":
    main()
