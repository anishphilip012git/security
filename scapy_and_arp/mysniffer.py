#!/usr/bin/env python3
import argparse
from scapy.all import *
from scapy.all import sniff, IP, TCP, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName,ServerName
import datetime

def parse_tls_sni(tls_extensions):
    val="Unknown SNI"
    for ext in tls_extensions:
        if isinstance(ext, TLS_Ext_ServerName) :
            val=(ext.servernames[0].servername.decode("utf-8"))
            # print("parse_tls_sni",val)
    return val


def parse_packet(packet: Packet):
    timestamp = datetime.datetime.now()
    # print(packet)
    ip_layer = packet.getlayer(IP)    
    # Check for TLS traffic by looking for the presence of HTTP Request using standard library for checking layer
    if packet.haslayer(HTTPRequest):
        
        print(":-----------------HTTP")
        # print("====>",packet)
        http_pkt=packet.getlayer(HTTPRequest)
        
        
        method=http_pkt.Method.decode('utf-8', 'ignore')
        uri=http_pkt.Path.decode('utf-8', 'ignore')
        host=http_pkt.Host.decode('utf-8', 'ignore')
        # httpv=http_pkt.Http-Version
        
        if method=="":
            payload = packet[Raw].load.decode('utf-8', 'ignore') 
            if "GET " in payload or "POST " in payload:
                method = "GET" if "GET " in payload else "POST"
            uri = payload.split(" ")[1] if method == "GET" else "N/A"
        

        print(f"{timestamp} HTTP {ip_layer.src}:{packet.sport} -> {ip_layer.dst}:{packet.dport} {host} {method} {uri}")
        

    # Check for TLS traffic by looking for the presence of TLS Handshake and Client Hello
    elif packet.haslayer(TLSClientHello):
                print(":-++++++++++----TLS")
                tls_layer = packet.getlayer(TLSClientHello)
                
                # print(tls_layer.string_class_name,tls_layer.ext)
                sni = parse_tls_sni(tls_layer.ext)
                # print(sni)
                print(f"{timestamp} TLS {ip_layer.src}:{packet.sport} -> {ip_layer.dst}:{packet.dport} {sni}")

def main():
    parser = argparse.ArgumentParser(description="Sniff HTTP and TLS traffic.")
    parser.add_argument("-i", "--interface", help="Specify the network interface.", required=False)
    parser.add_argument("-r", "--tracefile", help="Read packets from a tracefile (tcpdump format).", required=False)
    parser.add_argument("expression", nargs="?", help="BPF filter for sniffing.", default="")
    args = parser.parse_args()
    print("Starting to Sniff HTTP and TLS traffic.")
    load_layer('tls')
    if args.tracefile:
        print("Trace File: ",args.tracefile)
        print("Filter expression: ",args.expression)
        sniff(offline=args.tracefile, prn=parse_packet, filter=args.expression, store=0)
    else:
        print("Filter expression: ",args.expression)
        sniff(iface=args.interface, prn=parse_packet, filter=args.expression, store=0)

if __name__ == "__main__":
    main()
