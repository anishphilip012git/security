import sys
from scapy.all import *
import socket as socket_lib
import ssl
import argparse

def syn_scan(target, port_range):
    open_ports = []
    for port in port_range:
        pkt = IP(dst=target)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x12:  # SYN/ACK flags
            send(IP(dst=target)/TCP(dport=port, flags='R'), verbose=0)
            open_ports.append(port)
    return open_ports

import socket as socket_lib

def tcp_probe(ip, port):
    print("TCP probe", ip, port)
    try:
        with socket_lib.socket(socket_lib.AF_INET, socket_lib.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((ip, port))
            # First attempt to receive any server-initiated data
            try:
                data = sock.recv(1024)
                if data:
                    decoded_data = data.decode('utf-8', 'replace').replace('\ufffd', '.')
                    print(f"Port {port}: is of CASE #1: TCP server-initiated - {decoded_data}")
                    return True
            except socket_lib.timeout:
                print(f"Port {port}: No data received on initial connect, trying probes...")
            
            # If no initial data received, try an HTTP GET request
            if not tcp_http_get_request(sock, ip, port):
                # If no response to HTTP GET, try sending generic lines
                tcp_generic_request(sock, ip, port)
            else:
                return True
    except Exception as e:
        print(f"Port {port}: Error in TCP probe - {str(e)}")

def tcp_http_get_request(sock, ip, port):
    print("Sending HTTP GET request...")
    sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
    try:
        data = sock.recv(1024)
        if data:
            decoded_data = data.decode('utf-8', 'replace').replace('\ufffd', '.')
            print(f"Port {port}: is of CASE #3: HTTP server with GET Request - {decoded_data}")
            return True
        else:
            print(f"Port {port}: Connected but no response to HTTP GET")
    except socket_lib.timeout:
        print(f"Port {port}: No response after HTTP GET, likely not an HTTP server")
    except socket_lib.error as e:
        print(f"Port {port}: Network error after HTTP GET - {e}")
    return False

def tcp_generic_request(sock, ip, port):
    print("Sending generic request...")
    generic_lines = "\r\n\r\n\r\n\r\n"
    sock.sendall(generic_lines.encode('ascii'))
    try:
        data = sock.recv(1024)
        if data:
            decoded_data = data.decode('utf-8', 'replace').replace('\ufffd', '.')
            print(f"Port {port}: is of CASE #5: Generic TCP server response - {decoded_data}")
            return True
        else:
            print(f"Port {port}: No data received after generic request.")
    except socket_lib.timeout:
        print(f"Port {port}: TCP read timed out after sending generic request - partial data may have been received")
    return False

def tls_probe(ip, port):
    print("TLS probe", ip, port)
    tls_set=False
    try:
        context = ssl.create_default_context()
        # context.options &= ~ssl.OP_NO_SSLv3 & ~ssl.OP_NO_TLSv1 & ~ssl.OP_NO_TLSv1_1 & ~ssl.OP_NO_TLSv1_2
        # context.set_ciphers('HIGH:!DH:!aNULL')
        with context.wrap_socket(socket_lib.socket(socket_lib.AF_INET, socket_lib.SOCK_STREAM), server_hostname=ip) as tls_sock:
            tls_sock.settimeout(10)
            tls_sock.connect((ip, port))
            print("TLS Connection established.")
            data = None
            tls_set=True
            cipher = tls_sock.cipher()
            protocol_version = tls_sock.version()
            # peer_cert = tls_sock.getpeercert()
            
            print(f"Cipher used: {cipher}")
            print(f"Protocol version: {protocol_version}")
            # print("Peer certificate:")
            try:
                data = tls_sock.recv(1024)  # Attempt to receive data
                if data:
                    decoded_data = data.decode('utf-8', 'replace').replace('\ufffd', '.')
                    print(f"Port {port}: is of CASE ##2:  TLS server-initiated - {decoded_data}")
                    return True
            except socket_lib.timeout:
                print(f"Port {port}: No data received on initial connect, trying HTTP GET probe...")

            # First, try sending an HTTP GET request
            if not tls_http_get_request(tls_sock, ip, port):
                # If no proper response to HTTP GET, try generic lines
                tls_generic_request(tls_sock, ip, port)
            else:
                return True
    except ssl.SSLError as e:

        # print(f"Port {port}: SSL error - {str(e)}")
        if tls_set:
            print(f"Port {port}: is of CASE ##6 and is a Generic TLS Server, for which we couldn't elicit repsonse")
            return True
        else:
            print(f"Port {port}: Not TLS")
    except Exception as e:
        print(f"Port {port}: Error in TLS probe - {str(e)}")

def tls_http_get_request(tls_sock, ip, port):
    print("Sending HTTP GET request...")
    tls_sock.sendall(b"GET / HTTP/1.1\r\nHost: " + ip.encode('utf-8') + b"\r\nConnection: close\r\n\r\n")
    
    received_data = b''
    try:
        while True:
            data = tls_sock.recv(1024)
            if not data:
                break
            received_data += data
    except socket.timeout:
        print(f"Port {port}: is of CASE ##4 : TLS read timed out after sending GET request - partial data may have been received")
        decoded_data = received_data.decode('utf-8', 'replace').replace('\ufffd', '.')
        print(f"Port {port}: HTTPS server response - {decoded_data}")
        if decoded_data=="":
            return False
        return True

    if received_data:
        decoded_data = received_data.decode('utf-8', 'replace').replace('\ufffd', '.')
        print(f"Port {port}: CASE ##4 : HTTPS server response - {decoded_data}")
        return True
    else:
        print(f"Port {port}: No data received after HTTP GET request.")
        return False

def tls_generic_request(tls_sock, ip, port):
    print("Sending generic request...")
    generic_lines = "\r\n\r\n\r\n\r\n"
    tls_sock.sendall(generic_lines.encode('ascii'))

    received_data = b''
    try:
        while True:
            data = tls_sock.recv(1024)
            if not data:
                break
            received_data += data
    except socket.timeout:
        print(f"Port {port}: TLS read timed out after sending generic request - partial data may have been received")
        decoded_data = received_data.decode('utf-8', 'replace').replace('\ufffd', '.')
        print(f"Port {port}: CASE ##6  Generic TLS server response - {decoded_data}")
        return False

    if received_data:
        decoded_data = received_data.decode('utf-8', 'replace').replace('\ufffd', '.')
        print(f"Port {port}: CASE ##6 Generic TLS server response - {decoded_data}")
        return True
    else:
        print(f"Port {port}: No data received after generic request.")
        return True

def probe_port(ip, port):
    print("Probing port", port, "on", ip ,"===================")
    find_something= tls_probe(ip, port)  # Perform the TCP probe
    if not find_something:
         # Perform the TLS probe
        ans=tcp_probe(ip, port)


def main(target, ports):
    open_ports = syn_scan(target, ports)
    print(f"Open ports: {open_ports}")
    for port in open_ports:
        probe_port(target, port)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simple SYN scanner and service detector')
    parser.add_argument('target', type=str, help='IP address to scan')
    parser.add_argument('-p', '--ports', type=str, default="21, 22, 23, 25, 80, 110, 143, 443, 587,853, 993, 3389, 8080", help='Port range to scan, e.g., 80,443 or 80-443')
    args = parser.parse_args()
    print(args)
    port_ranges = args.ports.split(',')
    ports = []
    for range_ in port_ranges:
        if '-' in range_:
            start, end = map(int, range_.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(range_))
    # print(ports)
    main(args.target, ports)
