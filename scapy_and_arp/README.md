## 🧩 Project README

### 1. 🔖 **Title & Summary**
- **Project Name**: Scapy-Based Network Monitoring & ARP Poison Detection
- **One-liner**: Two Python tools that detect ARP poisoning attacks and monitor HTTP/TLS traffic using Scapy, built with live sniffing and `.pcap` support.

---

### 2. 🚀 **Overview**
- **What it does**: 
  - `mysniffer.py`: Captures and displays live or recorded HTTP and TLS handshake packets, logging essential metadata like timestamps, hosts, request URIs, ports, and protocols — even on non-standard ports.
  - `arpwatch.py`: Continuously monitors the network for ARP replies and alerts if IP-to-MAC address bindings change, flagging potential ARP poisoning (MITM) attacks.
- **Target audience**: Students, security analysts, or hobbyists learning packet sniffing and network attack detection.
- **Problem/value**: Provides lightweight, scriptable alternatives to full-fledged tools like Wireshark for basic threat monitoring and debugging, using Python.

---

### 3. 💡 **Motivation**
- **Why**: Built as part of CSE508: Network Security (Spring 2024) coursework at Stony Brook University.
- **Type**: Academic, hands-on learning with real packet inspection.
- **Inspiration**: Real-world security use cases such as stealth HTTPS detection and MITM protection via ARP poisoning identification.

---

### 4. 🛠️ **Tech Stack**
- **Languages/Tools**:
  - **Python 3**
  - **Scapy** (for sniffing and protocol parsing)
  - **cryptography** (for TLS support)
  - **argparse**, `os`, `datetime`
- **Tested On**: Kali Linux 2023.4 VM
- **Support Tools**: `arpspoof` (used for generating simulated attacks)

---

### 5. ✨ **Key Features**
- 🔎 Detect HTTP GET/POST traffic with full host/URI logging  
- 🔐 Detect TLS Client Hello messages, extract TLS version + SNI hostname  
- 📄 Handles `.pcap` tracefiles or live network sniffing  
- ⚠️ Detects ARP spoofing in real-time by monitoring MAC-IP inconsistencies  
- 📋 Console output with timestamps and structured logs  
- 🧪 Multiple test scenarios with screenshots included for ARP attack detection

---

### 6. 🔍 **Architecture / Design**
- Modular script design with flags for choosing between tracefiles or interfaces
- Default interface detection if `-i` is not provided
- Packet filters use BPF expressions passed by users
- Separate monitoring logic for HTTP, TLS, and ARP
- ARP poisoning detection works by snapshotting the system's ARP table and comparing it in real-time against incoming ARP replies

---

### 7. 🧠 **Learnings & Challenges**
- Learned how to dynamically load Scapy layers like `http` and `tls`
- Faced issues with partial packet parsing — solved by focusing on single-packet analysis
- Understood ARP poisoning logic and simulated it with `arpspoof`
- Designed the tool to detect “hidden” HTTP/TLS traffic not on ports 80/443

---

### 8. 📈 **Outcomes / Impact**
- Successfully captured and parsed traffic to/from domains like `www.google.com` and `us.archive.ubuntu.com`
- Detected multiple ARP spoofing attacks:
  - One self-loop spoof causing a blackhole (DoS)
  - One MITM attempt spoofing another victim
- Generated multiple test scenarios and collected screenshots to validate detection logic

---

### 9. 🚧 **Improvements / Future Work**
- Enhance TLS detection by including more handshake metadata (cipher suites, etc.)
- Extend support for IPv6-based spoofing
- Add JSON or CSV export options for logs
- Package as a CLI tool or lightweight GUI utility

---

### 10. 🔗 **Links & References**
- GitHub Repo: _[Add once published]_
- [Scapy Docs](https://scapy.readthedocs.io/en/latest/)
- [Kali Linux VM](https://www.kali.org/get-kali/#kali-virtual-machines)
- Tools used: `arpspoof`, `tcpdump`, `wireshark` (for cross-validation)
