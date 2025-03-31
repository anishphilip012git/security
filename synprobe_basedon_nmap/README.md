## 🧩 Project README

### 1. 🔖 **Title & Summary**
- **Project Name**: SynProbe – TCP SYN Scanner & Service Fingerprinter
- **One-liner**: A custom `nmap`-like tool that performs SYN scans and classifies services based on TCP and TLS behavior — all written in Python.

---

### 2. 🚀 **Overview**
- **What it does**: SynProbe actively scans TCP ports on a target host using SYN scans, and classifies the services running on open ports by analyzing both TCP and TLS-level responses using custom probes.
- **Target audience**: Security students, pentesters, network engineers.
- **Problem/value**: Offers a simplified but powerful way to fingerprint services without relying on port assumptions, revealing hidden or non-standard service deployments.

---

### 3. 💡 **Motivation**
- **Why**: Built as part of CSE508: Network Security coursework at Stony Brook University.
- **Type**: Learning-based implementation of real-world reconnaissance.
- **Inspiration**: Tools like `nmap -sS` and `nmap -sV`, but implemented from scratch with Python and Scapy.

---

### 4. 🛠️ **Tech Stack**
- **Languages**: Python 3
- **Libraries**: `scapy`, `socket`, `ssl`, `argparse`
- **Platform**: Kali Linux 2023.4 VM (tested)
- **Run as root**: Yes (for raw socket/SYN scan)

---

### 5. ✨ **Key Features**
- TCP SYN Scan to detect open ports
- TLS handshake check to detect secure servers
- Differentiates between:
  1. TCP Server-Initiated responses
  2. TLS Server-Initiated responses
  3. HTTP Server (via GET over TCP)
  4. HTTPS Server (via GET over TLS)
  5. Generic TCP server (probed using `\r\n`)
  6. Generic TLS server (probed using `\r\n`)
- Handles both standard and non-standard port-service mappings
- Displays up to 1024 bytes of received banner data
- Replaces non-printable bytes with `.` to avoid clutter

---

### 6. 🔍 **Architecture / Design**
- **SYN Scan**: Performed using raw socket to detect open ports
- **Service Classification**:
  - TLS-based probing is prioritized before TCP (as TLS implies TCP)
  - If server doesn't initiate communication, probe with GET and newline payloads
  - TLS connections verified using Python’s `ssl` library
- **Fallback Logic**: Tries each case (TLS first, TCP second) sequentially until response is detected

---

### 7. 🧠 **Learnings & Challenges**
- Understood TLS handshaking and TCP probing without relying on port-based assumptions
- Managed TLS socket negotiation and exception handling for closed/reset ports
- Built clean output formatting for mixed-protocol server response data
- Avoided scanning public services aggressively, focusing on VM-based testing

---

### 8. 📈 **Outcomes / Impact**
- Validated service detection on:
  - `ftp.dlptest.com:21` ➝ TCP server-initiated
  - `smtp.gmail.com:465` ➝ TLS server-initiated
  - `www.cs.stonybrook.edu:80` ➝ HTTP GET-based
  - `8.8.8.8:853` ➝ Generic TLS (couldn’t elicit response)
- Successfully fingerprinted services running on multiple open ports with detailed logs

---

### 9. 🚧 **Improvements / Future Work**
- Add support for subnet scanning
- Implement concurrency/multithreading for faster scanning
- Include HEX+ASCII dump (like `hexdump -C`)
- Export results to JSON/CSV
- Add UI or CLI verbosity levels

---

### 10. 🔗 **Links & References**
- GitHub Repo: _[Add here when ready]_
- Docs: [`nmap`](https://nmap.org/), [`scapy`](https://scapy.readthedocs.io/en/latest/), [`socket`](https://docs.python.org/3/library/socket.html)
- Tools: `netcat`, `openssl s_client` (used for validation)

