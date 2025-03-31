## 🧩 Project README

### 1. 🔖 **Title & Summary**
- **Project Name**: Passive Network Monitoring with `tcpdump`
- **One-liner**: A hands-on exploration of network traffic analysis using `tcpdump` and shell tools to extract meaningful insights from `.pcap` trace files.

---

### 2. 🚀 **Overview**
- **What it does**: This project demonstrates how to analyze a `.pcap` trace file using `tcpdump` and standard Unix command-line utilities. It involves filtering, sorting, and aggregating network traffic data.
- **Target audience**: Network security learners, system admins, or anyone new to packet analysis.
- **Problem/value**: Understanding how to passively inspect network traffic is essential for identifying malicious patterns, diagnosing issues, and securing infrastructure. This project serves as a practical primer.

---

### 3. 💡 **Motivation**
- **Why**: Built as part of CSE508 (Network Security) coursework at Stony Brook University.
- **Type**: Academic assignment.
- **Inspiration**: Introduce students to foundational network forensics with real packet data.

---

### 4. 🛠️ **Tech Stack**
- **Languages/Tools**:
  - **CLI Tools**: `tcpdump`, `grep`, `awk`, `cut`, `uniq`, `sort`, `wc`, `sed`, `head`, `tail`
  - **Environment**: Unix/Linux shell (Bash)

---

### 5. ✨ **Key Features**
- Extracted packet statistics (counts by protocol, port, IPs)
- Identified HTTP GET requests and file types (e.g., `.jpg`)
- Traced ARP/DHCP activity
- Detected SYN flags and TCP connection attempts
- Summarized MAC vendor analysis using OUI mapping
- Distribution of Ethernet packet sizes

---

### 6. 🔍 **Architecture / Design**
- Command-line one-liners were chained to filter and process `.pcap` files without needing external software.
- Prioritized performance and clarity through piped commands and filters.
- `tcpdump` was used with `-n` and `-r` flags to avoid name resolution and read from file.

---

### 7. 🧠 **Learnings & Challenges**
- Gained proficiency in `tcpdump` filters and advanced shell scripting.
- Learned how to interpret packet-level details and correlate with network behavior.
- Faced challenges in extracting precise data from verbose output, overcame using smart piping and text parsing.

---

### 8. 📈 **Outcomes / Impact**
- Used as part of coursework.
- Strengthened ability to interpret and analyze raw packet captures without relying on GUIs.
- Helped build intuition for identifying common network protocols and anomalies.

---

### 9. 🚧 **Improvements / Future Work**
- Automate analysis with a Python script wrapping `tcpdump` calls.
- Visualize data using charts (e.g., packet sizes, protocol distribution).
- Include MAC vendor lookups via `manuf` file or Wireshark-style parsing.

---

### 10. 🔗 **Links & References**
- GitHub repo: [repo](https://github.com/anishphilip012git/security/tree/main/tcpdump)
- Course: CSE508 - Network Security @ Stony Brook University
- Tools: [`tcpdump`](https://www.tcpdump.org/), [`awk`](https://www.gnu.org/software/gawk/manual/gawk.html), [Wireshark’s OUI list](https://gitlab.com/wireshark/wireshark/-/raw/master/manuf)

