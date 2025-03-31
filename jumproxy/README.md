# 🔐 Jumproxy

A lightweight encrypted TCP proxy to safeguard SSH and other sensitive services against initial handshake interception and MITM (Man-in-the-Middle) attacks.

---

## 📖 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
  - [Server Mode](#server-mode)
  - [Client Mode](#client-mode)
- [Technical Specifications](#technical-specifications)
- [Requirements](#requirements)
- [Resources](#resources)
- [Disclaimer](#disclaimer)

---

## 🧹 Overview

Even with SSL/TLS-based protocols like SSH, network security can be compromised — especially during the initial handshake. If an attacker sniffs the connection during the first key exchange, they can impersonate the server and execute a man-in-the-middle (MITM) attack.

**Jumproxy** is a "jump" proxy that acts as an encryption layer between the client and any TCP service (e.g., SSH). It wraps your connection in AES-256 GCM encryption, preventing passive sniffing and protecting pre-auth vulnerabilities on first-time connections.

---

## 🚀 Features

- 🔒 **AES-256 GCM Encryption** for data confidentiality and integrity.
- 🔀 **Bidirectional Proxy**: Functions as both client-side and server-side proxy.
- 🧠 **Secure Key Derivation**: Uses PBKDF2 + SHA-256 from a passphrase file.
- 🧵 **Concurrent Connection Handling**: Manages multiple sessions concurrently.
- 🧼 **Memory Safety**: Developed in Go to reduce common memory vulnerabilities.
- 🗂️ **Raw Binary Transmission**: Perfect for tunneling protocols like SSH.

---

## ⚙️ How It Works

- Acts as a wrapper between SSH clients and SSH servers.
- The client encrypts data before sending it to the Jumproxy server.
- The server decrypts and forwards the data to the real destination.
- Return traffic follows the reverse path, maintaining full-duplex encrypted transport.

---

## 🧱 Installation

### Prerequisites

- Go 1.15 or later
- A network path that allows TCP communication between the Jumproxy client and server

### Steps

```bash
git clone https://github.com/anishphilip012git/netsec.git
cd netsec/jumproxy
go build -o jumproxy
```

---

## 🧪 Usage

### 🔌 Server Mode

Start a Jumproxy instance that listens for encrypted traffic and forwards it to a destination:

```bash
./jumproxy -k [path_to_passphrase_file] -l [listen_port] [destination_host] [destination_port]
```

**Example:**

```bash
./jumproxy -k mypass.txt -l 2222 localhost 22
```

---

### 🔧 Client Mode

Run Jumproxy on the client side and use it as a proxy for SSH:

```bash
./jumproxy -k [path_to_passphrase_file] [server_host] [server_port]
```

**With SSH ProxyCommand:**

```bash
ssh -o "ProxyCommand ./jumproxy -k mypass.txt 192.168.0.123 2222" user@localhost
```

---

## 🧰 Technical Specifications

- **Symmetric Encryption**: AES-256-GCM
- **Key Derivation**: PBKDF2-HMAC-SHA256 from passphrase file
- **Nonces**: Securely generated and managed per session
- **Data Handling**: Raw, binary-safe I/O for protocol-agnostic forwarding
- **Persistent Mode**: Server continues to accept new connections indefinitely
- **Efficient I/O**: Buffered and goroutine-powered concurrent reads/writes

---

## 📦 Requirements

- ✅ Go 1.15+
- ✅ TCP connectivity between Jumproxy client and server
- ✅ Same passphrase/key file on both ends

---

## 📚 Resources

- [Go Crypto Cipher](https://pkg.go.dev/crypto/cipher)
- [Go Socket Programming Intro](https://www.developer.com/languages/intro-socket-programming-go/)
- [Netcat for Penetration Testing](https://medium.com/@HackTheBridge/beginners-guide-to-netcat-for-hackers-55abe449991d)
- [Tour of Go](https://go.dev/tour/welcome/1)
- [GitHub Repo](https://github.com/anishphilip012git/security/tree/main/jumproxy)

---

## ⚠️ Disclaimer

This tool is provided strictly for educational and research purposes. The author assumes **no legal responsibility** for any misuse of Jumproxy on unauthorized networks.

---