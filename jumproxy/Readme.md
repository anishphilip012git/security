# Jumproxy

## Overview

Jumproxy is a "jump" proxy designed to add an extra layer of encryption to connections towards TCP services, enhancing security by protecting against potential vulnerabilities in publicly accessible services like SSH servers. The tool is built using Go and leverages the Crypto library for robust AES-256 encryption.

## Key Features

- **AES-256 GCM Encryption**: Ensures data integrity and confidentiality using AES-256 in Galois Counter Mode (GCM).
- **Dual Mode Functionality**: Acts as both a client-side proxy and a server-side reverse proxy.
- **Secure Key Derivation**: Utilizes PBKDF2 with SHA-256 for secure key derivation from a passphrase.
- **Concurrent Session Management**: Capable of handling multiple concurrent sessions in server mode.
- **Memory Safety**: Built in Go, a memory-safe language, minimizing the risk of memory corruption vulnerabilities.

## Requirements

- Go 1.15 or later
- Network settings that allow TCP connections between the client and the server

## Installation

Clone the repository and build the project:

```bash
git clone https://github.com/anishphilip012git/netsec.git
cd jumproxy
go build -o jumproxy
```

## Usage Instructions

### Server Mode

Run Jumproxy in server mode to listen for inbound connections and relay them to a specified destination:

```bash
./jumproxy -k [path_to_passphrase_file] -l [listen_port] [destination_host] [destination_port]
```

### Client Mode

Run Jumproxy in client mode to proxy traffic through a local instance, encrypting traffic sent to the server:

```bash
./jumproxy -k [path_to_passphrase_file] [server_host] [server_port]
ssh -o "ProxyCommand ./jumproxy -k mykey 192.168.0.123 2222" user@localhost
```

## Compliance Specifications

- **Encryption/Decryption**: Implements AES-256 GCM for secure, bidirectional encryption and decryption.
- **Symmetric Key Usage**: Both the client and server use the same symmetric key derived from the provided passphrase file.
- **Persistent Server Listening**: Continues to listen for new connections even after a connection is terminated.
- **Nonces Managed Securely**: Ensures secure and appropriate management of nonces for encryption.
- **Binary Data Handling**: Treats all I/O as raw binary data, suitable for protocols like SSH.
- **Efficiency and Buffer Management**: Utilizes efficient I/O handling to ensure timely reading and writing of data.


## Resources

- [Go Programming Tour](https://go.dev/tour/welcome/1)
- [Intro to Socket Programming in Go](https://www.developer.com/languages/intro-socket-programming-go/)
- [Go Crypto Cipher Documentation](https://pkg.go.dev/crypto/cipher)
- [Beginner's Guide to Netcat](https://medium.com/@HackTheBridge/beginners-guide-to-netcat-for-hackers-55abe449991d)

---

This README is tailored to clearly explain how to set up and use Jumproxy, ensuring compliance with the homework specifications and providing detailed instructions for both server and client usage. It also includes a strategy for testing and a list of helpful resources for further learning.