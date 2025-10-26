# 👁️SeeWire

> **SeeWire** — A lightweight, C-based packet sniffer that lets you *see what’s really on the wire.*

```
  _________             __      __.__                
 /   _____/ ____   ____/  \    /  \__|______   ____  
 \_____  \_/ __ \_/ __ \   \/\/   /  \_  __ \_/ __ \ 
 /        \  ___/\  ___/\        /|  ||  | \/\  ___/ 
/_______  /\___  >\___  >\__/\  / |__||__|    \___  >
        \/     \/     \/      \/                  \/
```


---

## Overview

**SeeWire** is a simple yet powerful **packet sniffer** written entirely in **C**.  
It captures and inspects raw network packets in real time, giving you a clear view of what’s happening on your network interface — just like `tcpdump`, but lighter and easier to understand for students and developers learning low-level networking.

---

## Features

- 🔍 Capture live packets from a network interface  
- 🧩 Decode Ethernet, IP, TCP, UDP, and ICMP headers  
- 💾 Optional logging to a file for later analysis  
- ⚡ Built with **raw sockets** and standard POSIX libraries  
- 💡 Perfect for learning about packet structures and network layers  

---

## 🧱 Build Instructions

### Requirements
- A C compiler (`gcc` or `clang`)
- Root privileges (for raw socket access)
- Linux or BSD-based OS

### Run
```bash
sudo ./seewire -i eth0
```

or with logging:

```bash
sudo ./seewire -i wlan0 -o capture.log
```

---

## ⚙️ Usage

| Option | Description |
|--------|-------------|
| `-i <interface>` | Specify the network interface (e.g. `eth0`, `wlan0`) |
| `-o <file>` | Save captured packets to a file |
| `-f <filter>` | Apply a simple packet filter (e.g. `tcp`, `udp`) |
| `-v` | Verbose mode — print detailed header info |
| `-h` | Show help message |

**Example:**
```bash
sudo ./seewire -i eth0 -f tcp -v
```

---

## 🧬 How It Works

SeeWire uses **raw sockets** to directly capture frames at the data link layer.  
Each packet is parsed manually to reveal Ethernet, IP, and transport-layer details.  
This gives you a low-level, hands-on understanding of how packet sniffers like Wireshark and tcpdump operate internally.

---

## 📘 Educational Value

SeeWire is designed as a **learning tool** for:
- Computer networks students exploring packet structures  
- Developers learning about sockets and network programming in C  
- Security enthusiasts experimenting with traffic analysis  

---

## Example Output

```
[+] Capturing on eth0...
-------------------------------------------------
Frame: 1 | Size: 74 bytes
Ethernet: src=00:1a:2b:3c:4d:5e dst=ff:ff:ff:ff:ff:ff
IP: 192.168.1.10 → 192.168.1.1 | Protocol: TCP
TCP: src port 443 → dst port 56732 | Flags: SYN, ACK
-------------------------------------------------
```

---

## 🛠️ Future Plans

- Add IPv6 support  
- Include DNS and HTTP decoding  
- Implement colorized terminal output  
- PCAP file export for Wireshark integration  

---

## ✨ Author

**Pius Kakeeto**  
*Network and systems enthusiast, programmer, and security engineer in training*
> “Sniff. Decode. Learn.”
