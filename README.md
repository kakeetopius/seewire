# 👁️ SeeWire

> **SeeWire** — A lightweight, C-based packet sniffer that lets you *see what’s really on the wire.*

```
  _________             __      __.__                
 ╱   _____╱ ____   ____╱  ╲    ╱  ╲__│______   ____  
 ╲_____  ╲_╱ __ ╲_╱ __ ╲   ╲╱╲╱   ╱  ╲_  __ ╲_╱ __ ╲ 
 ╱        ╲  ___╱╲  ___╱╲        ╱│  ││  │ ╲╱╲  ___╱ 
╱_______  ╱╲___  >╲___  >╲__╱╲  ╱ │__││__│    ╲___  >
        ╲╱     ╲╱     ╲╱      ╲╱                  ╲╱
```

---

## Overview

**SeeWire** is a simple yet powerful **packet sniffer** written entirely in **C**.  
It captures and inspects raw network packets in real time, giving you a clear view of what’s happening on your network interface ,
just like `tcpdump`, but lighter and easier to understand.

---

## Features

-  Capture live packets from a network interface  
-  Decode Ethernet, IP, TCP, UDP, and ICMP headers  
-  Optional logging to a file for later analysis  
-  Built with libpcap and standard POSIX libraries  
-  Perfect for learning about packet structures and network layers  

---

##  Build Instructions

### Requirements
- A C compiler (`gcc` or `clang`)
- Build System Requirements: meson(requires python3), ninja-build plus the libpcap development files.
- Root privileges (for raw socket access)
- Linux or BSD-based OS

### Installation.
1. Install meson, ninja-build and libpcap packages from your preferred package manager, for example
```bash
#debian, ubuntu, kali and the like
sudo apt install meson ninja-build libpcap-dev

#fedora and friends
sudo dnf install meson ninja-build libpcap-devel
```

2. Clone the repository.
```bash
git clone https://github.com/kakeetopius/SeeWire.git seewire && cd seewire
```

3. Build with meson
```bash
meson setup build && cd build
meson compile 

#optionally if you want to install to path.
sudo meson install 
```

### Run
```bash
sudo ./seewire -i eth0
```

or with logging:

```bash
sudo ./seewire -i wlan0 -o capture.pcap
```

---

##  Usage

| Option | Description |
|--------|-------------|
| `-i <interface>` | Specify the network interface (e.g. `eth0`, `wlan0`) |
| `-o <file>` | Save captured packets to a file |
| `-f <filter>` | Apply a simple packet filter in BPF syntax(e.g. `tcp`, `udp`) |
| `-in <file>` | Stream packets from a pcap file instead of a network interface.
| `-h` | Show help message |

**Example:**
```bash
sudo ./seewire -i eth0 -f tcp 
```

---

##  How It Works

SeeWire uses libpcap that uses **raw sockets** or **PF_PACKET** sockets to directly capture frames at the data link layer.  
Each packet is parsed manually to reveal Ethernet, IP, and transport-layer details.  

---

##  Educational Value

SeeWire is designed as a **learning tool** for:
- Computer networks students exploring packet structures  
- Developers learning about sockets and network programming in C  
- Security enthusiasts experimenting with traffic analysis  

---

## Future Plans

- Add IPv6 support  
- Include DNS and HTTP decoding  
- Implement colorized terminal output  

---

## ✨ Author

**Pius Kakeeto**  
*Network and systems enthusiast, programmer, and security engineer in training*
> “Sniff. Decode. Learn.”
