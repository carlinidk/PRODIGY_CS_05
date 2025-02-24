# Network Packet Analyzer

## Overview
Network Packet Analyzer is a real-time packet capture tool built using Python and Scapy. It provides a user-friendly GUI with a dark neon theme and allows users to filter network packets based on protocol types (IP, TCP, UDP, ICMP, or all).

## Features
✅ Real-time packet capture and display  
✅ User-friendly GUI with dynamic resizing  
✅ Customizable packet filtering options (IP, TCP, UDP, ICMP, or all)  
✅ Double-click to view detailed packet information  
✅ Real-time traffic speed indicator (Packets Per Second - PPS)  
✅ Status bar to show capture progress  
✅ Dark neon theme with hover glow effect on buttons  
✅ Clear logs button for easy data management  

## Installation
### Prerequisites
Make sure you have Python installed (version 3.x recommended). You will also need the following dependencies:
```sh
pip install scapy
```
For Windows users, ensure WinPcap or npcap is installed to enable packet sniffing.

#### Install npcap:
Download and install npcap from the official website:
[https://nmap.org/npcap/](https://nmap.org/npcap/)

## Usage
1. Run the script:
   ```sh
   python networkpa.py
   ```
2. Select the desired packet filter (IP, TCP, UDP, ICMP, or all) from the dropdown.
3. Click "Start Capture" to begin packet sniffing.
4. Double-click a packet entry to view its details.
5. Click "Stop Capture" to end the session.
6. Use "Clear Logs" to remove previous entries.


This project is for educational and ethical use only. Unauthorized use for malicious purposes is strictly prohibited.




