# PCAP Network Traffic Analysis – JOVAC Ethical Hacking Assignment 2

## 📌 Overview

This repository contains the forensic analysis report of the provided **traffic.pcapng** capture file completed as part of the **JOVAC Ethical Hacking** course.

The analysis was performed using **Wireshark 4.2.2** and **TShark**, focusing on packet inspection, protocol statistics, IP/MAC address identification, and network communication patterns.

---

## 👨‍💻 Author

**Tarun Thakur**  
**University Roll No.:** 2415001680  
**Course:** JOVAC – Ethical Hacking  
**Assignment:** Assignment 2 – PCAP Analysis  
**Submission Date:** July 25, 2026

---

## 🛠 Tools Used

- Wireshark 4.2.2
- TShark
- Display Filters
- Packet-Level Analysis

---

## 📂 Analyzed File

```
traffic.pcapng
```

---

## 🎯 Objective

The objective of this assignment is to perform forensic analysis of a network packet capture and extract important network information including:

- DHCP traffic
- ARP packets
- DNS activity
- HTTP/HTTPS traffic
- SMB communication
- NBNS traffic
- IP and MAC address mapping
- Vendor identification
- Capture duration
- Host communication statistics

---

## 📊 Analysis Summary

| Item | Result |
|------|--------|
| DHCP Messages | 5 |
| ARP Packets | 680 |
| UDP Packets | 102 |
| SMB Packets | 518 |
| NBNS Packets | 963 |
| IPv4 Packets | 24,606 |
| HTTPS Source Port 443 Packets | 7,275 |
| HTTPS Destination Port 443 Packets | 5,966 |
| Capture Duration | 348.1066 Seconds |

---

## 🔍 Key Findings

- Identified the client accessing **baidu.com**
- Determined packet counts for multiple protocols
- Mapped IP addresses to MAC addresses
- Identified the firewall gateway MAC address
- Verified DNS infrastructure
- Investigated SMB and Windows domain traffic
- Calculated capture duration
- Identified network vendors using MAC addresses

---

## 🔐 Security Observations

- Check Point Firewall Gateway detected.
- Internal DNS server located at **10.103.0.20**.
- HTTPS traffic dominates the capture.
- Active Windows Domain environment observed.
- SMB and NBNS traffic indicate Active Directory communication.
- DHCP activity suggests stable IP lease assignments.

---

## 📖 Skills Demonstrated

- Network Traffic Analysis
- Packet Inspection
- Wireshark Filtering
- TShark Commands
- Protocol Analysis
- TCP/IP Networking
- DNS Analysis
- SMB Investigation
- MAC Vendor Identification
- Digital Network Forensics

---

## 📁 Repository Contents

```
.
├── traffic.pcapng
├── Assignment_Report.pdf
├── screenshots/
└── README.md
```

---

## 📚 Learning Outcomes

This project demonstrates practical experience in:

- Network Forensics
- Ethical Hacking
- Wireshark Analysis
- Packet Capture Investigation
- Protocol Identification
- Incident Investigation
- Enterprise Network Traffic Analysis

---

## ⭐ Conclusion

The packet capture was successfully analyzed using Wireshark and TShark. All required assignment questions were answered through packet-level investigation without assumptions. The analysis demonstrates practical knowledge of network protocols, forensic investigation techniques, and industry-standard packet analysis tools.

---

## 📜 License

This project is published for **educational purposes only** as part of the **JOVAC Ethical Hacking** program.
