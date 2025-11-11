# ARP Spoofing & DNS MitM — Lab Project

**Author:** Romain Auchet  
**Date:** November 11, 2025  
**Summary:** Scapy-based tools and analysis to demonstrate ARP spoofing and selective DNS spoofing in an isolated virtual lab. This repository contains scripts, a small fake web server, PCAP evidence, screenshots and the final report.

---

## Repository layout (reflects repository screenshot)
```text
├─ evidence/
│  ├─ arp_table_after_victim.png
│  ├─ arp_table_after.png
│  ├─ arp_table_before_gateway.png
│  ├─ arp_table_before_victim.png
│  ├─ arp_table_before.png
│  ├─ fake_server_logs.png
│  ├─ fake_server_task3_look.png
│  ├─ task1_passing_through_attacker.png
│  ├─ task2_result1.png
│  ├─ task2_result2.png
│  ├─ task3_dns_spoofed.png
│  ├─ wireshark_task2_http.png
│  └─ wireshark_task2_ssh.png
├─ fake server/
│  ├─ fake.html
│  └─ server.py
├─ pcap_files/
│  ├─ capture_task1_test.pcap
│  ├─ capture_task1.pcap
│  ├─ capture_task2_test.pcap
│  ├─ capture_task2_test2.pcap
│  └─ capture.pcap
├─ script/
│  ├─ arp_spoof.py
│  ├─ dns_spoof.py
│  ├─ domain.json
│  └─ traffic_interceptor.py
├─ README.md
├─ report_arp_dns_spoofing.pdf
└─ requirements.txt
```


---

 **Run these only inside an isolated VM network** (Attacker, Victim, Gateway VMs). Do not run on public or institutional networks

