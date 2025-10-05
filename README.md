# ARP-Sentinel
A robust system for detection and prevention a ARP Cache Poisoning attacks and MiTM attack. When run on a device, it scans the network and dynamically creates a trusted IP:MAC address table which is then used as a reference to cross-check all arriving packets. If spoofing is detected, it manually re-corrects the cache.
