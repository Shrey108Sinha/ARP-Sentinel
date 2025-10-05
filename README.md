# ARP Sentinel 

A proactive, hybrid Python/C system for the detection, prevention, and correction of ARP Cache Poisoning and Man-in-the-Middle (MiTM) attacks.

This tool provides a robust, real-time defense mechanism for local area networks by actively monitoring ARP traffic, intelligently verifying threats, and executing a multi-layered defense strategy to neutralize attackers and repair network integrity.

-----

## Features

  * **Automatic Network Discovery:** Automatically detects the active network interface and its IP range without any manual configuration.
  * **Dynamic Trusted Table:** Performs an initial network scan to build a trusted table of IP-to-MAC address mappings.
  * **Real-time Monitoring:** Actively sniffs all ARP traffic to instantly detect anomalies against the trusted table.
  * **Intelligent Verification:** When a mismatch is detected, the system re-verifies the host to intelligently distinguish between a legitimate DHCP change and a malicious attack.
  * **Multi-OS Attacker Blocking:** Upon confirming an attack, the attacker's MAC address is immediately blocked using the native OS firewall.
      * On **Linux**, it uses **`iptables`** to block incoming IP traffic and **`arptables`** to block outgoing ARP replies to the attacker.
      * On **macOS**, it uses **`pfctl`** to implement similar rules.
  * **Forced Local Cache Correction:** Manually corrects the ARP cache on the host machine running the tool, bypassing the OS's skepticism of unsolicited ARP replies.
  * **Network-Wide Repair:** Broadcasts corrective ARP packets to the entire network to repair the poisoned caches of all connected devices.
  * **High-Speed Packet Injection:** Utilizes a hybrid architecture where corrective packet templates are built in **Python/Scapy** but are injected onto the network using a lightweight, high-performance **C** executable for maximum speed and defensive reliability.

-----

## How It Works

The system follows a precise, automated workflow to defend the network:

1.  **Initialization:** The script starts by automatically identifying the active network interface and calculating the local network range (e.g., `192.168.1.0/24`).
2.  **Discovery:** It broadcasts ARP requests across the discovered range and builds an initial "source of truth" table mapping the IP addresses of all responsive hosts to their corresponding MAC addresses.
3.  **Monitoring:** The tool enters a monitoring phase, sniffing every ARP packet on the network and comparing it against the trusted table.
4.  **Verification:** If an incoming packet presents an `IP:MAC` pair that contradicts the trusted table, the system does not immediately assume an attack. It broadcasts a new ARP request for the contested IP to verify the claim:
      * If the new MAC responds alone, the change is deemed legitimate (e.g., a DHCP lease change) and the trusted table is updated.
      * If the original MAC and the new MAC both respond, or only the original MAC responds, the new MAC is confirmed to be an attacker.
5.  **Mitigation:** Once an attack is confirmed, the system executes a rapid, multi-step defense:
      * **Block:** A firewall rule is immediately added to block all traffic from the attacker's MAC address.
      * **Fix Local:** The local machine's ARP cache is manually cleared of the poisoned entry and set with the correct, static entry.
      * **Fix Network:** The high-speed C injector is called to broadcast a burst of corrective ARP replies, ensuring all other devices on the network correct their poisoned cache entries.

-----

## Architecture

This project uses a hybrid **Python/C** architecture to leverage the strengths of both languages:

  * **Python (The Brain):** Handles all complex logic, including network discovery, packet analysis, threat verification, and OS interaction. Libraries like **Scapy** and **Netifaces** are used for high-level networking tasks.
  * **C (The Muscle):** A minimal, compiled C executable (`raw_injector`) is used for the single, speed-critical task of injecting raw packets onto the wire. This ensures that corrective packets are sent with the lowest possible latency to outpace a persistent attacker.

-----

## Prerequisites

  * Root or **`sudo`** privileges
  * Python 3
  * A C compiler (e.g., **`gcc`**)
  * Python libraries: **`scapy`**, **`netifaces`**
  * System tools (Linux): **`iptables`**, **`arptables`**

-----

## Usage

1.  **Install dependencies:**
    ```bash
    pip install scapy netifaces
    ```
2.  **Compile the C injector:**
    ```bash
    gcc -o raw_injector raw_injector.c
    ```
3.  **Run the main application:**
    ```bash
    sudo python3 arp_sentinel.py
    ```
