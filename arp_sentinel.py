import os
import ipaddress
import netifaces
from platform import system
import subprocess
from scapy.all import *

chk_db = {}
INTERFACE_NAME = None
BLOCKED_MACS = set()

def get_mac(ip):

    target_ip = ip
    arp_req = ARP(pdst = target_ip)
    eth = Ether(dst = "ff:ff:ff:ff:ff:ff")
    req_bdcst = eth/arp_req

    ans_list = srp(req_bdcst, timeout = 1, verbose = False)[0]

    if ans_list:
        return ans_list[0][1].hwsrc
    else:
        return None

def get_network_range():
    try:
        global INTERFACE_NAME
        gateways = netifaces.gateways()
        default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)

        if not default_gateway:
            raise ValueError("Could not determine default gateway.")

        gateway_ip, interface_name = default_gateway
        INTERFACE_NAME = interface_name
        if_addresses = netifaces.ifaddresses(interface_name)
        ipv4_info = if_addresses.get(netifaces.AF_INET)

        if not ipv4_info:
            raise ValueError(f"No IPv4 information found for interface {interface_name}.")

        ip_address = ipv4_info[0]['addr']
        netmask = ipv4_info[0]['netmask']
        
        interface = ipaddress.IPv4Interface(f"{ip_address}/{netmask}")
        network = interface.network
        
        print(f"[*] Automatically detected network range: {str(network)}")
        return str(network)

    except Exception as e:
        print(f"[!] Error detecting network range: {e}")
        return None


def verify_change(ip, new_mac):
    print(f"[*] Suspicious change for {ip}. New MAC: {new_mac}. Verifying...")
    real_mac = chk_db[ip]
    arp_req = ARP(pdst=ip)
    eth = Ether(dst="ff:ff:ff:ff:ff:ff")
    req_bdcst = eth / arp_req
    
    ans_list = srp(req_bdcst, timeout=2, verbose=False)[0]
    
    if len(ans_list) == 0:
        print(f"[!] No device responded for {ip}. Change might be temporary.")
        return False
        
    elif len(ans_list) == 1:
        res_mac = ans_list[0][1].hwsrc
        if res_mac == new_mac:
            print(f"[+] Verification successful. {ip} legitimately moved to {new_mac}.")
            chk_db[ip] = new_mac
            return True
        else:
            if res_mac == real_mac:
                print(f"[!] Verification conflict. Original MAC {real_mac} responded. Therefore MAC {new_mac} belongs to an attacker.")
                return False
            else:
                print(f"[!] Verification conflict. A different MAC {res_mac} responded.")
                return False

    elif len(ans_list) > 1:
        print(f" VERIFICATION FAILED! Multiple devices responded for {ip}. Definite attack.")
        return False

def fix_local_arp_cache(ip, correct_mac):

    print(f"[*] Manually fixing local ARP cache for {ip}...")
    system_os = system()
    
    if system_os == "Linux" or system_os == "Darwin":
        os.system(f"arp -d {ip}")
        os.system(f"arp -s {ip} {correct_mac}")
    elif system_os == "Windows":
        os.system(f"arp -d {ip}")
        os.system(f"arp -s {ip} {correct_mac.replace(':', '-')}")
    
    print(f"[+] Local cache entry for {ip} set to {correct_mac}.")

def send_correction(real_ip, real_mac):

    global INTERFACE_NAME
    if not INTERFACE_NAME:
        print("[!] ERROR: Interface name not set. Cannot send correction.")
        return
    
    print(f"[*] Sending corrective ARP broadcast for {real_ip} -> {real_mac}")
    try:
        correction_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            psrc=real_ip,
            hwsrc=real_mac,
            pdst="255.255.255.255",
            hwdst="ff:ff:ff:ff:ff:ff"
        )
        raw_packet_bytes = bytes(correction_packet)
        executable_path = "./raw_injector"
        command = [executable_path, INTERFACE_NAME]
        for _ in range(5):
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            stdout, stderr = process.communicate(input=raw_packet_bytes)
            
            if process.returncode != 0:
                print(f"[!] Injector mechanism failed: {stderr.decode().strip()}")
    except FileNotFoundError:
        print(f"[!] ERROR: Executable not found at '{executable_path}'.")
    except Exception as e:
        print(f"[!] An error occurred during injection procedure: {e}")

def discover_hosts(network_range):
    
    print(f"[*] Scanning network {network_range} to build trusted table...")
    
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    clients_dict = {}
    for element in answered_list:
        ip_addr = element[1].psrc
        mac_addr = element[1].hwsrc
        clients_dict[ip_addr] = mac_addr
        
    return clients_dict

def block_attacker(mac_address, interface_name):
    
    if mac_address in BLOCKED_MACS:
        print(f"[*] MAC {mac_address} is already blocked.")
        return

    print(f"[*] Blocking all traffic from attacker's MAC: {mac_address}")
    
    system_os = system()
    command = ""

    if system_os == "Linux":
        command = (
            f"iptables -A INPUT -m mac --mac-source {mac_address} -j DROP && "
            f"arptables -A OUTPUT --destination-mac {mac_address} -j DROP"
        )
        
    elif system_os == "Darwin":
        command = f'(pfctl -sr 2>/dev/null; echo "block drop quick on {interface_name} from {mac_address} to any"; echo "block drop out quick on {interface_name} from any to {mac_address}") | pfctl -f -'
        
    elif system_os == "Windows":
        print("[!] MAC address blocking is not directly supported on Windows via 'netsh'.")
        return
        
    else:
        print(f"[!] Unsupported OS ({system_os}) for MAC address blocking.")
        return
    try:
        os.system(command)
        BLOCKED_MACS.add(mac_address)
        print(f"[+] Firewall rule added to drop packets from {mac_address}.")
    except Exception as e:
        print(f"[!] Failed to execute firewall command: {e}")

def process_packet(packet):
    
    if packet.haslayer(ARP):
        
        if packet[ARP].op == 2 or packet[ARP].op == 1:
            try:
                real_mac = chk_db[packet[ARP].psrc]
                response_mac = packet[ARP].hwsrc
                response_ip = packet[ARP].psrc

                if response_mac in BLOCKED_MACS:
                    print(f"[*] Ignored packet from already-blocked MAC: {response_mac}")
                    return 

                if real_mac != response_mac:
                    is_legitimate = verify_change(response_ip, response_mac)
        
                    if not is_legitimate:
                        print(f"[!] Attack confirmed for {response_ip}. Sending correction to real MAC {real_mac}.")
                        block_attacker(response_mac, INTERFACE_NAME)
                        fix_local_arp_cache(response_ip, real_mac)
                        send_correction(response_ip, real_mac)
            
                    print("-" * 30)

            except KeyError: #for unknowwn ip, try later
                pass

def main():
    
    if os.geteuid() != 0:
        exit("You need to be root to run this script.")
    global chk_db
    NETWORK_RANGE = get_network_range()
    if not NETWORK_RANGE:
        exit("[!] Could not determine network range. Exiting.")
    chk_db = discover_hosts(NETWORK_RANGE)
    if not chk_db:
        exit("[!] Could not discover any devices. Check network range or connectivity. Exiting.")
    print("\n Initial scan complete. Monitoring the following discovered devices:")
    for ip, mac in chk_db.items():
        print(f"  -> IP: {ip.ljust(15)} MAC: {mac}")
    print("-" * 40)
    try:
        sniff(filter="arp", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n Detector stopped by user.")
        exit(0)

if __name__ == "__main__":
    main()
