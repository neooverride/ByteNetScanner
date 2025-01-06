from scapy.all import *
from threading import Thread
import ipaddress
import socket
import time
import subprocess

GREEN = '\033[1;97m'
RESET = '\033[0m'

def main():
    def resolve_domain(domain):
        """Resolve a domain name to an IP address."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def is_valid_ip(ip):
        """Check if the IP address is valid."""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    def expand_ip_range(ip_range):
        """Expand an IP range (e.g., 192.168.100.102-192.168.100.108)."""
        start_ip, end_ip = ip_range.split("-")
        
        if not is_valid_ip(start_ip) or not is_valid_ip(end_ip):
            raise ValueError(f"Invalid IP range: {ip_range}")
        
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        
        return [str(ipaddress.IPv4Address(int(start) + i)) for i in range(int(end) - int(start) + 1)]

    def expand_cidr(cidr):
        """Expand a CIDR block (e.g., 192.168.100.0/24)."""
        try:
            return [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False)]
        except ValueError:
            raise ValueError(f"Invalid CIDR block: {cidr}")

    def parse_inputs(inputs):
        """Parse the user's input and expand into a list of IP addresses."""
        ip_list = []
        items = inputs.split()

        for item in items:
            if "-" in item and "/" not in item:  # IP range
                try:
                    ip_list.extend(expand_ip_range(item))
                except ValueError as e:
                    print(f"{GREEN}Error: {e}{RESET}")
                    continue
            elif "/" in item:  # CIDR block
                try:
                    ip_list.extend(expand_cidr(item))
                except ValueError as e:
                    print(f"{GREEN}Error: {e}{RESET}")
                    continue
            elif is_valid_ip(item):  # Single IP
                ip_list.append(item)
            else:  # Domain name
                resolved_ip = resolve_domain(item)
                if resolved_ip:
                    ip_list.append(resolved_ip)
                else:
                    print(f"{GREEN}Error: Invalid domain name '{item}'{RESET}")

        return list(set(ip_list))  # Remove duplicates

    def get_os_info(ip):
        """Get OS information for a target IP using multiple methods."""
        try:
            # Method 1: Send a SYN request to port 80 (HTTP)
            syn = IP(dst=ip) / TCP(dport=80, flags="S")
            response = sr1(syn, timeout=2, verbose=0)

            if response:
                if response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 18:
                        return f"{GREEN}Possibly Linux/Unix-based (SYN-ACK response){RESET}"
                    elif response.getlayer(TCP).flags == 4:
                        return f"{GREEN}Possibly Windows (RST response){RESET}"
                return f"{GREEN}OS information could not be determined{RESET}"
            else:
                return f"{GREEN}No response from target{RESET}"

        except Exception as e:
            return f"{GREEN}Error detecting OS: {str(e)}{RESET}"

    def get_ttl_based_os(ip):
        """Get OS information based on TTL value (common for ICMP responses)."""
        try:
            # Send an ICMP echo request (ping) and analyze the TTL value
            icmp = IP(dst=ip) / ICMP()
            response = sr1(icmp, timeout=2, verbose=0)

            if response:
                ttl = response.ttl
                if ttl <= 64:
                    return f"{GREEN}Possibly Linux-based (TTL <= 64){RESET}"
                elif ttl <= 128:
                    return f"{GREEN}Possibly Windows-based (TTL <= 128){RESET}"
                else:
                    return f"{GREEN}OS information could not be determined based on TTL{RESET}"
            else:
                return f"{GREEN}No response from target{RESET}"

        except Exception as e:
            return f"{GREEN}Error getting TTL for OS detection: {str(e)}{RESET}"

    def nmap_os_detection(ip):
        """Use Nmap's OS detection for more accurate results (requires Nmap installed)."""
        try:
            # Run Nmap with OS detection flag
            result = subprocess.run(['nmap', '-O', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if "OS details:" in result.stdout:
                return f"{GREEN}{result.stdout.split('OS details:')[1].split('\n')[0].strip()}{RESET}"
            else:
                return f"{GREEN}OS detection using Nmap failed{RESET}"
        except FileNotFoundError:
            return f"{GREEN}Nmap is not installed, OS detection failed{RESET}"
        except Exception as e:
            return f"{GREEN}Error using Nmap: {str(e)}{RESET}"

    def send_arp_request(ip, result_dict):
        """Send an ARP request to a specific IP and store the result."""
        try:
            arp = ARP(pdst=ip)
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp, timeout=2, verbose=0)

            if ans:
                for _, received in ans:
                    ip_address = received.psrc
                    mac_address = received.hwsrc
                    os_info = get_os_info(ip_address)
                    if os_info == f"{GREEN}No response from target{RESET}":
                        os_info = get_ttl_based_os(ip_address)
                    if os_info == f"{GREEN}OS information could not be determined{RESET}":
                        os_info = nmap_os_detection(ip_address)
                    result_dict[ip_address] = f"{GREEN}Scan report for {ip_address}\nHost is up.\nMAC Address: {mac_address}\nOS: {os_info}{RESET}"
                    return
            result_dict[ip] = f"{GREEN}Scan report for {ip}\nHost seems down.\nMAC Address: Unknown\nOS: Unknown{RESET}"
        except Exception as e:
            result_dict[ip] = f"{GREEN}Scan report for {ip}\nHost seems down.\nError: {str(e)}{RESET}"

    def active_host_enumeration(ips):
        """Enumerate active hosts from the provided list of IPs."""
        result_dict = {}
        threads = []

        print(f"\n{GREEN}Scanning, please wait...{RESET}\n")
        
        # Start time for scanning
        start_time = time.time()

        for ip in ips:
            thread = Thread(target=send_arp_request, args=(ip, result_dict))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # End time after scanning is complete
        end_time = time.time()
        total_time = end_time - start_time

        print(f"\n{GREEN}Scan Results:{RESET}\n")
        for ip in sorted(ips):
            print(result_dict.get(ip, f"{GREEN}Scan report for {ip}\nHost seems down.\nMAC ADDRESS: Unknown\nOPERATING SYSTEM: Unknown{RESET}"))

        print(f"\n{GREEN}Scanning completed in {total_time:.2f} seconds.{RESET}")

    user_input = input(f"{GREEN}Enter target IPs (e.g., 192.168.1.1, 192.168.1.1-192.168.1.5, 192.168.1.0/24, www.example.com): {RESET}")
    target_ips = parse_inputs(user_input)
    if target_ips:
        active_host_enumeration(target_ips)
    else:
        print(f"{GREEN}No valid IPs or domains found to scan.{RESET}")

if __name__ == "__main__":
    main()
