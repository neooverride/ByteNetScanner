import threading
import os
import time
import ipaddress
import socket

def main():
    
    GREEN = '\033[1;97m' 
    RESET = '\033[0m'


    def ping_ip(ip):
        response = os.system(f"ping -c 1 {ip} > /dev/null 2>&1")
        if response == 0:
            print(f"{GREEN}[+] {ip} is up.{RESET}")
        else:
            print(f"{GREEN}[-] {ip} is down.{RESET}")

    def is_valid_ip(ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or int(part) < 0 or int(part) > 255:
                return False
        return True

    def is_valid_domain(domain):
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False

    def is_cidr_notation(cidr):
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    def expand_cidr(cidr):
        return [str(ip) for ip in ipaddress.ip_network(cidr, strict=False).hosts()]

    # Green color input prompt and displaying input
    user_input = input(f"{GREEN}Enter IP addresses, ranges, or domains separated by space: {RESET}").split()
    print(f"{GREEN}You entered: {' '.join(user_input)}{RESET}")  # Display input in green
    threads = []
    expanded_ips = []
    invalid_domains = []

    for item in user_input:
        if is_cidr_notation(item):
            expanded_ips.extend(expand_cidr(item))
        elif '-' in item:
            start_ip, end_ip = item.split('-')
            if not is_valid_ip(start_ip) or not is_valid_ip(end_ip):
                print(f"{GREEN}[FLAGGED] Invalid IP address range: {item}{RESET}")
                continue
            start_parts = start_ip.split('.')
            end_parts = end_ip.split('.')
            for i in range(int(start_parts[3]), int(end_parts[3]) + 1):
                expanded_ips.append(f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}")
        elif is_valid_ip(item):
            expanded_ips.append(item)
        elif is_valid_domain(item):
            try:
                ip = socket.gethostbyname(item)
                expanded_ips.append(ip)
            except socket.gaierror:
                invalid_domains.append(item)
        else:
            invalid_domains.append(item)

    expanded_ips = sorted(set(expanded_ips))  # Sort and remove duplicates

    if invalid_domains:
        print(f"\n{GREEN}[!] Invalid domains detected:{RESET}")
        for domain in invalid_domains:
            print(f"    {GREEN}[FLAGGED] {domain}{RESET}")

    start_time = time.time()

    for ip in expanded_ips:
        t = threading.Thread(target=ping_ip, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end_time = time.time()
    print(f"\n{GREEN}Execution time: {end_time - start_time:.2f} seconds{RESET}")

if __name__ == "__main__":
    main()
