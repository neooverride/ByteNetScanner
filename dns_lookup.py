import socket

def main():

    GREEN = '\033[1;97m'
    RESET = '\033[0m'

    # Forward DNS Lookup for IPv4
    def forward_dns_lookup(domain_name):
        try:
            ip_address = socket.gethostbyname(domain_name)
            print(f"{GREEN}Forward DNS Lookup for {domain_name} (IPv4): {ip_address}{RESET}")
        except socket.gaierror:
            print(f"{GREEN}Error: Unable to resolve IPv4 for {domain_name}{RESET}")

    # Resolve all IPs (IPv4 and IPv6)
    def resolve_all_ips(domain_name):
        try:
            addr_info = socket.getaddrinfo(domain_name, None, socket.AF_UNSPEC)
            ipv4_addresses = set()
            ipv6_addresses = set()

            for entry in addr_info:
                family, _, _, _, sockaddr = entry
                if family == socket.AF_INET:
                    ipv4_addresses.add(sockaddr[0])
                elif family == socket.AF_INET6:
                    ipv6_addresses.add(sockaddr[0])

            if ipv4_addresses:
                print(f"{GREEN}All IPv4 addresses for {domain_name}: {', '.join(ipv4_addresses)}{RESET}")
            else:
                print(f"{GREEN}No IPv4 addresses found for {domain_name}{RESET}")

            if ipv6_addresses:
                print(f"{GREEN}All IPv6 addresses for {domain_name}: {', '.join(ipv6_addresses)}{RESET}")
            else:
                print(f"{GREEN}No IPv6 addresses found for {domain_name}{RESET}")

        except socket.gaierror:
            print(f"{GREEN}Error: Unable to resolve any IP for {domain_name}{RESET}")

    # Reverse DNS Lookup
    def reverse_dns_lookup(ip_address):
        try:
            domain_name = socket.gethostbyaddr(ip_address)
            print(f"{GREEN}The domain name for IP address {ip_address} is {domain_name[0]}{RESET}")
        except socket.herror:
            print(f"{GREEN}Reverse DNS Lookup for {ip_address} failed.{RESET}")

    # Function to check if the input is a valid IP address
    def is_ip_address(input_str):
        try:
            socket.inet_aton(input_str)
            return True
        except socket.error:
            return False

    # Function to check if the input is a valid domain
    def is_valid_domain(input_str):
        try:
            socket.gethostbyname(input_str)
            return True
        except socket.gaierror:
            return False

    # Main program to accept user input
    user_input = input(f"{GREEN}Enter domain names or IP addresses (space separated): {RESET}")
    inputs = user_input.split()

    for item in inputs:
        if is_ip_address(item):
            # Perform Reverse DNS Lookup if input is an IP address
            reverse_dns_lookup(item)
        elif is_valid_domain(item):
            # Resolve all IPs for a valid domain name
            resolve_all_ips(item)
        else:
            print(f"{GREEN}Invalid IP/domain: {item}{RESET}")

if __name__ == "__main__":
    main()
