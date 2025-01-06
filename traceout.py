import os
import socket
import requests
from scapy.all import *
from urllib.parse import urlparse

BRIGHT_WHITE = "\033[1;97m"  # For bright white color
RESET = "\033[0m"  # Reset color

def main():

    def is_broadcast_address(ip):
        # Check if the IP is a broadcast address
        octets = ip.split('.')
        if octets[-1] == '255':
            return True
        return False

    def perform_traceroute(target, protocol="icmp"):
        # Check if the target is a broadcast address
        if is_broadcast_address(target):
            print(f"{BRIGHT_WHITE}Broadcast address {target} detected. Performing traceroute...{RESET}")

        # Continue with existing traceroute logic
        result, unanswered = traceroute(target, protocol=protocol)
        print(result)

    # Function to get the geolocation of an IP address
    def get_geolocation(ip):
        try:
            response = requests.get(f'https://ipinfo.io/{ip}/json')
            data = response.json()
            loc = data.get('loc', 'Location not available').split(',')
            city = data.get('city', 'Unknown')
            region = data.get('region', 'Unknown')
            country = data.get('country', 'Unknown')
            return f"{city}, {region}, {country}"
        except requests.exceptions.RequestException as e:
            return 'Geolocation not available'

    # Function to validate domain/IP
    def validate_domain_ip(target):
        try:
            # Try to resolve the domain/IP address
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

    # Function to extract the IP address from the URL
    def get_ip_from_url(url):
        parsed_url = urlparse(url)
        domain = parsed_url.hostname  # Extract the domain part from the URL
        return socket.gethostbyname(domain)

    # Function to resolve hostnames or subdomains to IP
    def get_ip_from_hostname_or_subdomain(hostname):
        return socket.gethostbyname(hostname)

    # ICMP traceroute
    def icmp_traceroute(target, max_hops=30):
        print(f"\n{'Hop':<5} {'IP Address':<20} {'Geolocation':<35} {'Time (s)'}")
        print('-' * 85)  # For separator line
        for ttl in range(1, max_hops + 1):
            pkt = IP(dst=target, ttl=ttl) / ICMP()
            reply = sr1(pkt, timeout=2, verbose=False)
            
            if reply is None:
                print(f"{ttl:<5} {'*':<20} {'Request timed out':<35} {'-'}")
            else:
                geolocation = get_geolocation(reply.src)
                # Convert time from milliseconds to seconds and round to 2 decimal places
                response_time = round(reply.time, 2) if reply.time else "-"
                print(f"{ttl:<5} {BRIGHT_WHITE}{reply.src:<20}{RESET} {BRIGHT_WHITE}{geolocation:<35}{RESET} {BRIGHT_WHITE}{response_time:<10}{RESET}")

    # TCP traceroute (Same for TCP)
    def tcp_traceroute(target, max_hops=30):
        print(f"\n{'Hop':<5} {'IP Address':<20} {'Geolocation':<35} {'Time (s)'}")
        print('-' * 85)  # For separator line
        for ttl in range(1, max_hops + 1):
            pkt = IP(dst=target, ttl=ttl) / TCP(dport=80, flags="S")
            reply = sr1(pkt, timeout=2, verbose=False)
            
            if reply is None:
                print(f"{ttl:<5} {'*':<20} {'Request timed out':<35} {'-'}")
            else:
                geolocation = get_geolocation(reply.src)
                # Convert time from milliseconds to seconds and round to 2 decimal places
                response_time = round(reply.time, 2) if reply.time else "-"
                print(f"{ttl:<5} {BRIGHT_WHITE}{reply.src:<20}{RESET} {BRIGHT_WHITE}{geolocation:<35}{RESET} {BRIGHT_WHITE}{response_time:<10}{RESET}")

    # UDP traceroute (Same for UDP)
    def udp_traceroute(target, max_hops=30):
        print(f"\n{'Hop':<5} {'IP Address':<20} {'Geolocation':<35} {'Time (s)'}")
        print('-' * 85)  # For separator line
        for ttl in range(1, max_hops + 1):
            pkt = IP(dst=target, ttl=ttl) / UDP(dport=33434)
            reply = sr1(pkt, timeout=2, verbose=False)
            
            if reply is None:
                print(f"{ttl:<5} {'*':<20} {'Request timed out':<35} {'-'}")
            else:
                geolocation = get_geolocation(reply.src)
                # Convert time from milliseconds to seconds and round to 2 decimal places
                response_time = round(reply.time, 2) if reply.time else "-"
                print(f"{ttl:<5} {BRIGHT_WHITE}{reply.src:<20}{RESET} {BRIGHT_WHITE}{geolocation:<35}{RESET} {BRIGHT_WHITE}{response_time:<10}{RESET}")

    # Main function to perform the traceroute based on user input
    def perform_traceroute(target, protocol='icmp', max_hops=30):
        if not validate_domain_ip(target):
            print(f"{BRIGHT_WHITE}Error: Invalid domain or IP address '{target}'. Please enter a valid domain/IP.{RESET}")
            return

        print(f"\nPerforming traceroute to {BRIGHT_WHITE}{target}{RESET}...\n")
        if protocol == 'icmp':
            icmp_traceroute(target, max_hops)
        elif protocol == 'tcp':
            tcp_traceroute(target, max_hops)
        elif protocol == 'udp':
            udp_traceroute(target, max_hops)
        else:
            print(f"{BRIGHT_WHITE}Error: Unsupported protocol. Please enter 'icmp', 'tcp', or 'udp'.{RESET}")

    try:
        target_input = input(f"{BRIGHT_WHITE}Enter domain names, IP addresses, hostnames, subdomains, or URLs (space separated): {RESET}")
        protocol = input(f"{BRIGHT_WHITE}Enter protocol to use (icmp/tcp/udp): {RESET}")

        # Check if user entered a URL, subdomain or hostname
        for item in target_input.split():
            if item.startswith('http://') or item.startswith('https://'):
                # If URL, extract the IP address and run traceroute
                ip_address = get_ip_from_url(item)
                print(f"Resolved IP for {item} is {BRIGHT_WHITE}{ip_address}{RESET}")
                perform_traceroute(ip_address, protocol=protocol)
            elif item.isalnum() and not item.startswith("http"):
                # If it's a valid hostname or subdomain, resolve it to IP and run traceroute
                ip_address = get_ip_from_hostname_or_subdomain(item)
                print(f"Resolved IP for hostname/subdomain {item} is {BRIGHT_WHITE}{ip_address}{RESET}")
                perform_traceroute(ip_address, protocol=protocol)
            else:
                # If it's already an IP or domain, run traceroute directly
                perform_traceroute(item, protocol=protocol)

    except KeyboardInterrupt:
        print("\n\nProcess interrupted by user. Thank you for using the tool!")

if __name__ == "__main__":
    main()
