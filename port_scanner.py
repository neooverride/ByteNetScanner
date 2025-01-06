import socket
import sys
import threading
import re

# Bright White Color Code
BRIGHT_WHITE = '\033[1;97m'
RESET = '\033[0m'

def main():
    """Main function to run the port scan"""

    def scanHost(ip, startPort, endPort):
        """ Starts a TCP scan on a given IP address """
        print(f'{BRIGHT_WHITE}[*] Starting TCP port scan on host {ip}{RESET}')
        threads = []
        
        # Creating threads for each port
        for port in range(startPort, endPort + 1):
            thread = threading.Thread(target=tcp_scan, args=(ip, port))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to finish
        for thread in threads:
            thread.join()
        
        print(f'{BRIGHT_WHITE}[+] TCP scan on host {ip} complete{RESET}')

    def scanRange(network, startPort, endPort):
        """ Starts a TCP scan on a given IP address range """
        print(f'{BRIGHT_WHITE}[*] Starting TCP port scan on network {network}.0{RESET}')
        threads = []
        
        for host in range(1, 255):
            ip = network + '.' + str(host)
            thread = threading.Thread(target=tcp_scan, args=(ip, startPort, endPort))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()

        print(f'{BRIGHT_WHITE}[+] TCP scan on network {network}.0 complete{RESET}')

    def tcp_scan(ip, port):
        """ Creates a TCP socket and attempts to connect via a supplied port """
        try:
            # Create a new socket
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(1)  # Timeout for connection attempt
            
            # Print if the port is open
            if not tcp.connect_ex((ip, port)):
                print(f'{BRIGHT_WHITE}[+] {ip}:{port}/TCP Open{RESET}')
            tcp.close()
        except Exception:
            pass

    def is_valid_ip(ip):
        """Validate the format of the given IP address"""
        # Regular expression to validate an IP address
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        return re.match(ip_pattern, ip) is not None

    def is_valid_port_range(startPort, endPort):
        """Validate the given port range"""
        if startPort < 1 or startPort > 65535 or endPort < 1 or endPort > 65535:
            return False
        if startPort > endPort:
            return False
        return True

    # Timeout in seconds
    socket.setdefaulttimeout(0.01)

    # Input prompt for target IP and port range
    while True:
        target_ip = input(f"{BRIGHT_WHITE}Enter target IP (e.g., 192.168.100.102: {RESET}")
        if is_valid_ip(target_ip):
            break
        else:
            print(f"{BRIGHT_WHITE}Error: Invalid IP format. Please enter a valid IP address (e.g., 192.168.100.102).{RESET}")
    
    while True:
        try:
            start_port = int(input(f"{BRIGHT_WHITE}Enter TCP port range (start): {RESET}"))
            end_port = int(input(f"{BRIGHT_WHITE}Enter TCP port range (end): {RESET}"))
            if is_valid_port_range(start_port, end_port):
                break
            else:
                print(f"{BRIGHT_WHITE}Error: Invalid port range. Please ensure the start port is less than or equal to the end port, and ports are between 1 and 65535.{RESET}")
        except ValueError:
            print(f"{BRIGHT_WHITE}Error: Invalid port number. Please enter valid integers for port range.{RESET}")

    # Scan the given host or range
    if '.' in target_ip:
        scanHost(target_ip, start_port, end_port)
    else:
        scanRange(target_ip, start_port, end_port)

if __name__ == '__main__':
    main()
