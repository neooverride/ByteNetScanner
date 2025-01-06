import ipaddress
import socket

def main():
    def process_input(input_str):
        """Process individual input and return a list of IPs and their subnet masks."""
        results = []
        # Check if it's an IP range
        if '-' in input_str:
            start_ip, end_ip = input_str.split('-')
            try:
                start = ipaddress.ip_address(start_ip)
                end = ipaddress.ip_address(end_ip)
                if start > end:
                    raise ValueError("Invalid range: Start IP is greater than End IP")
                # Generate all IPs in the range
                current = start
                while current <= end:
                    network = ipaddress.ip_network(f"{start_ip}/24", strict=False)
                    results.append((str(current), str(network.netmask)))
                    current += 1
            except ValueError as e:
                results.append((input_str, "WRONG FORMAT IP OR DOMAIN: Invalid IP range"))
        
        # Check if it's a domain
        elif not input_str.replace('.', '').isdigit():
            try:
                resolved_ip = socket.gethostbyname(input_str)
                network = ipaddress.ip_network(f"{resolved_ip}/24", strict=False)
                results.append((resolved_ip, str(network.netmask)))
            except socket.gaierror:
                results.append((input_str, "Unknown."))
        
        # Check if it's a standalone IP
        else:
            try:
                ip = ipaddress.ip_address(input_str)
                network = ipaddress.ip_network(f"{input_str}/24", strict=False)
                results.append((str(ip), str(network.netmask)))
            except ValueError:
                results.append((input_str, "Unknown."))
        
        return results

    def calculate_subnet_mask():
        try:
            # User input with bright white color
            user_input = input("\033[1;97mEnter multiple IPs, ranges, or domains (space-separated): \033[0m").strip()
            inputs = user_input.split()  # Split by spaces
            
            all_results = []
            for input_item in inputs:
                all_results.extend(process_input(input_item))
            
            # Display results in bright white color
            print("\033[1;97mResults:\033[0m")
            for ip, subnet_mask in all_results:
                print(f"\033[1;97mIP/Domain: {ip}\nSubnet Mask: {subnet_mask}\n\033[0m")
        
        except Exception as e:
            print(f"\033[1;97mError: {e}\033[0m")

    # Correct the indentation of the function call
    calculate_subnet_mask()

# Run the main function
if __name__ == "__main__":
    main()
