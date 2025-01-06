import sys
from ping_sweep import main as ping_sweep
from active_host_enum import main as active_host_enum
from subnet_mask import main as subnet_mask
from dns_lookup import main as dns_lookup
from traceout import main as traceout
from port_scanner import main as port_scanner
from ASCII_art import main as ASCII_art

GREEN = '\033[1;97m'
RESET = '\033[0m'


def main_menu():
    ASCII_art()
    while True:
        print(f"\n{GREEN}Select an option:{RESET}")
        print(f"{GREEN}1. Ping Sweep.{RESET}")
        print(f"{GREEN}2. Active Host Enumeration.{RESET}")
        print(f"{GREEN}3. Subnet Mask Discovery.{RESET}")
        print(f"{GREEN}4. DNS Lookup.{RESET}")
        print(f"{GREEN}5. Traceout.{RESET}")
        print(f"{GREEN}6. Port Scanner.{RESET}")
        print(f"{GREEN}7. Exit the Program.{RESET}")
        try:
            choice = int(input(f"{GREEN}Enter your choice: {RESET}").strip())
            if choice == 1:
                ping_sweep()
            elif choice == 2:
                active_host_enum()
            elif choice == 3:
                subnet_mask()
            elif choice == 4:
                dns_lookup()
            elif choice == 5:
                traceout()
            elif choice == 6:
                port_scanner()
            elif choice == 7:
                print(f"{GREEN}Program has been terminated :D{RESET}")
                sys.exit(0)
            else:
                print(f"{GREEN}Invalid choice. Please select a valid option:{RESET}")
        except ValueError:
            print(f"{GREEN}Invalid input. Please enter a number between 1 and 7.{RESET}")
        except KeyboardInterrupt:
            print(f"\n{GREEN}Program interrupted by user. Exiting gracefully.{RESET}")
            sys.exit(0)

if __name__ == "__main__":
    main_menu()
