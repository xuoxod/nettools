#!/usr/bin/python3

import argparse
import csv
import socket
import threading
import time
import subprocess  # For running iptables commands
from queue import Queue
from ipaddress import ip_network, ip_address

from scapy.all import *

# Use a threading.Event to signal the blocking thread to stop
stop_blocking = threading.Event()


def scan_single_port(ip_address, port):
    """Scans a single port on a single IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                return port, service
    except (socket.gaierror, socket.error):
        pass
    return None


def scan_ip_range(ip_range, start_port, end_port, output_queue):
    """Scans a range of IPs and puts results in the output queue."""
    try:
        for ip in ip_network(ip_range, strict=False).hosts():
            print(f"Scanning {ip}...")
            open_ports = []
            for port in range(start_port, end_port + 1):
                result = scan_single_port(str(ip), port)
                if result:
                    open_ports.append(result)
            output_queue.put((str(ip), open_ports))
    except KeyboardInterrupt:
        print("\nScanning interrupted by user.")


def network_scan(target, start_port, end_port, output_file, num_threads=50):
    """
    Scans a network for open ports within a specified range,
    utilizing multithreading for speed, and saves the results
    to a CSV file. Handles both IPv4 and IPv6 addresses/ranges.
    """

    open_ports = {}
    output_queue = Queue()
    threads = []

    try:
        # Check if it's a single IP address
        ip_address(target)
        ip_chunks = [[target]]  # Single IP, no need to chunk
    except ValueError:
        # If it's not a single IP, treat it as a network range
        try:
            network = ip_network(target, strict=False)
            hosts = list(network.hosts())
            chunk_size = max(1, len(hosts) // num_threads)
            ip_chunks = [
                hosts[i : i + chunk_size] for i in range(0, len(hosts), chunk_size)
            ]
        except ValueError:
            print(f"Invalid IP address or range: {target}")
            return

    # Start threads for each IP chunk
    for ip_chunk in ip_chunks:
        # Pass target directly if it's a single IP
        if len(ip_chunk) == 1:
            thread = threading.Thread(
                target=scan_ip_range,
                args=(ip_chunk[0], start_port, end_port, output_queue),
            )
        else:  # It's a range, proceed as before
            thread = threading.Thread(
                target=scan_ip_range,
                args=(ip_chunk, start_port, end_port, output_queue),
            )
        threads.append(thread)
        thread.start()

    # Collect results from the queue
    try:
        for _ in range(len(ip_chunks)):
            ip, ports = output_queue.get()
            open_ports[ip] = ports
    except KeyboardInterrupt:
        print("\nCollecting scan results interrupted by user.")

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # Save results to CSV file
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Port", "Service"])
        for ip, ports in open_ports.items():
            if ports:
                for port, service in ports:
                    writer.writerow([ip, port, service])
            else:
                writer.writerow([ip, "", ""])

    print(f"Scan results saved to {output_file}")


def block_target(target_ips):
    """Blocks network traffic to and from the target IPs using iptables."""

    if not target_ips:
        print("No IP addresses to block.")
        return

    print("Blocking packets to and from the following IPs:")
    for ip in target_ips:
        print(f"  - {ip}")

    # Create iptables rules to DROP packets to/from target IPs
    for ip in target_ips:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
            stderr=subprocess.DEVNULL,
        )

    try:
        print("Blocking started. Press Ctrl+C to stop.")
        while not stop_blocking.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping blocking...")
    finally:
        # Remove the iptables rules when done
        for ip in target_ips:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                stderr=subprocess.DEVNULL,
            )
        print("Blocking stopped.")


def get_ips_to_block_from_user(csv_file):
    """Prompts the user to choose IPs from the CSV file to block."""

    ips_to_block = set()
    with open(csv_file, "r") as file:
        reader = csv.reader(file)
        next(reader)  # Skip header row
        for row in reader:
            ips_to_block.add(row[0])

    if not ips_to_block:
        print("No IP addresses found in the CSV file.")
        return ips_to_block

    print("\nDiscovered IPs:")
    for index, ip in enumerate(ips_to_block):
        print(f"{index + 1}. {ip}")

    while True:
        choice = input(
            "\nEnter the number(s) corresponding to the IP(s) you want to block "
            "(comma-separated, or 'all' to block all, or 'none' to block none): "
        )
        if choice.lower() == "all":
            return ips_to_block
        elif choice.lower() == "none":
            return set()  # Return an empty set
        else:
            try:
                choices = [int(x.strip()) for x in choice.split(",")]
                selected_ips = {list(ips_to_block)[i - 1] for i in choices}
                return selected_ips
            except (ValueError, IndexError):
                print("Invalid input. Please enter valid number(s), 'all', or 'none'.")


def main():
    """Main function to handle arguments and start network operations."""
    parser = argparse.ArgumentParser(
        description="Network Node Discovery and Packet Blocking Tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "target",
        help="The IP address, IPv6 address, or CIDR range to scan (e.g., 192.168.1.1, 2001:db8::1, or 192.168.1.0/24)",
    )
    parser.add_argument(
        "-sp",
        "--start_port",
        type=int,
        default=1,
        help="Starting port number for scanning (default: 1)",
    )
    parser.add_argument(
        "-ep",
        "--end_port",
        type=int,
        default=1024,
        help="Ending port number for scanning (default: 1024)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="scan_results.csv",
        help="Output CSV file path (default: scan_results.csv)",
    )
    args = parser.parse_args()

    try:
        print("Network Scan:")
        network_scan(args.target, args.start_port, args.end_port, args.output)

        target_ips_to_block = get_ips_to_block_from_user(args.output)

        if target_ips_to_block:
            block_thread = threading.Thread(
                target=block_target, args=(target_ips_to_block,)
            )
            block_thread.start()
            while True:
                time.sleep(1)
        else:
            print("No IP addresses selected for blocking.")
    except KeyboardInterrupt:
        print("\nExiting...")
        stop_blocking.set()  # Signal the blocking thread to stop
        if target_ips_to_block:
            block_thread.join()  # Wait for the thread to finish


if __name__ == "__main__":
    main()
