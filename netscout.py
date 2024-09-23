#!/usr/bin/env python3
"""
NetworkRecon ⚡: A blazing-fast network scanner built for speed and detail.

NetworkRecon efficiently scans target IP addresses, IP ranges, or CIDR blocks 
to discover active hosts and gather valuable network intelligence. 

Key Features:

- Flexible Target Specification: Scan single IPs, IP ranges, or CIDR blocks.
- Port Scanning Prowess: Define specific ports, port ranges, or scan common ports.
- Detailed Host Information: Retrieve IP addresses, MAC addresses, and vendor information.
- Structured Output: Save results in organized CSV or JSON formats for easy parsing.
- Real-time Console Output: Monitor scan progress and host discoveries in real-time.
- Performance Optimized: Leverages threading and asynchronous operations for maximum speed.

Usage:

  networkrecon.py [-h] [-i IP_ADDRESS] [-r IP_RANGE] [-c CIDR] [-p PORT] 
                   [-pr PORT_RANGE] [-o OUTPUT_FILE] [-f {csv,json}] 
                   [-v]

Example:

  networkrecon.py -c 192.168.1.0/24 -p 80,443 -o scan_results.json -v

Note: Running this script might require root privileges.
"""

import argparse
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import paramiko  # For potential future SSH-based tasks
from invoke import run  # For potential future system command execution
from fabric import Connection  # For potential future remote server interaction
import ipaddress
import threading
import asyncio
import csv
import json
import time

# ------------------------------------------------------------------------------
# Global Variables and Constants
# ------------------------------------------------------------------------------

# Define common ports to scan if no specific ports are provided
COMMON_PORTS = [22, 80, 443, 3389]

# Lock for thread-safe console output
print_lock = threading.Lock()

# ------------------------------------------------------------------------------
# Network Scanning Functions
# ------------------------------------------------------------------------------


async def scan_host(ip, ports):
    """Scans a single host on specified ports and returns host details."""
    try:
        # Use scapy to send ARP requests and receive responses
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=0)[0]

        # Process answered ARP requests
        for element in answered_list:
            # Get MAC address and potentially vendor info (using another library)
            mac = element[1].hwsrc
            # ... (Add vendor lookup logic here if needed)

            # Perform port scanning if ports are provided
            if ports:
                open_ports = scan_ports(ip, ports)
            else:
                open_ports = []

            # Acquire the print lock for thread-safe output
            with print_lock:
                print(f"IP: {ip}, MAC: {mac}, Open Ports: {open_ports}")

            # Return host details as a dictionary
            return {"ip": ip, "mac": mac, "open_ports": open_ports}
    except Exception as e:
        # Handle potential exceptions during scanning
        print(f"Error scanning {ip}: {e}")
        return None


async def scan_ports(ip, ports):
    """Scans a list of ports on a given IP address."""
    open_ports = []
    for port in ports:
        try:
            # Attempt a TCP connection to the port
            await asyncio.open_connection(ip, port)
            open_ports.append(port)
        except:
            pass
    return open_ports


# ------------------------------------------------------------------------------
# Helper Functions for IP Range and CIDR Handling
# ------------------------------------------------------------------------------


def expand_ip_range(ip_range):
    """Expands an IP range string into a list of IP addresses."""
    start_ip, end_ip = map(int, ip_range.split("-"))
    return [str(ipaddress.IPv4Address(ip)) for ip in range(start_ip, end_ip + 1)]


def get_ips_from_cidr(cidr):
    """Returns a list of IP addresses from a CIDR block."""
    return [str(ip) for ip in ipaddress.IPv4Network(cidr)]


# ------------------------------------------------------------------------------
# Data Output Functions
# ------------------------------------------------------------------------------


def save_to_csv(data, filename):
    """Saves scan results to a CSV file."""
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["ip", "mac", "open_ports"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for host_data in data:
            writer.writerow(host_data)


def save_to_json(data, filename):
    """Saves scan results to a JSON file."""
    with open(filename, "w") as jsonfile:
        json.dump(data, jsonfile, indent=4)


# ------------------------------------------------------------------------------
# Main Function
# ------------------------------------------------------------------------------


async def main():
    """Main function to handle arguments, scanning, and output."""

    # --------------------------------------------------------------------------
    # Argument Parsing
    # --------------------------------------------------------------------------

    parser = argparse.ArgumentParser(
        description="NetworkRecon: A fast and comprehensive network scanner.",
        formatter_class=argparse.RawTextHelpFormatter,  # Preserve formatting
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-i", "--ip_address", help="Single IP address to scan (e.g., 192.168.1.100)"
    )
    group.add_argument(
        "-r",
        "--ip_range",
        help="IP address range to scan (e.g., 192.168.1.10-192.168.1.20)",
    )
    group.add_argument("-c", "--cidr", help="CIDR block to scan (e.g., 192.168.1.0/24)")
    parser.add_argument(
        "-p",
        "--port",
        help="Specific port(s) to scan (comma-separated, e.g., 80,443)",
        default=COMMON_PORTS,
    )
    parser.add_argument("-pr", "--port_range", help="Port range to scan (e.g., 1-1000)")
    parser.add_argument(
        "-o",
        "--output_file",
        help="Output file to save results (e.g., scan_results.csv)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Output file format (csv or json)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    # --------------------------------------------------------------------------
    # Target IP Processing
    # --------------------------------------------------------------------------

    target_ips = []
    if args.ip_address:
        target_ips.append(args.ip_address)
    elif args.ip_range:
        target_ips.extend(expand_ip_range(args.ip_range))
    elif args.cidr:
        target_ips.extend(get_ips_from_cidr(args.cidr))

    # --------------------------------------------------------------------------
    # Port Processing
    # --------------------------------------------------------------------------

    ports = []
    if args.port:
        ports = [int(p) for p in args.port.split(",")]
    elif args.port_range:
        start_port, end_port = map(int, args.port_range.split("-"))
        ports = list(range(start_port, end_port + 1))

    # --------------------------------------------------------------------------
    # Network Scanning
    # --------------------------------------------------------------------------

    start_time = time.time()
    scan_results = []

    # Use asyncio.gather to run scan_host concurrently for each IP
    tasks = [scan_host(ip, ports) for ip in target_ips]
    results = await asyncio.gather(*tasks)

    # Filter out any None results (from errors)
    scan_results = [result for result in results if result is not None]

    end_time = time.time()

    # --------------------------------------------------------------------------
    # Output and Data Saving
    # --------------------------------------------------------------------------

    if args.verbose:
        print("\n----- Scan Results -----")
        for host_data in scan_results:
            print(host_data)

    if args.output_file:
        if args.format == "csv":
            save_to_csv(scan_results, args.output_file)
            print(f"\nResults saved to {args.output_file} (CSV)")
        elif args.format == "json":
            save_to_json(scan_results, args.output_file)
            print(f"\nResults saved to {args.output_file} (JSON)")

    print(f"\nScan completed in {end_time - start_time:.2f} seconds.")


# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    asyncio.run(main())
