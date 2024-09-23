#!/usr/bin/python3

import argparse
import socket
import sys
import subprocess
from datetime import datetime
from ipaddress import ip_network, ip_address
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import Scapy for efficient MAC address retrieval
from scapy.all import ARP, Ether, srp

# Import Jinja2 for HTML output templating
from jinja2 import Environment, FileSystemLoader

# Define a global lock for printing to avoid mixed output from threads
print_lock = threading.Lock()


def scan_single_port(ip_address, port):
    """
    Scans a single port on a single IP address and handles potential errors.

    Args:
        ip_address (str): The IP address to scan.
        port (int): The port number to scan.

    Returns:
        tuple or None: A tuple containing the port number and service name if the port is open,
                       otherwise None.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)  # Set a timeout for faster scanning
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                try:
                    service = socket.getservbyport(
                        port
                    )  # Get service name if available
                except OSError:
                    service = "Unknown"
                return port, service
    except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
        with print_lock:
            print(f"Error scanning {ip_address}:{port}: {e}")
    except KeyboardInterrupt:
        with print_lock:
            print("\nScan interrupted by user.")
        sys.exit()
    return None


def scan_ip(ip_address, ports, skip_ports=None):
    """
    Scans a single IP for a list of ports, optionally skipping
    specified ports or port ranges.

    Args:
        ip_address (str): The IP address to scan.
        ports (list): A list of port numbers to scan.
        skip_ports (list, optional): A list of port numbers or port ranges
                                     to skip (e.g., [22, 80, "100-110"]).

    Returns:
        tuple: A tuple containing the IP address and a list of open ports with their services.
    """
    open_ports = []
    for port in ports:
        if skip_ports:
            for skip_item in skip_ports:
                if isinstance(skip_item, str) and "-" in skip_item:
                    # Handle port range skipping
                    skip_start, skip_end = map(int, skip_item.split("-"))
                    if skip_start <= port <= skip_end:
                        continue  # Skip this port
                elif port == skip_item:
                    # Handle single port skipping
                    continue  # Skip this port
        result = scan_single_port(ip_address, port)
        if result:
            open_ports.append(result)
    return str(ip_address), open_ports


def get_mac_address(ip_address):
    """
    Retrieves the MAC address associated with an IP address using Scapy.

    Args:
        ip_address (str): The IP address to look up.

    Returns:
        str: The MAC address in the format "XX:XX:XX:XX:XX:XX",
             or "Unknown" if the MAC address cannot be resolved.
    """
    try:
        arp_request = ARP(pdst=ip_address)  # Create an ARP request packet
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Create an Ethernet broadcast packet
        packet = ether / arp_request  # Combine the packets
        result = srp(packet, timeout=2, verbose=0)[0]  # Send and receive the packet
        return result[0][1].hwsrc if result else "Unknown"  # Extract MAC address
    except Exception as e:
        print(f"Error getting MAC address for {ip_address}: {e}")
        return "Unknown"


def network_scan(
    targets,
    ports,
    skip_octets=None,
    skip_octet_ranges=None,
    skip_ports=None,
    max_threads=50,
):
    """
    Scans a network for open ports within a specified range using multithreading.

    Args:
        targets (list): A list of IP addresses and/or CIDR ranges to scan.
        ports (list): A list of port numbers to scan.
        skip_octets (list, optional): A list of last octets to skip.
        skip_octet_ranges (list, optional): A list of tuples representing octet ranges to skip.
        skip_ports (list, optional): A list of port numbers to skip.
        max_threads (int, optional): The maximum number of threads to use for scanning.

    Returns:
        dict: A dictionary where keys are IP addresses and values are dictionaries
              containing open ports with services and MAC addresses.
    """

    open_ports = {}
    all_ips = []

    for target in targets:
        try:
            # If the target is a network range, get all hosts
            for ip in ip_network(target, strict=False).hosts():
                last_octet = int(str(ip).split(".")[-1])

                if skip_octets and last_octet in skip_octets:
                    with print_lock:
                        print(f"Skipping {ip}...")
                    continue

                if skip_octet_ranges:
                    should_skip = False
                    for start, end in skip_octet_ranges:
                        if start <= last_octet <= end:
                            with print_lock:
                                print(f"Skipping {ip}...")
                            should_skip = True
                            break
                    if should_skip:
                        continue

                all_ips.append(str(ip))

        except ValueError:
            # If the target is a single IP, add it to the list
            try:
                ip_address(target)  # Validate IP address
                with print_lock:
                    print(f"Scanning {target}...")
                all_ips.append(target)
            except ValueError:
                with print_lock:
                    print(f"Invalid IP address: {target}")

    # Use threading to scan IP addresses concurrently
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_ip, ip, ports, skip_ports) for ip in all_ips]

        for future in as_completed(futures):
            ip, ports = future.result()
            if ports:
                mac = get_mac_address(ip)  # Get MAC address for the current IP
                open_ports[ip] = {"ports": ports, "mac": mac}
                with print_lock:
                    print(f"IP: {ip}, MAC: {mac}")  # Print IP and MAC to console
                    for port, service in ports:
                        print(f"  Port: {port}, Service: {service}")
                    print("")  # Add a blank line between nodes

    return open_ports


def save_results(results, output_format, output_file=None):
    """
    Saves the scan results to a file or prints them to the console in a format
    that is both human-readable and easily parsable by other programs.

    Args:
        results (dict): A dictionary of scan results (IP: [(port, service)]).
        output_format (str): The desired output format ('txt', 'csv', 'html', or None).
        output_file (str, optional): The path to the output file. If None, results
                                      are printed to the console.
    """

    if output_format is None:
        # Print to console if no output format is specified
        for ip, data in results.items():
            with print_lock:
                print(f"IP: {ip}, MAC: {data['mac']}")
                for port, service in data["ports"]:
                    print(f"  Port: {port}, Service: {service}")
        return

    if output_format.lower() == "txt":
        # Use a set to store unique lines and a list to maintain order
        content_set = set()
        content_list = []

        for ip, data in results.items():
            line = f"IP: {ip}\nMAC: {data['mac']}\n"
            if line not in content_set:
                content_set.add(line)
                content_list.append(line)
            if data["ports"]:
                for port, service in data["ports"]:
                    line = f"  Port: {port}, Service: {service}\n"
                    if line not in content_set:
                        content_set.add(line)
                        content_list.append(line)
            else:
                line = "  No open ports found.\n"
                if line not in content_set:
                    content_set.add(line)
                    content_list.append(line)
            content_list.append("\n")  # Add extra line for readability
        # Join the ordered list back into a string
        content = "".join(content_list)

    elif output_format.lower() == "csv":
        # Use a set to store unique lines and a list to maintain order
        content_set = set()
        content_list = ["IP,MAC Address,Port,Service\n"]  # Standard CSV header

        for ip, data in results.items():
            if data["ports"]:
                for port, service in data["ports"]:
                    line = f"{ip},{data['mac']},{port},{service}\n"
                    if line not in content_set:  # Check for duplicates
                        content_set.add(line)
                        content_list.append(line)  # Add to the ordered list
            else:
                line = f"{ip},{data['mac']},,No open ports found.\n"
                if line not in content_set:
                    content_set.add(line)
                    content_list.append(line)
        # Join the ordered list back into a string
        content = "".join(content_list)

    elif output_format.lower() == "html":
        # Load Jinja2 template for HTML output
        # trunk-ignore(bandit/B701)
        env = Environment(loader=FileSystemLoader("."))
        template = env.get_template("scan_results.html")
        content = template.render(scan_results=results, scan_time=datetime.now())

    else:
        print(f"Invalid output format: {output_format}")
        return

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(content)
            with print_lock:
                print(f"Results saved to {output_file}")
        except OSError as e:
            with print_lock:
                print(f"Error writing to file: {e}")
    else:
        with print_lock:
            print(content)


def parse_octet_ranges(range_string):
    """
    Parses a string of octet ranges into a list of tuples.

    Args:
        range_string (str): A string representing octet ranges (e.g., "1,5-10,20").

    Returns:
        list: A list of tuples representing the octet ranges.
    """

    octet_ranges = []
    ranges = range_string.split(",")
    for r in ranges:
        if "-" in r:
            start, end = map(int, r.split("-"))
            octet_ranges.append((start, end))
        else:
            octet_ranges.append((int(r), int(r)))
    return octet_ranges


def parse_ports(ports_string):
    """
    Parses a string of comma-separated port numbers and port ranges
    into a list of integers.

    Args:
        ports_string (str): A string representing ports and port ranges
                            (e.g., "22,80,100-110,443").

    Returns:
        list: A list of integers representing the ports to scan.
    """
    ports = []
    for item in ports_string.split(","):
        item = item.strip()
        if "-" in item:
            start, end = map(int, item.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(item))
    return ports


def parse_skip_ports(skip_ports_string):
    """
    Parses a string of comma-separated port numbers and port ranges
    into a list.

    Args:
        skip_ports_string (str): A string representing ports and port ranges
                                 (e.g., "22,80,100-110,443").

    Returns:
        list: A list of integers (for single ports) and strings (for ranges).
    """
    skip_ports = []
    if skip_ports_string:
        for item in skip_ports_string.split(","):
            item = item.strip()
            if "-" in item:
                skip_ports.append(item)  # Add range as a string
            else:
                skip_ports.append(int(item))  # Add single port as integer
    return skip_ports


def run_metasploit(msf_command):
    """Runs a Metasploit command using the `msfconsole` command-line interface."""
    try:
        # Construct the full command, including piping to stdout
        full_command = f"msfconsole -q -x '{msf_command}'"

        # Execute the command and capture output
        process = subprocess.Popen(
            full_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output, error = process.communicate()

        # Decode the output and error
        output = output.decode("utf-8")
        error = error.decode("utf-8")

        # Print output and errors (if any)
        if output:
            print(output)
        if error:
            print(f"Error: {error}")

    except FileNotFoundError:
        print(
            "Error: msfconsole not found. Please make sure Metasploit is installed and in your PATH."
        )
    except Exception as e:
        print(f"An error occurred while running the Metasploit command: {e}")


def main():
    """Main function to perform the scan and handle results."""
    parser = argparse.ArgumentParser(
        description="NetworkRecon - Enhanced Network Port Scanner with Metasploit Integration",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="One or more IP addresses or CIDR ranges to scan (e.g., 192.168.1.1 192.168.1.0/24 10.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help="Comma-separated list of ports or port ranges to scan (e.g., 22,80,100-110,443)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path (e.g., results.txt, results.csv, results.html). "
        "If not provided, results will be printed to the console.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["txt", "csv", "html"],
        help="Output format: 'txt', 'csv', or 'html'. "
        "Defaults to plain text output on the console if not specified.",
    )
    parser.add_argument(
        "-skip",
        "--skip_octets",
        help="Comma-separated list of last IP octets to skip (e.g., 1,5,10)",
    )
    parser.add_argument(
        "-skip-ranges",
        "--skip_octet_ranges",
        help="Comma-separated list of last IP octet ranges to skip (e.g., 1-5,10-20,30)",
    )
    parser.add_argument(
        "-skip-ports",
        "--skip_ports",
        help="Comma-separated list of port numbers to skip (e.g., 22,80,100-110,443)",
    )
    parser.add_argument(
        "-msf",
        "--metasploit",
        metavar="MSF_COMMAND",
        help="Run a Metasploit command after the scan (e.g., 'search ms17-010')",
    )
    args = parser.parse_args()

    # Split the skip_octets argument into a list
    skip_octets = (
        [int(o) for o in args.skip_octets.split(",")] if args.skip_octets else None
    )

    # Parse the skip_octet_ranges argument
    skip_octet_ranges = (
        parse_octet_ranges(args.skip_octet_ranges) if args.skip_octet_ranges else None
    )

    # Parse the ports argument
    ports = parse_ports(args.ports)

    # Parse the skip_ports argument
    skip_ports = parse_skip_ports(args.skip_ports)

    results = network_scan(
        args.targets,
        ports,
        skip_octets=skip_octets,
        skip_octet_ranges=skip_octet_ranges,
        skip_ports=skip_ports,
    )

    # Render the Jinja2 template
    # trunk-ignore(bandit/B701)
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("scan_results.html")
    html_output = template.render(scan_results=results, scan_time=datetime.now())

    # Save the rendered HTML to a file
    with open("scan_results.html", "w") as f:
        f.write(html_output)

    save_results(results, args.format, args.output)

    # Run Metasploit command if provided
    if args.metasploit:
        run_metasploit(args.metasploit)


if __name__ == "__main__":
    main()

"""This script performs a network port scan on the specified target IP addresses or CIDR ranges. It utilizes asynchronous I/O for faster scanning and provides options for output formatting, skipping specific IP ranges or ports, and running Metasploit commands after the scan.

Examples:

# Scan a single IP address for common ports:
python3 networkrecon.py 192.168.1.1 -p 22,80,443

# Scan a CIDR range, skipping the last octet 5:
python3 networkrecon.py 192.168.1.0/24 -p 1-1000 -skip 5

# Scan multiple targets, skipping a range of octets and specific ports:
python3 networkrecon.py 192.168.1.0/24 10.0.0.1 -p 1-65535 -skip-ranges 1-10,20-30 -skip-ports 22,80,443

# Scan and save results to a CSV file:
python3 networkrecon.py 192.168.1.0/24 -p 1-1000 -o results.csv -f csv

# Scan and run a Metasploit command:
python3 networkrecon.py 192.168.1.1 -p 445 -msf "search ms17-010"
"""
