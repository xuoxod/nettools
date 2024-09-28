#!/usr/bin/python3

import argparse
import scapy.all as scapy
import ipaddress
import json
import csv
import random


# ANSI escape codes for text coloring
class TextColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


# Function to generate a random ANSI color code
def get_random_ansi_color():
    return f"\033[38;5;{random.randint(31, 37)}m"


def scan_network(net_address):
    """Sends ARP requests to a network and yields IP-MAC mappings as they are discovered."""

    arp_request = scapy.ARP(pdst=net_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        client_ip = element[1].psrc
        client_mac = element[1].hwsrc
        yield client_ip, client_mac


def print_results(results):
    """Prints the results to the console with color and formatting."""

    print(
        f"\n{TextColors.BOLD}{TextColors.OKGREEN}IP Address\t\tMAC Address{TextColors.ENDC}"
    )
    print(f"{TextColors.OKBLUE}-{TextColors.ENDC}" * 40)

    ip_colors = {}  # Store colors for each IP

    for ip, mac in results:
        if ip not in ip_colors:
            ip_colors[ip] = get_random_ansi_color()
        color = ip_colors[ip]
        print(f"{color}{ip}\t\t{mac}{TextColors.ENDC}")


def save_to_csv(results, filename="network_scan.csv"):
    """Saves the results to a CSV file."""

    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "MAC Address"])
        for ip, mac in results:
            writer.writerow([ip, mac])


def save_to_json(results, filename="network_scan.json"):
    """Saves the results to a JSON file."""

    data = []
    for ip, mac in results:
        data.append({"IP Address": ip, "MAC Address": mac})

    with open(filename, "w") as jsonfile:
        json.dump(data, jsonfile, indent=4)


def save_to_html(results, filename="network_scan.html"):
    """Saves the results to an HTML file with color and formatting."""

    html = """
    <!DOCTYPE html>
    <html>
    <head>
    <title>Network Scan Results</title>
    <style>
    body {font-family: monospace;}
    table {border-collapse: collapse; width: 50%;}
    th, td {border: 1px solid black; padding: 8px; text-align: left;}
    th {background-color: #f2f2f2;}
    </style>
    </head>
    <body>
    <h2>Network Scan Results</h2>
    <table>
    <tr>
    <th>IP Address</th>
    <th>MAC Address</th>
    </tr>
    """

    ip_colors = {}  # Store colors for each IP

    for ip, mac in results:
        if ip not in ip_colors:
            ip_colors[ip] = get_random_ansi_color()
        color = ip_colors[ip]
        html += f"<tr><td style='color:{color}'>{ip}</td><td>{mac}</td></tr>"

    html += """
    </table>
    </body>
    </html>
    """
    with open(filename, "w") as htmlfile:
        htmlfile.write(html)


def main():
    """Parses arguments and performs the network scan."""

    parser = argparse.ArgumentParser(description="Network Scanner using ARP requests")
    parser.add_argument(
        "-t",
        "--target",
        help="Target IP address or CIDR range (default: current network)",
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["csv", "json", "html"],
        help="Save output to file (csv, json, html)",
    )
    args = parser.parse_args()

    if args.target:
        try:
            ipaddress.ip_network(args.target)  # Check if it's a valid CIDR
            target_ip = args.target
        except ValueError:
            target_ip = args.target
    else:
        target_ip = (
            scapy.get_if_addr(scapy.conf.iface) + "/24"
        )  # Default to current network

    scanned_results = list(scan_network(target_ip))  # Store results for reuse

    print_results(scanned_results)

    if args.output:
        if args.output == "csv":
            save_to_csv(scanned_results, "network_scan.csv")
            print(
                f"\n{TextColors.OKGREEN}[+] Results saved to network_scan.csv{TextColors.ENDC}"
            )
        elif args.output == "json":
            save_to_json(scanned_results, "network_scan.json")
            print(
                f"\n{TextColors.OKGREEN}[+] Results saved to network_scan.json{TextColors.ENDC}"
            )
        elif args.output == "html":
            save_to_html(scanned_results, "network_scan.html")
            print(
                f"\n{TextColors.OKGREEN}[+] Results saved to network_scan.html{TextColors.ENDC}"
            )


if __name__ == "__main__":
    main()
