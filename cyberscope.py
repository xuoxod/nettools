import argparse
import netifaces
import time
import threading
import json
import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Packet
import socket
import ipaddress
import requests  # Import requests for making HTTP requests

# Global dictionary to store captured packets
captured_packets = []
print_lock = threading.Lock()


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


def get_external_ip_info(ip_address):
    """Gets detailed information for external IP addresses using IP-API."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        response.raise_for_status()
        data = response.json()

        if data["status"] == "success":
            city = data.get("city", "N/A")
            country = data.get("country", "N/A")
            isp = data.get("isp", "N/A")
            org = data.get("org", "N/A")
            return f"{TextColors.OKCYAN}City: {city}, Country: {country}, ISP: {isp}, Organization: {org}{TextColors.ENDC}"
        else:
            return "External IP: No additional information found."

    except requests.exceptions.RequestException as e:
        return f"Error fetching IP details: {e}"


def format_packet_data(packet):
    """Formats the packet data for display."""
    output = []
    output.append("-" * 80)

    try:
        output.append(
            f"{TextColors.HEADER}{TextColors.BOLD}Timestamp:{TextColors.ENDC} {datetime.fromtimestamp(packet.time)}"
        )
    except Exception as e:
        output.append(f"Error getting timestamp: {e}")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        output.append(f"{TextColors.OKBLUE}Source IP:{TextColors.ENDC} {src_ip}")
        output.append(f"{TextColors.OKBLUE}Destination IP:{TextColors.ENDC} {dst_ip}")
        output.append(
            f"{TextColors.OKGREEN}Protocol:{TextColors.ENDC} {packet.sprintf('%IP.proto%')}"
        )

        if not is_local_ip(src_ip):
            output.append(get_external_ip_info(src_ip))

        if not is_local_ip(dst_ip):
            output.append(get_external_ip_info(dst_ip))

    else:
        output.append("IP Layer not found in packet.")

    if TCP in packet:
        output.append(f"Source Port: {packet[TCP].sport}")
        output.append(f"Destination Port: {packet[TCP].dport}")
    elif UDP in packet:
        output.append(f"Source Port: {packet[UDP].sport}")
        output.append(f"Destination Port: {packet[UDP].dport}")

    if ICMP in packet:
        output.append(f"ICMP Type: {packet[ICMP].type}")
        output.append(f"ICMP Code: {packet[ICMP].code}")

    if Raw in packet:
        try:
            payload = packet[Raw].load.decode("utf-8", errors="replace")
            output.append(f"Payload:\n{payload}")
        except Exception as e:
            output.append(f"Error decoding payload: {e}")

    return "\n".join(output)


def is_local_ip(ip_address):
    """Checks if an IP address is within the local network."""
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False


def process_packet(packet):
    """Processes each captured packet."""
    global captured_packets
    with print_lock:
        print(format_packet_data(packet))
    captured_packets.append(packet)


def packet_sniffer(interface, filter_exp):
    """Starts sniffing packets on the specified interface."""
    print(
        f"{TextColors.OKGREEN}[*]{TextColors.ENDC} Starting packet capture on interface: {interface}"
    )
    sniff(iface=interface, filter=filter_exp, prn=process_packet, store=False)


def analyze_traffic(output_format="console"):
    """Analyzes the captured traffic and provides insights."""
    global captured_packets

    if output_format == "console":
        print("\n----- Traffic Analysis -----")
        # Example: Print the number of packets per protocol
        protocol_counts = {}
        for packet in captured_packets:
            if IP in packet:
                protocol = packet.sprintf("%IP.proto%")
                if protocol in protocol_counts:
                    protocol_counts[protocol] += 1
                else:
                    protocol_counts[protocol] = 1
        for protocol, count in protocol_counts.items():
            print(f"Protocol: {protocol}, Packets: {count}")

    elif output_format == "json":
        # Example: Create a JSON structure for analysis
        analysis_data = {"packets": []}
        for packet in captured_packets:
            packet_info = {}
            if IP in packet:
                packet_info["src_ip"] = packet[IP].src
                packet_info["dst_ip"] = packet[IP].dst
                packet_info["protocol"] = packet.sprintf("%IP.proto%")
            analysis_data["packets"].append(packet_info)

        with open("traffic_analysis.json", "w") as f:
            json.dump(analysis_data, f, indent=4)
        print("Traffic analysis saved to traffic_analysis.json")

    elif output_format == "csv":
        # Example: Create a CSV file for analysis
        with open("traffic_analysis.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Source IP", "Destination IP", "Protocol"])
            for packet in captured_packets:
                if IP in packet:
                    writer.writerow(
                        [packet[IP].src, packet[IP].dst, packet.sprintf("%IP.proto%")]
                    )
        print("Traffic analysis saved to traffic_analysis.csv")


def get_network_interfaces():
    """Returns a list of available network interfaces."""
    return netifaces.interfaces()


def main():
    """Main function to handle arguments and start the program."""
    parser = argparse.ArgumentParser(
        description="CyberScope - A Network Packet Analyzer and Forensics Tool"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to sniff on (e.g., eth0, wlan0). "
        "Omit this argument to capture on all interfaces.",
        required=False,  # Make the interface argument optional
    )
    parser.add_argument(
        "-f",
        "--filter",
        help="BPF filter expression (e.g., 'tcp port 80')",
        default=None,
    )
    parser.add_argument(
        "-a",
        "--analyze",
        help="Analyze captured traffic (options: console, json, csv)",
        default=None,
    )
    args = parser.parse_args()

    # Get available interfaces
    available_interfaces = get_network_interfaces()

    # Capture on all interfaces if none is specified
    if not args.interface:
        interfaces_to_sniff = available_interfaces
    else:
        # Check if the specified interface exists
        if args.interface not in available_interfaces:
            print(
                f"{TextColors.FAIL}[-]{TextColors.ENDC} Interface '{args.interface}' not found. Available interfaces: {', '.join(available_interfaces)}"
            )
            exit(1)
        interfaces_to_sniff = [args.interface]

    # Start a sniffer thread for each interface
    sniffer_threads = []
    for interface in interfaces_to_sniff:
        sniffer_thread = threading.Thread(
            target=packet_sniffer, args=(interface, args.filter)
        )
        sniffer_thread.daemon = True
        sniffer_thread.start()
        sniffer_threads.append(sniffer_thread)

    # Keep the main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{TextColors.WARNING}[*]{TextColors.ENDC} Exiting...")

    # Perform traffic analysis if requested
    if args.analyze:
        analyze_traffic(args.analyze)


if __name__ == "__main__":
    main()
