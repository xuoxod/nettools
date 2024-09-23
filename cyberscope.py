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

# Global dictionary to store captured packets, grouped by IP
captured_packets = {}
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
        response.raise_for_status()  # Raise an exception for bad status codes
        data = response.json()

        if data["status"] == "success":
            city = data.get("city", "N/A")
            country = data.get("country", "N/A")
            isp = data.get("isp", "N/A")
            org = data.get("org", "N/A")  # Get organization info
            return f"{TextColors.OKCYAN}City: {city}, Country: {country}, ISP: {isp}, Organization: {org}{TextColors.ENDC}"
        else:
            return "External IP: No additional information found."

    except requests.exceptions.RequestException as e:
        return f"Error fetching IP details: {e}"


def format_packet_data(packet):
    """Formats the packet data for display, handling potential errors."""
    output = []
    output.append("-" * 80)  # Separator line

    try:
        output.append(
            f"{TextColors.HEADER}{TextColors.BOLD}Timestamp:{TextColors.ENDC} {datetime.fromtimestamp(packet.time)}"
        )
    except Exception as e:
        output.append(f"Error getting timestamp: {e}")

    # Check if the IP layer is present before accessing its attributes
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        output.append(f"{TextColors.OKBLUE}Source IP:{TextColors.ENDC} {src_ip}")
        output.append(f"{TextColors.OKBLUE}Destination IP:{TextColors.ENDC} {dst_ip}")
        output.append(
            f"{TextColors.OKGREEN}Protocol:{TextColors.ENDC} {packet.sprintf('%IP.proto%')}"
        )

        # Get external IP info if not in local network
        if not is_local_ip(src_ip):
            output.append(get_external_ip_info(src_ip))

        if not is_local_ip(dst_ip):
            output.append(get_external_ip_info(dst_ip))

    else:
        output.append("IP Layer not found in packet.")

    # Add port information if TCP or UDP
    if TCP in packet:
        output.append(f"Source Port: {packet[TCP].sport}")
        output.append(f"Destination Port: {packet[TCP].dport}")
    elif UDP in packet:
        output.append(f"Source Port: {packet[UDP].sport}")
        output.append(f"Destination Port: {packet[UDP].dport}")

    # Add ICMP type and code if ICMP
    if ICMP in packet:
        output.append(f"ICMP Type: {packet[ICMP].type}")
        output.append(f"ICMP Code: {packet[ICMP].code}")

    # Add payload information if available
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

    # Store packet data for analysis (example: group by IP)
    if IP in packet:
        ip_key = packet[IP].src
        if ip_key not in captured_packets:
            captured_packets[ip_key] = []
        captured_packets[ip_key].append(packet)


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
        # Example: Print the number of packets per IP
        print("\n----- Traffic Analysis -----")
        for ip, packets in captured_packets.items():
            print(f"IP: {ip}, Packets: {len(packets)}")

    elif output_format == "json":
        # Example: Create a JSON structure for analysis
        analysis_data = {}
        for ip, packets in captured_packets.items():
            analysis_data[ip] = {"packet_count": len(packets)}
        with open("traffic_analysis.json", "w") as f:
            json.dump(analysis_data, f, indent=4)
        print("Traffic analysis saved to traffic_analysis.json")

    elif output_format == "csv":
        # Example: Create a CSV file for analysis
        with open("traffic_analysis.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP Address", "Packet Count"])
            for ip, packets in captured_packets.items():
                writer.writerow([ip, len(packets)])
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
        help="Network interface to sniff on (e.g., eth0, wlan0)",
        required=True,
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

    # Check if the specified interface exists
    if args.interface not in available_interfaces:
        print(
            f"{TextColors.FAIL}[-]{TextColors.ENDC} Interface '{args.interface}' not found. Available interfaces: {', '.join(available_interfaces)}"
        )
        exit(1)

    # Start the packet sniffer in a separate thread
    sniffer_thread = threading.Thread(
        target=packet_sniffer, args=(args.interface, args.filter)
    )
    sniffer_thread.daemon = True  # Allow main thread to exit even if sniffer is running
    sniffer_thread.start()

    # Keep the main thread running to allow analysis
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
