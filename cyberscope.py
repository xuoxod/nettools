import argparse
import netifaces
import time
import threading
import json
import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Define common filter expressions with descriptions
COMMON_FILTERS = {
    1: ("tcp port 80", "Capture HTTP traffic"),
    2: ("tcp port 443", "Capture HTTPS traffic"),
    3: ("udp port 53", "Capture DNS traffic"),
    4: ("tcp port 22", "Capture SSH traffic"),
    5: ("tcp port 21", "Capture FTP traffic"),
    6: ("tcp port 25", "Capture SMTP traffic"),
    7: ("tcp port 110", "Capture POP3 traffic"),
    8: ("tcp port 143", "Capture IMAP traffic"),
}

# Global dictionary to store captured packets, grouped by IP
captured_packets = {}
print_lock = threading.Lock()


def format_packet_data(packet):
    """Formats the packet data for display."""
    output = []
    output.append("-" * 40)  # Separator line
    output.append(f"Timestamp: {datetime.fromtimestamp(packet.time)}")
    output.append(f"Source IP: {packet[IP].src}")
    output.append(f"Destination IP: {packet[IP].dst}")
    output.append(f"Protocol: {packet.sprintf('%IP.proto%')}")

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
        payload = packet[Raw].load.decode("utf-8", errors="replace")
        output.append(f"Payload:\n{payload}")

    return "\n".join(output)


def packet_callback(packet):
    """Callback function to process captured packets."""
    with print_lock:
        # Extract relevant information from the packet
        src_ip = packet[IP].src if IP in packet else "Unknown"
        dst_ip = packet[IP].dst if IP in packet else "Unknown"
        protocol = packet.sprintf("%IP.proto%")

        # Group packets by source IP
        if src_ip not in captured_packets:
            captured_packets[src_ip] = []
        captured_packets[src_ip].append(packet)

        # Print the formatted packet information to the console
        print(format_packet_data(packet))
        print("-" * 40)  # Separator line


def capture_traffic(interface, filter_expression, count=0):
    """Captures network traffic on the specified interface."""
    sniff(
        iface=interface,
        filter=filter_expression,
        prn=packet_callback,
        count=count,
        store=False,
    )


def save_to_csv(filename):
    """Saves the captured packets to a CSV file."""
    with open(filename, "w", newline="") as csvfile:
        fieldnames = [
            "timestamp",
            "src_ip",
            "dst_ip",
            "protocol",
            "src_port",
            "dst_port",
            "icmp_type",
            "icmp_code",
            "payload",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for src_ip, packets in captured_packets.items():
            for packet in packets:
                data = {
                    "timestamp": datetime.fromtimestamp(packet.time),
                    "src_ip": packet[IP].src if IP in packet else "Unknown",
                    "dst_ip": packet[IP].dst if IP in packet else "Unknown",
                    "protocol": packet.sprintf("%IP.proto%"),
                    "src_port": packet[TCP].sport if TCP in packet else "N/A",
                    "dst_port": packet[TCP].dport if TCP in packet else "N/A",
                    "icmp_type": packet[ICMP].type if ICMP in packet else "N/A",
                    "icmp_code": packet[ICMP].code if ICMP in packet else "N/A",
                    "payload": (
                        packet[Raw].load.decode("utf-8", errors="replace")
                        if Raw in packet
                        else "N/A"
                    ),
                }
                writer.writerow(data)


def save_to_json(filename):
    """Saves the captured packets to a JSON file."""
    output_data = {}
    for src_ip, packets in captured_packets.items():
        output_data[src_ip] = []
        for packet in packets:
            data = {
                "timestamp": datetime.fromtimestamp(packet.time).isoformat(),
                "src_ip": packet[IP].src if IP in packet else "Unknown",
                "dst_ip": packet[IP].dst if IP in packet else "Unknown",
                "protocol": packet.sprintf("%IP.proto%"),
                "src_port": packet[TCP].sport if TCP in packet else "N/A",
                "dst_port": packet[TCP].dport if TCP in packet else "N/A",
                "icmp_type": packet[ICMP].type if ICMP in packet else "N/A",
                "icmp_code": packet[ICMP].code if ICMP in packet else "N/A",
                "payload": (
                    packet[Raw].load.decode("utf-8", errors="replace")
                    if Raw in packet
                    else "N/A"
                ),
            }
            output_data[src_ip].append(data)

    with open(filename, "w") as jsonfile:
        json.dump(output_data, jsonfile, indent=4)


def main():
    """Main function to handle arguments and start the capture."""
    parser = argparse.ArgumentParser(
        description="""Capture and analyze network traffic on a specific interface.

        This script allows you to capture and view network packets in detail. 
        You can specify the network interface, the number of packets to capture, 
        and apply filters to focus on specific traffic.""",
        formatter_class=argparse.RawTextHelpFormatter,  # Preserve formatting
    )

    # Get default interface
    default_interface = (
        netifaces.gateways()["default"][netifaces.AF_INET][1]
        if netifaces.gateways()
        else "No default gateway found"
    )

    # Get available interfaces
    interfaces = netifaces.interfaces()

    parser.add_argument(
        "-i",
        "--interface",
        help="""Network interface to capture on (e.g., eth0, wlan0).
        Defaults to the system's default interface for communication (%(default)s) if not provided."""
        % {"default": default_interface},
        choices=interfaces,
        default=default_interface,
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 for continuous capture). Defaults to 0.",
    )
    parser.add_argument(
        "-f",
        "--filter",
        type=int,
        choices=list(COMMON_FILTERS.keys()),
        default=1,  # Default to the most common filter (HTTP)
        help="""Choose a predefined filter by its number:
        %s"""
        % "\n".join([f"  {key}: {value[1]}" for key, value in COMMON_FILTERS.items()]),
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional output file path (e.g., output.csv, output.json). "
        "If not provided, output will be printed to the console only.",
    )
    parser.add_argument(
        "-t",
        "--type",
        choices=["csv", "json"],
        help="Output file type (csv or json). Required if -o is specified.",
    )
    args = parser.parse_args()

    # Get the filter expression from the chosen filter
    filter_expression = COMMON_FILTERS[args.filter][0]

    # Start the capture in a separate thread
    capture_thread = threading.Thread(
        target=capture_traffic, args=(args.interface, filter_expression, args.count)
    )
    capture_thread.daemon = True
    capture_thread.start()

    try:
        while True:
            # Keep the main thread alive to allow capturing
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nCapture stopped.")

    # Save the output to a file if requested
    if args.output:
        if args.type == "csv":
            save_to_csv(args.output)
            print(f"Output saved to {args.output} (CSV)")
        elif args.type == "json":
            save_to_json(args.output)
            print(f"Output saved to {args.output} (JSON)")
        else:
            print("Error: Please specify the output type (-t csv or -t json).")


if __name__ == "__main__":
    main()
