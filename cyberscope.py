import argparse
import netifaces
import time
import threading
import json
import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Packet

# Global dictionary to store captured packets, grouped by IP
captured_packets = {}
print_lock = threading.Lock()


def format_packet_data(packet):
    """Formats the packet data for display, handling potential errors."""
    output = []
    output.append("-" * 40)  # Separator line

    try:
        output.append(f"Timestamp: {datetime.fromtimestamp(packet.time)}")
    except Exception as e:
        output.append(f"Error getting timestamp: {e}")

    # Check if the IP layer is present before accessing its attributes
    if IP in packet:
        output.append(f"Source IP: {packet[IP].src}")
        output.append(f"Destination IP: {packet[IP].dst}")
        output.append(f"Protocol: {packet.sprintf('%IP.proto%')}")
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


def packet_callback(packet):
    """Callback function to process captured packets, handling potential errors."""
    with print_lock:
        try:
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

        except Exception as e:
            print(f"Error processing packet: {e}")


def capture_traffic(interface, count=0):
    """Captures network traffic on the specified interface, handling potential errors."""
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            count=count,
            store=False,
        )
    except PermissionError:
        print(
            "Error: Insufficient permissions to capture on interface. Try running with sudo."
        )
    except Exception as e:
        print(f"Error capturing traffic: {e}")


def save_to_csv(filename):
    """Saves the captured packets to a CSV file, handling potential errors."""
    try:
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
                    # Use a try-except block to handle potential errors when accessing packet layers
                    try:
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
                    except Exception as e:
                        print(f"Error writing packet data to CSV: {e}")
    except OSError as e:
        print(f"Error saving to CSV file: {e}")


def save_to_json(filename):
    """Saves the captured packets to a JSON file, handling potential errors."""
    output_data = {}
    for src_ip, packets in captured_packets.items():
        output_data[src_ip] = []
        for packet in packets:
            # Use a try-except block to handle potential errors when accessing packet layers
            try:
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
            except Exception as e:
                print(f"Error writing packet data to JSON: {e}")

    try:
        with open(filename, "w") as jsonfile:
            json.dump(output_data, jsonfile, indent=4)
    except OSError as e:
        print(f"Error saving to JSON file: {e}")


def main():
    """Main function to handle arguments and start the capture."""
    parser = argparse.ArgumentParser(
        description="""Capture and analyze network traffic on a specific interface.

        This script allows you to capture and view network packets in detail. 
        You can specify the network interface, the number of packets to capture, 
        and apply filters to focus on specific traffic.

        Examples:
        - Capture 100 packets on interface eth0:
            python cyberscope.py -i eth0 -c 100
        - Capture packets continuously on interface wlan0 and save to a CSV file:
            python cyberscope.py -i wlan0 -o output.csv -t csv
        - Capture packets continuously on the default interface and save to a JSON file:
            python cyberscope.py -o output.json -t json
        """,
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

    # Start the capture in a separate thread
    capture_thread = threading.Thread(
        target=capture_traffic, args=(args.interface, args.count)
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
