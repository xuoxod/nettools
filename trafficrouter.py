#!/usr/bin/python3

"""
This script establishes an SSH tunnel to a remote host and forwards traffic
from a remote port to a local port, effectively routing traffic through
the SSH connection. It captures the traffic data and provides options to
save it to various file formats (txt, csv, html) along with a summary
of the traffic flow, including IP addresses, ports, direction, and timestamps.

Requirements:
- Python 3.6+
- paramiko library (install with: pip install paramiko)
- scapy library (install with: pip install scapy)

Usage:
  python traffic_router.py -r <remote_host> -u <username> [-p <password>] [-k <key_file>] -rp <remote_port> -lp <local_port> [-o <output_file>] [-f <format>]

Example:
  python traffic_router.py -r 192.168.1.100 -u john -rp 8080 -lp 80 -o traffic_data.html -f html

Options:
  -r, --remote_host   Required: The hostname or IP address of the remote host.
  -u, --username      Required: The username to use for SSH authentication.
  -p, --password      Optional: The password to use for SSH authentication.
  -k, --key_file      Optional: The path to the private key file for SSH key-based authentication (default).
  -rp, --remote_port  Required: The remote port to forward traffic from.
  -lp, --local_port   Required: The local port to forward traffic to.
  -o, --output_file   Optional: The path to the output file to save traffic data.
  -f, --format        Optional: The output format for traffic data (txt, csv, html). Default: txt

Note:
- Ensure that port forwarding is enabled on the SSH server.
- The script captures traffic while the tunnel is active. Press Ctrl+C to stop capturing and exit.
"""

import argparse
import socket
import threading
import time
import csv
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

import paramiko
from scapy.all import *


class TrafficData:
    """Stores and formats captured traffic data."""

    def __init__(self):
        self.data = []

    def add_entry(self, packet, direction):
        """Adds a new traffic entry to the data list."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        src_ip = dst_ip = src_port = dst_port = src_mac = dst_mac = "N/A"

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        self.data.append(
            {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "direction": direction,
            }
        )

    def to_string(self):
        """Returns a formatted string representation of the traffic data."""
        output = "Captured Traffic Data:\n\n"
        for entry in self.data:
            output += f"Timestamp: {entry['timestamp']}\n"
            output += (
                f"Source: {entry['src_ip']}:{entry['src_port']} ({entry['src_mac']})\n"
            )
            output += f"Destination: {entry['dst_ip']}:{entry['dst_port']} ({entry['dst_mac']})\n"
            output += f"Direction: {entry['direction']}\n\n"
        return output

    def to_csv(self, filename):
        """Saves the traffic data to a CSV file."""
        with open(filename, "w", newline="") as csvfile:
            fieldnames = [
                "timestamp",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "src_mac",
                "dst_mac",
                "direction",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.data)

    def to_html(self, filename):
        """Saves the traffic data to an HTML file using a Jinja2 template."""
        env = Environment(loader=FileSystemLoader("."))
        template = env.get_template("traffic_template.html")
        html_output = template.render(traffic_data=self.data)
        with open(filename, "w") as f:
            f.write(html_output)


def packet_capture(interface, traffic_data, direction):
    """Captures network packets on the specified interface."""
    sniff(
        iface=interface,
        prn=lambda packet: traffic_data.add_entry(packet, direction),
        store=False,
    )


def start_traffic_capture(local_port, traffic_data):
    """Starts listeners for incoming and outgoing traffic."""
    # Create threads for capturing incoming and outgoing traffic
    incoming_thread = threading.Thread(
        target=packet_capture, args=("lo", traffic_data, "Incoming")
    )
    outgoing_thread = threading.Thread(
        target=packet_capture, args=("eth0", traffic_data, "Outgoing")
    )

    # Start the capture threads
    incoming_thread.start()
    outgoing_thread.start()

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping traffic capture...")


def main():
    """Parses arguments and establishes the SSH tunnel."""
    parser = argparse.ArgumentParser(
        description="SSH Traffic Router and Data Capture Tool"
    )
    parser.add_argument("-r", "--remote_host", required=True, help="Remote hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password")
    parser.add_argument(
        "-k", "--key_file", default=None, help="Path to SSH private key file"
    )
    parser.add_argument(
        "-rp", "--remote_port", required=True, type=int, help="Remote port"
    )
    parser.add_argument(
        "-lp", "--local_port", required=True, type=int, help="Local port"
    )
    parser.add_argument("-o", "--output_file", help="Output file to save traffic data")
    parser.add_argument(
        "-f",
        "--format",
        choices=["txt", "csv", "html"],
        default="txt",
        help="Output format for traffic data (txt, csv, html)",
    )
    args = parser.parse_args()

    # Create an SSH client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Connect to the remote host
    try:
        if args.key_file:
            client.connect(
                args.remote_host,
                username=args.username,
                key_filename=args.key_file,
            )
        elif args.password:
            client.connect(
                args.remote_host,
                username=args.username,
                password=args.password,
            )
        else:
            print(
                "Error: No authentication method provided. Please provide either a password (-p) or a key file (-k)."
            )
            return

        print(
            f"SSH tunnel established to {args.remote_host} on port {args.remote_port}"
        )

        # Start traffic capture
        traffic_data = TrafficData()
        capture_thread = threading.Thread(
            target=start_traffic_capture, args=(args.local_port, traffic_data)
        )
        capture_thread.daemon = True
        capture_thread.start()

        # Start port forwarding
        try:
            local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            local_socket.bind(("", args.local_port))
            local_socket.listen(5)
            client.forward_tcp(
                "localhost", args.remote_port, local_socket, handler=None
            )
            # Keep the tunnel open
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nClosing SSH tunnel...")
        finally:
            # Save captured traffic data
            if args.output_file:
                if args.format == "txt":
                    with open(args.output_file, "w") as f:
                        f.write(traffic_data.to_string())
                elif args.format == "csv":
                    traffic_data.to_csv(args.output_file)
                elif args.format == "html":
                    traffic_data.to_html(args.output_file)
                print(f"Traffic data saved to {args.output_file}")

            client.close()

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
