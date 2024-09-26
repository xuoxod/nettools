#!/usr/bin/python3
import argparse
import socket
import csv
import json
from scapy.all import *
import threading


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


# Predefined common ports and protocols
COMMON_PORTS = {
    "ssh": 22,
    "http": 80,
    "https": 443,
    "rdp": 3389,
    "dns": 53,
    "smtp": 25,
    "ftp": 21,
}
COMMON_PROTOCOLS = ["tcp", "udp", "icmp"]


def get_mac_address(ip_address):
    """Tries to get the MAC address for an IP address using ARP."""
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
            timeout=2,
            verbose=False,
        )
        if ans:
            return ans[0][1].hwsrc
        else:
            return None
    except Exception as e:
        print(f"{TextColors.FAIL}Error getting MAC address: {e}{TextColors.ENDC}")
        return None


def save_output(data, output_format="html", filename="output.html"):
    """Saves the output data to a file in the specified format."""
    try:
        if output_format.lower() == "csv":
            with open(filename, "a", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
                # Write header only if file is empty
                if csvfile.tell() == 0:
                    writer.writeheader()
                writer.writerows(data)
        elif output_format.lower() == "html":
            with open(filename, "w") as htmlfile:
                htmlfile.write("<html><body><table>\n")
                htmlfile.write("<tr>")  # Start header row

                # Define colors for each column (you can customize these)
                column_colors = [
                    "#ADD8E6",  # Light Blue
                    "#90EE90",  # Light Green
                    "#FFFFE0",  # Light Yellow
                    "#FFC0CB",  # Pink
                    "#D3D3D3",  # Light Gray
                    "#FFA07A",  # Light Salmon
                    "#FAFAD2",  # Light Goldenrod Yellow
                    "#E0FFFF",  # Light Cyan
                    "#FFDAB9",  # Peach Puff
                ]

                for col_index, fieldname in enumerate(data[0].keys()):
                    htmlfile.write(
                        f'<th style="background-color: {column_colors[col_index % len(column_colors)]};">{fieldname}</th>'
                    )
                htmlfile.write("</tr>\n")  # End header row

                for row in data:
                    htmlfile.write("<tr>")
                    for col_index, value in enumerate(row.values()):
                        htmlfile.write(
                            f'<td style="background-color: {column_colors[col_index % len(column_colors)]};">{value}</td>'
                        )
                    htmlfile.write("</tr>\n")
                htmlfile.write("</table></body></html>")
        elif output_format.lower() == "json":
            with open(filename, "r+") as jsonfile:
                try:
                    # Try to load existing data
                    existing_data = json.load(jsonfile)
                except json.JSONDecodeError:
                    # If file is empty or invalid JSON, start with an empty list
                    existing_data = []
                # Append new data
                existing_data.extend(data)  # Use extend for list of dictionaries
                # Move to the beginning of the file
                jsonfile.seek(0)
                # Write the entire data back
                json.dump(existing_data, jsonfile, indent=4)
                # Truncate in case the new data is shorter than the old data
                jsonfile.truncate()
        else:
            print(
                f"{TextColors.FAIL}Error: Invalid output format specified.{TextColors.ENDC}"
            )
    except Exception as e:
        print(f"{TextColors.FAIL}Error saving output to file: {e}{TextColors.ENDC}")


def send_custom_packet(
    dst_ip,
    dst_port=None,
    payload=None,
    protocol="icmp",
    output_format=None,
    output_file=None,
):
    """Sends a custom packet and handles responses."""

    try:
        # Validate IP address
        socket.inet_aton(dst_ip)
    except socket.error:
        print(
            f"{TextColors.FAIL}Error: Invalid destination IP address: {dst_ip}{TextColors.ENDC}"
        )
        return

    # Determine port if not provided
    if dst_port is None:
        if protocol.lower() == "tcp":
            dst_port = 80  # Default to port 80 (HTTP) for TCP
        elif protocol.lower() == "udp":
            dst_port = 53  # Default to port 53 (DNS) for UDP
        else:
            dst_port = 0  # ICMP doesn't use a port number

    # Create packet based on selected protocol
    if protocol.lower() == "tcp":
        packet = IP(dst=dst_ip) / TCP(dport=dst_port, flags="S")  # SYN flag for reply
    elif protocol.lower() == "udp":
        packet = IP(dst=dst_ip) / UDP(dport=dst_port)
    elif protocol.lower() == "icmp":
        packet = IP(dst=dst_ip) / ICMP()
    else:
        print(
            f"{TextColors.FAIL}Error: Invalid protocol specified. Choose from: {', '.join(COMMON_PROTOCOLS)}{TextColors.ENDC}"
        )
        return

    # Add payload if provided
    if payload:
        packet = packet / Raw(load=payload.encode())

    # Send the packet and receive response
    print(
        f"{TextColors.OKGREEN}Sending {protocol.upper()} packet to {dst_ip}:{dst_port}...{TextColors.ENDC}"
    )
    send_recv = sr1(packet, timeout=2, verbose=False)  # Send and receive 1 packet

    # --- Output Handling ---
    if send_recv:
        print(
            f"{TextColors.OKGREEN}Response from {send_recv[IP].src}:{TextColors.ENDC}"
        )
        print(send_recv.show())  # Print detailed response to console

        # --- Prepare Simplified Data for File Output ---
        output_data = []
        unique_id = get_mac_address(dst_ip)
        if not unique_id:
            unique_id = dst_ip  # Use IP if MAC is not available

        # --- Protocol Mapping ---
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        protocol_name = protocol_map.get(send_recv[IP].proto, "Unknown")

        # --- Type of Service (TOS) Mapping (Example) ---
        tos_map = {
            0: "Routine",
            1: "Priority",
            2: "Immediate",
            # ... Add more TOS values and descriptions as needed
        }
        tos_description = tos_map.get(send_recv[IP].tos, "Unknown")

        # --- Console Output (Formatted and Colored) ---
        print(f"{TextColors.BOLD}Target:{TextColors.ENDC} {unique_id}")
        print(f"{TextColors.BOLD}Source IP:{TextColors.ENDC} {send_recv[IP].src}")
        print(f"{TextColors.BOLD}Destination IP:{TextColors.ENDC} {send_recv[IP].dst}")
        print(
            f"{TextColors.BOLD}Protocol:{TextColors.ENDC} {send_recv[IP].proto} ({protocol_name})"
        )
        print(f"{TextColors.BOLD}Checksum:{TextColors.ENDC} {send_recv[IP].chksum}")
        print(f"{TextColors.BOLD}ID:{TextColors.ENDC} {send_recv[IP].id}")
        print(f"{TextColors.BOLD}Length:{TextColors.ENDC} {send_recv[IP].len}")
        print(
            f"{TextColors.BOLD}Type of Service:{TextColors.ENDC} {send_recv[IP].tos} ({tos_description})"
        )
        print(
            f"{TextColors.BOLD}Packet Type:{TextColors.ENDC} {send_recv.getlayer(1).sprintf('%TCP.flags%') if protocol.lower() == 'tcp' else send_recv.getlayer(1).type}"
        )

        # --- Data for File Output (Includes both numerical and descriptive) ---
        output_data.append(
            {
                "Target": unique_id,
                "Source IP": send_recv[IP].src,
                "Destination IP": send_recv[IP].dst,
                "Protocol (Number)": send_recv[IP].proto,  # Numerical value
                "Protocol (Name)": protocol_name,  # Descriptive name
                "Checksum": send_recv[IP].chksum,
                "ID": send_recv[IP].id,
                "Length": send_recv[IP].len,
                "Type of Service (Number)": send_recv[IP].tos,  # Numerical value
                "Type of Service (Description)": tos_description,  # Description
                "Packet Type": (
                    send_recv.getlayer(1).sprintf("%TCP.flags%")
                    if protocol.lower() == "tcp"
                    else send_recv.getlayer(1).type
                ),
            }
        )

        # Save simplified output to file
        if output_format:
            if not output_file:
                if output_format.lower() == "csv":
                    output_file = "output.csv"
                elif output_format.lower() == "json":
                    output_file = "output.json"
                else:
                    output_file = "output.html"

            save_output(output_data, output_format, output_file)

    else:
        print(f"{TextColors.WARNING}No response received.{TextColors.ENDC}")
        # ... (No simplified output to save in this case)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Sends a custom network packet and logs the responses. 

        Examples:
        - Send an ICMP (ping) packet to 192.168.1.1:
            python targecon.py 192.168.1.1 
        - Send a TCP SYN packet to 10.0.0.5 on port 8080:
            python targecon.py 10.0.0.5 -p 8080 -prot tcp
        - Send a UDP packet with data "Hello" to 172.16.0.254 on port 53 and save output to JSON:
            python targecon.py 172.16.0.254 -p 53 -prot udp -d "Hello" -of json -o results.json
        """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("dst_ip", help="Destination IP address (e.g., 192.168.1.1)")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Destination port (optional, defaults vary by protocol, e.g., 80 for HTTP)",
    )
    parser.add_argument(
        "-d",
        "--data",
        help="Payload data to include in the packet (optional, e.g., 'Hello')",
    )
    parser.add_argument(
        "-prot",
        "--protocol",
        choices=COMMON_PROTOCOLS,
        default="icmp",
        help="Protocol to use (tcp, udp, icmp). Default: icmp",
    )
    parser.add_argument(
        "-of",
        "--output-format",
        choices=["csv", "json", "html"],
        help="Output format for saving results (csv, json, html). If provided, output will be saved to a file.",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        help="Optional output filename. If not provided, a default name will be used based on the format (e.g., output.csv, output.json).",
    )

    args = parser.parse_args()

    # Create and start the thread
    thread = threading.Thread(
        target=send_custom_packet,
        args=(
            args.dst_ip,
            args.port,
            args.data,
            args.protocol,
            args.output_format,
            args.output_file,
        ),
    )
    thread.start()
