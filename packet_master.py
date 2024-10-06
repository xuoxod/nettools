#!/usr/bin/python3

import argparse
import socket
import threading
import textwrap
import struct
from colorama import Fore, Style
from scapy.all import *  # Import scapy for packet dissection

# Define colors
COLORS = {
    "white": Fore.WHITE,
    "light_yellow": Fore.LIGHTYELLOW_EX,
    "off_white": Style.DIM + Fore.WHITE,
    "very_pale_light_gold": "\033[38;5;223m",
    "pale_light_cyan": "\033[38;5;159m",
    "pale_light_green": "\033[38;5;108m",
    "light_green": Fore.LIGHTGREEN_EX,  # Added for IP/MAC labels
}


def get_packet_summary(packet):
    """Provides a human-readable summary of the packet."""
    try:
        # --- Layer 3 (Network Layer) ---
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_name = packet[IP].sprintf("%IP.proto%")  # Use Scapy's sprintf
        else:
            return "Unknown Packet Type"  # Handle non-IP packets

        # --- Layer 4 (Transport Layer) ---
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].sprintf("%TCP.flags%")
            summary = f"{protocol_name} ({src_ip}:{src_port} -> {dst_ip}:{dst_port}, Flags: {flags})"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            summary = f"{protocol_name} ({src_ip}:{src_port} -> {dst_ip}:{dst_port})"
        elif ICMP in packet:
            summary = f"{protocol_name} (Type: {packet[ICMP].type}, Code: {packet[ICMP].code})"
        else:
            summary = f"{protocol_name} (Unknown Transport Protocol)"

        # --- Application Layer (Partial Example) ---
        if packet.haslayer(DNS):
            summary += f" - DNS (Queries: {len(packet[DNS].qd)})"

        return summary

    except Exception as e:
        return f"Error parsing packet: {e}"


def colorize(text, color):
    """Colorizes the given text with the specified color."""
    if color in COLORS:
        return f"{COLORS[color]}{text}{Style.RESET_ALL}"
    else:
        return text


def packet_monitor(interface, color_scheme):
    """Monitors and displays incoming packets on the specified interface."""
    try:
        # Create a raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))

        print("-" * 120)  # Initial separator

        while True:
            # Receive packet data
            packet_data, addr = sock.recvfrom(65535)

            # Use scapy to parse the packet
            packet = Ether(packet_data)

            # Extract source MAC and IP addresses
            src_mac = packet[Ether].src
            src_ip, dst_ip = get_ip_from_packet(packet_data)  # Reuse existing function

            # Get human-readable summary
            summary = get_packet_summary(packet)

            # Colorize output
            output = (
                f"{colorize(f'[{src_mac}]', color_scheme.get('node', 'white'))}\n"  # MAC on its own line
                f"{colorize('Source IP:', 'light_green')}: {src_ip}\n"
                f"{colorize('Dest IP:', 'light_green')}: {dst_ip}\n"
                f"{colorize('Summary:', 'pale_light_green')}: {summary}\n"
                f"{colorize('Raw Hex:', 'off_white')}\n{bytes(packet).hex()}"  # Use bytes(packet).hex()
            )

            # Print output with wrapping and spacing
            print(textwrap.fill(output, width=120))
            print("\n\n\n")  # Add 3 blank lines between packets

    except PermissionError:
        print(
            f"Error: Insufficient permissions to capture packets on interface '{interface}'. "
            "Try running with sudo."
        )
    except socket.error as e:
        print(f"Error: Socket error - {e}")
    except KeyboardInterrupt:
        print("Exiting...")


def get_ip_from_packet(packet):
    """Extracts the source and destination IP addresses from a packet."""
    # Parse the IP header
    ip_header = packet[14:34]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4

    # Extract IP addresses based on IP version
    if version == 4:
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        return s_addr, d_addr
    elif version == 6:
        # Add IPv6 handling if needed
        return None, None
    else:
        return None, None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A robust packet monitor with colorized output.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "interface",
        help=textwrap.dedent(
            f"""
            {colorize('interface', 'white')}
                {colorize('The network interface to monitor (e.g., eth0, wlan0)', 'pale_light_green')}
            """
        ),
    )
    parser.add_argument(
        "-c",
        "--color",
        choices=COLORS.keys(),
        default="white",
        help=textwrap.dedent(
            f"""
            {colorize('-c, --color <color>', 'light_yellow')}
                {colorize('Color scheme for node identification (default: white)', 'pale_light_cyan')}
                {colorize('Available colors:', 'very_pale_light_gold')} {' '.join(COLORS.keys())}
            """
        ),
    )
    args = parser.parse_args()

    # Create color scheme dictionary
    color_scheme = {"node": args.color}

    # Start packet monitoring in a separate thread
    monitor_thread = threading.Thread(
        target=packet_monitor, args=(args.interface, color_scheme)
    )
    monitor_thread.daemon = True
    monitor_thread.start()

    # Keep the main thread alive
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Exiting...")
