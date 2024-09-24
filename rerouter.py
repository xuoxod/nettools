#!/usr/bin/env python3
from scapy.all import *

import sys
import argparse
import netifaces

# Store original forwarding state
original_forwarding = None


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

    # Limit payload display
    if Raw in packet:
        try:
            payload = packet[Raw].load.decode("utf-8", errors="replace")
            output.append(
                f"Payload (truncated):\n{payload[:100]}"
            )  # Show first 100 characters
        except Exception as e:
            output.append(f"Error decoding payload: {e}")

    return "\n".join(output)


def packet_callback(packet):
    global original_forwarding

    if IP in packet and (
        packet[IP].src == args.target_ip or packet[IP].dst == args.target_ip
    ):
        try:
            print(format_packet_data(packet))

            # Forward the packet
            send(packet, verbose=0)
        except Exception as e:
            print(f"{TextColors.FAIL}Error processing packet: {e}{TextColors.ENDC}")


def enable_ip_forwarding():
    global original_forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            original_forwarding = f.read().strip()
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
        print("IP forwarding enabled.")
    except FileNotFoundError:
        print(
            "Warning: Could not automatically enable IP forwarding. "
            "Please enable it manually if needed."
        )


def restore_ip_forwarding():
    global original_forwarding
    if original_forwarding is not None:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(original_forwarding + "\n")
            print("IP forwarding restored to original state.")
        except FileNotFoundError:
            print("Warning: Could not restore original IP forwarding state.")


def get_default_gateway_interface():
    """Returns the network interface associated with the default gateway."""
    gws = netifaces.gateways()
    return gws["default"][netifaces.AF_INET][1]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Reroute network traffic from a specific IP."
    )

    # Get the default gateway interface
    default_interface = get_default_gateway_interface()

    parser.add_argument(
        "target_ip", help="The IP address of the node to reroute traffic from"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help=f"The network interface to sniff on (e.g., eth0, wlan0). Default: {default_interface}",
        default=default_interface,  # Set default interface here
    )
    args = parser.parse_args()

    try:
        enable_ip_forwarding()

        print(
            f"Sniffing and rerouting traffic on interface: {args.interface} "
            f"from/to IP: {args.target_ip}"
        )

        # trunk-ignore(ruff/F405)
        sniff(iface=args.interface, prn=packet_callback, store=0)

    except KeyboardInterrupt:
        print("\nStopping traffic rerouting...")
    finally:
        restore_ip_forwarding()
