from scapy.all import *
import argparse


def send_packet(target_ip, payload):
    """Sends a packet with the specified payload to the target IP address.

    Args:
        target_ip (str): The IP address of the target node.
        payload (str): The data to be sent in the packet.
    """

    # Create a raw IP packet
    packet = IP(dst=target_ip) / ICMP(type=8, code=0) / payload

    # Send the packet
    send(packet, verbose=0)

    print(f"Packet sent to {target_ip} with payload: {payload}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Send a packet with arbitrary payload to a target IP address."
    )
    parser.add_argument("target_ip", help="The IP address of the target node.")
    parser.add_argument("payload", help="The data to be sent in the packet.")

    args = parser.parse_args()

    send_packet(args.target_ip, args.payload)
