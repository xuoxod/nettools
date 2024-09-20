import socket
import argparse
import struct


def send_packet(
    dest_ip="127.0.0.1", dest_port=80, protocol="tcp", payload=b"", eth_header=None
):
    """Sends a raw packet with the specified parameters.

    Args:
        dest_ip (str): Destination IP address (e.g., "192.168.1.10"). Defaults to "127.0.0.1".
        dest_port (int): Destination port number. Defaults to 80.
        protocol (str): Protocol (e.g., "tcp", "udp", "icmp"). Defaults to "tcp".
        payload (bytes): Raw packet payload. Defaults to b"".
        eth_header (bytes, optional): Ethernet header (if needed).
                                        Defaults to None.

    Raises:
        ValueError: If an invalid protocol is provided.
    """

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        print("Error: You need root privileges to send raw packets.")
        exit(1)

    # Construct IP header
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # Version and IHL
        0,  # Type of Service
        20 + len(payload),  # Total length
        0,  # Identification
        0,  # Flags and Fragment Offset
        64,  # Time to Live (TTL)
        (
            socket.IPPROTO_TCP
            if protocol.lower() == "tcp"
            else (
                socket.IPPROTO_UDP if protocol.lower() == "udp" else socket.IPPROTO_ICMP
            )
        ),  # Protocol
        0,  # Header checksum (calculated later)
        socket.inet_aton(dest_ip),  # Destination IP
        socket.inet_aton("192.168.1.5"),  # Source IP (replace with your IP)
    )

    # Calculate IP header checksum
    checksum = calculate_checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # Version and IHL
        0,  # Type of Service
        20 + len(payload),  # Total length
        0,  # Identification
        0,  # Flags and Fragment Offset
        64,  # Time to Live (TTL)
        (
            socket.IPPROTO_TCP
            if protocol.lower() == "tcp"
            else (
                socket.IPPROTO_UDP if protocol.lower() == "udp" else socket.IPPROTO_ICMP
            )
        ),  # Protocol
        checksum,  # Header checksum
        socket.inet_aton(dest_ip),  # Destination IP
        socket.inet_aton("192.168.1.5"),  # Source IP (replace with your IP)
    )

    # Combine headers and payload
    packet = ip_header + payload

    # Send the packet
    s.sendto(packet, (dest_ip, dest_port))


def calculate_checksum(header):
    """Calculates the checksum for IP and TCP/UDP headers.

    Args:
        header (bytes): The header data.

    Returns:
        int: The calculated checksum.
    """

    s = 0
    for i in range(0, len(header), 2):
        w = (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
        s += w

    s = (s >> 16) + (s & 0xFFFF)
    s = ~s & 0xFFFF

    return s


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send custom network packets.")
    parser.add_argument("dest_ip", help="Destination IP address")
    parser.add_argument("dest_port", type=int, help="Destination port")
    parser.add_argument("protocol", help="Protocol (TCP, UDP, ICMP)")
    parser.add_argument(
        "-f",
        "--file",
        help="Path to file containing packet payload (raw bytes)",
    )
    parser.add_argument("-t", "--text", help="Text string to use as packet payload")
    args = parser.parse_args()

    if not args.file and not args.text:
        print("Error: Please provide either a file (-f) or text (-t) for the payload.")
        exit(1)

    if args.file:
        with open(args.file, "rb") as f:
            payload = f.read()
    else:
        payload = args.text.encode()

    send_packet(args.dest_ip, args.dest_port, args.protocol, payload)
    print(f"Packet sent to {args.dest_ip}:{args.dest_port} (Protocol: {args.protocol})")
