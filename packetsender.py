import argparse
import select
import socket
import struct


def send_packet(dest_ip, dest_port=80, protocol="tcp", payload=b"", eth_header=None):
    """Sends a raw packet with the specified parameters and receives a response.

    Args:
        dest_ip (str): Destination IP address (e.g., "192.168.1.10").
        dest_port (int): Destination port number. Defaults to 80.
        protocol (str): Protocol (e.g., "tcp", "udp", "icmp"). Defaults to "tcp".
        payload (bytes): Raw packet payload. Defaults to b"".
        eth_header (bytes, optional): Ethernet header (if needed).
                                        Defaults to None.

    Raises:
        ValueError: If an invalid protocol is provided.
        PermissionError: If run without root privileges.
        socket.error: For socket-related errors.
    """

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        # trunk-ignore(ruff/B904)
        raise PermissionError("Error: You need root privileges to send raw packets.")

    # Get source IP automatically
    source_ip = socket.gethostbyname(socket.gethostname())

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
                socket.IPPROTO_UDP
                if protocol.lower() == "udp"
                else (socket.IPPROTO_ICMP if protocol.lower() == "icmp" else None)
            )
        ),  # Protocol
        0,  # Header checksum (calculated later)
        socket.inet_aton(dest_ip),  # Destination IP
        socket.inet_aton(source_ip),  # Source IP
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
        socket.inet_aton(source_ip),  # Source IP
    )

    # Combine headers and payload
    packet = ip_header + payload

    try:
        # Send the packet
        s.sendto(packet, (dest_ip, dest_port))

        # Wait for a response (optional timeout)
        s.setblocking(False)
        timeout = 2
        ready = select.select([s], [], [], timeout)
        if ready[0]:
            data, addr = s.recvfrom(65535)
            print(f"Response from {addr}: {data.hex()}")
        else:
            print("No response received within the timeout.")

    except socket.error as e:
        raise socket.error(f"Error sending packet: {e}")
    finally:
        s.close()


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

    try:
        send_packet(args.dest_ip, args.dest_port, args.protocol, payload)
        print(
            f"Packet sent to {args.dest_ip}:{args.dest_port} (Protocol: {args.protocol})"
        )
    except (ValueError, PermissionError, socket.error) as e:
        print(e)
