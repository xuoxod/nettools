import dpkt
import socket
import argparse


def analyze_packet(packet_data):
    """Analyzes a raw packet and prints its contents in a readable format.

    Args:
        packet_data (bytes): The raw packet data.
    """

    try:
        eth = dpkt.ethernet.Ethernet(packet_data)
    except dpkt.dpkt.NeedData:
        print("Invalid packet data. Please provide valid raw packet data.")
        return

    print("Ethernet Frame:")
    print(f"  Source MAC: {eth.src.hex(':')}")
    print(f"  Destination MAC: {eth.dst.hex(':')}")
    print(f"  Type: 0x{eth.type:04x}")

    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        analyze_ip_packet(eth.data)
    else:
        print("  Payload: (Non-IP Packet - Not Analyzed)")
        print(f"    Data: {eth.data.hex()}")


def analyze_ip_packet(ip_data):
    """Analyzes an IP packet."""
    ip = dpkt.ip.IP(ip_data)
    print("\nIP Packet:")
    print(f"  Version: {ip.v}")
    print(f"  Header Length: {ip.hl * 4} bytes")
    print(f"  Type of Service: {ip.tos}")
    print(f"  Total Length: {ip.len} bytes")
    print(f"  Identification: {ip.id}")
    print(f"  Flags: {ip.flags}")
    print(f"  Fragment Offset: {ip.off}")
    print(f"  Time to Live (TTL): {ip.ttl}")
    print(f"  Protocol: {ip.p}")
    print(f"  Header Checksum: {ip.sum}")
    print(f"  Source IP: {socket.inet_ntoa(ip.src)}")
    print(f"  Destination IP: {socket.inet_ntoa(ip.dst)}")

    if ip.p == dpkt.ip.IP_PROTO_TCP:
        analyze_tcp_segment(ip.data)
    elif ip.p == dpkt.ip.IP_PROTO_UDP:
        analyze_udp_segment(ip.data)
    elif ip.p == dpkt.ip.IP_PROTO_ICMP:
        analyze_icmp_packet(ip.data)
    else:
        print("  Payload: (Unsupported Protocol - Not Analyzed)")
        print(f"    Data: {ip.data.hex()}")


def analyze_tcp_segment(tcp_data):
    """Analyzes a TCP segment."""
    tcp = dpkt.tcp.TCP(tcp_data)
    print("\nTCP Segment:")
    print(f"  Source Port: {tcp.sport}")
    print(f"  Destination Port: {tcp.dport}")
    print(f"  Sequence Number: {tcp.seq}")
    print(f"  Acknowledgment Number: {tcp.ack}")
    print(f"  Data Offset: {tcp.off * 4} bytes")
    print(f"  Flags:")
    print(f"    - FIN: {tcp.flags & dpkt.tcp.TH_FIN}")
    print(f"    - SYN: {tcp.flags & dpkt.tcp.TH_SYN}")
    print(f"    - RST: {tcp.flags & dpkt.tcp.TH_RST}")
    print(f"    - PSH: {tcp.flags & dpkt.tcp.TH_PUSH}")
    print(f"    - ACK: {tcp.flags & dpkt.tcp.TH_ACK}")
    print(f"    - URG: {tcp.flags & dpkt.tcp.TH_URG}")
    print(f"  Window Size: {tcp.win}")
    print(f"  Checksum: {tcp.sum}")
    print(f"  Urgent Pointer: {tcp.urp}")
    print(f"  Data: {tcp.data.hex()}")


def analyze_udp_segment(udp_data):
    """Analyzes a UDP segment."""
    udp = dpkt.udp.UDP(udp_data)
    print("\nUDP Segment:")
    print(f"  Source Port: {udp.sport}")
    print(f"  Destination Port: {udp.dport}")
    print(f"  Length: {udp.ulen} bytes")
    print(f"  Checksum: {udp.sum}")
    print(f"  Data: {udp.data.hex()}")


def analyze_icmp_packet(icmp_data):
    """Analyzes an ICMP packet."""
    icmp = dpkt.icmp.ICMP(icmp_data)
    print("\nICMP Packet:")
    print(f"  Type: {icmp.type}")
    print(f"  Code: {icmp.code}")
    print(f"  Checksum: {icmp.sum}")
    print(f"  Data: {icmp.data.hex()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a raw network packet.")
    parser.add_argument(
        "packet_data",
        help="The raw packet data as a hexadecimal string (e.g., 'ffff....')",
    )
    args = parser.parse_args()

    try:
        # Convert the hex string to bytes
        packet_data = bytes.fromhex(args.packet_data)
        analyze_packet(packet_data)
    except ValueError:
        print("Invalid packet data format. Please provide a valid hexadecimal string.")
