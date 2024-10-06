#!/usr/bin/python3

import argparse
import socket
import struct
import subprocess
import threading
import netifaces
import logging

DEFAULT_PORT_RANGE = (1, 65535)
DEFAULT_INTERFACE = "eth0"
LOG_FILE = "portcullis.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def block_packet_iptables(
    interface, protocol, s_addr, d_addr, s_port=None, d_port=None
):
    """Blocks the packet using iptables.

    This function attempts to insert a rule into the iptables INPUT chain
    to drop packets matching the provided criteria. It logs the action taken
    and any errors encountered.

    Args:
        interface (str): The network interface to apply the rule to.
        protocol (str): The protocol of the packet (e.g., 'tcp', 'udp', 'icmp').
        s_addr (str, optional): Source IP address. Defaults to None.
        d_addr (str, optional): Destination IP address. Defaults to None.
        s_port (int, optional): Source port. Defaults to None.
        d_port (int, optional): Destination port. Defaults to None.
    """
    cmd = [
        "iptables",
        "-I",
        "INPUT",
        "-i",
        interface,
        "-p",
        protocol,
    ]
    if s_addr:
        cmd.extend(["-s", s_addr])
    if d_addr:
        cmd.extend(["-d", d_addr])
    if s_port:
        cmd.extend(["--sport", str(s_port)])
    if d_port:
        cmd.extend(["--dport", str(d_port)])
    cmd.append("-j", "DROP")

    try:
        subprocess.check_call(cmd)
        logging.info(f"Blocked packet: {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error blocking packet: {e}")


def remove_rule_iptables(
    interface, protocol, s_addr=None, d_addr=None, s_port=None, d_port=None
):
    """Removes a specific iptables rule.

    This function attempts to delete a rule from the iptables INPUT chain
    matching the provided criteria. It logs the action taken and any errors
    encountered.

    Args:
        interface (str): The network interface the rule applies to.
        protocol (str): The protocol of the packet (e.g., 'tcp', 'udp', 'icmp').
        s_addr (str, optional): Source IP address. Defaults to None.
        d_addr (str, optional): Destination IP address. Defaults to None.
        s_port (int, optional): Source port. Defaults to None.
        d_port (int, optional): Destination port. Defaults to None.
    """
    cmd = [
        "iptables",
        "-D",
        "INPUT",
        "-i",
        interface,
        "-p",
        protocol,
    ]
    if s_addr:
        cmd.extend(["-s", s_addr])
    if d_addr:
        cmd.extend(["-d", d_addr])
    if s_port:
        cmd.extend(["--sport", str(s_port)])
    if d_port:
        cmd.extend(["--dport", str(d_port)])
    cmd.append("-j", "DROP")

    try:
        subprocess.check_call(cmd)
        logging.info(f"Removed rule: {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error removing rule: {e}")


def list_rules_iptables():
    """Lists all iptables rules for the INPUT chain.

    This function executes 'iptables -L INPUT' to retrieve and print
    the current ruleset for the INPUT chain. Errors during execution
    are logged.
    """
    try:
        output = subprocess.check_output(["iptables", "-L", "INPUT"])
        logging.info("Listing iptables rules:")
        print(output.decode())
    except subprocess.CalledProcessError as e:
        logging.error(f"Error listing rules: {e}")


def flush_rules_iptables():
    """Flushes all rules in the iptables INPUT chain.

    This function executes 'iptables -F INPUT' to delete all existing
    rules within the INPUT chain. Errors during execution are logged.
    """
    try:
        subprocess.check_call(["iptables", "-F", "INPUT"])
        logging.info("Flushed all iptables rules.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error flushing rules: {e}")


def packet_listener(interface, ports, protocols, verbose=False):
    """Listens for and blocks packets based on specified criteria.

    This function creates a raw socket to capture network packets on the
    specified interface. It then filters packets based on the provided
    ports and protocols, blocking those that match using iptables.

    Args:
        interface (str): The network interface to listen on.
        ports (list): A list of port numbers to block.
        protocols (list): A list of protocol numbers to block.
        verbose (bool, optional): Whether to enable verbose logging.
              Defaults to False.
    """
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))

        if verbose:
            logging.info(
                f"Started packet blocking on interface: {interface}, Ports: {ports}, Protocols: {protocols}"
            )

        while True:
            packet, _ = s.recvfrom(65565)

            # Determine IP version
            version = (packet[0] >> 4) & 0xF

            if version == 4:  # IPv4
                ip_header = packet[0:20]
                iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])
                protocol = iph[6]
                header_length = (iph[0] & 0xF) * 4

            elif version == 6:  # IPv6
                ip_header = packet[0:40]
                iph = struct.unpack("!BBHHBB16s16s", ip_header)
                s_addr = socket.inet_ntop(socket.AF_INET6, iph[4])
                d_addr = socket.inet_ntop(socket.AF_INET6, iph[5])
                protocol = iph[3]
                header_length = 40

            else:
                continue

            # Filtering logic
            if protocol in protocols:
                tcp_udp_header = packet[header_length : header_length + 8]
                tcph = struct.unpack("!HH", tcp_udp_header)
                source_port = tcph[0]
                dest_port = tcph[1]

                if source_port in ports or dest_port in ports:
                    proto_name = socket.getprotobynumber(protocol)
                    block_packet_iptables(
                        interface,
                        proto_name,
                        s_addr,
                        d_addr,
                        source_port,
                        dest_port,
                    )

    except KeyboardInterrupt:
        logging.info("Packet blocking stopped by user.")
    except Exception as e:
        logging.error(f"Error in packet listener: {e}")


def parse_ports(port_str):
    """Parses a string of ports and port ranges into a list of integers.

    Args:
        port_str (str): A string containing comma-separated ports and port
                        ranges (e.g., '80,443,1000-2000').

    Returns:
        list: A list of integers representing the parsed port numbers.
    """
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        try:
            if "-" in part:
                start, end = map(int, part.split("-"))
                if start <= end:
                    ports.extend(range(start, end + 1))
                else:
                    logging.warning(f"Invalid port range: {part}")
            else:
                ports.append(int(part))
        except ValueError:
            logging.warning(f"Invalid port specification: {part}")
    return ports


def get_network_interfaces():
    """Returns a list of available network interface names.

    Returns:
        list: A list of strings representing the names of available
              network interfaces.
    """
    interfaces = netifaces.interfaces()
    return interfaces


def main():
    """Parses arguments and starts packet blocking threads."""
    parser = argparse.ArgumentParser(
        description="Block incoming packets based on specified criteria."
    )

    available_interfaces = get_network_interfaces()

    parser.add_argument(
        "-i",
        "--interface",
        choices=available_interfaces,
        default=DEFAULT_INTERFACE,
        help="Network interface to listen on (default: %(default)s)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=",".join(map(str, DEFAULT_PORT_RANGE)),
        help="Comma-separated list of ports or port ranges to block (e.g., 80,443,1000-2000)",
    )
    parser.add_argument(
        "-proto",
        "--protocols",
        default="6,17",
        help="Comma-separated list of protocol numbers to block (e.g., 6,17,1)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="List existing iptables rules",
    )
    parser.add_argument(
        "-f", "--flush", action="store_true", help="Flush all iptables rules"
    )

    args = parser.parse_args()

    if args.list:
        list_rules_iptables()
        return

    if args.flush:
        flush_rules_iptables()
        return

    try:
        ports = parse_ports(args.ports)
        protocols = [int(proto.strip()) for proto in args.protocols.split(",")]

        listener_thread = threading.Thread(
            target=packet_listener,
            args=(args.interface, ports, protocols, args.verbose),
        )
        listener_thread.daemon = True
        listener_thread.start()

        print(
            f"Blocking packets on interface: {args.interface}, Ports: {ports}, Protocols: {protocols}"
        )
        print("Press Ctrl+C to stop.")

        while True:
            pass

    except KeyboardInterrupt:
        print("\nPacket blocking stopped.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
