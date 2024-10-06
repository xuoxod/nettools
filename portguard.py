#!/usr/bin/python3

import sys
import argparse
import os
import socket
import struct
import subprocess
import threading
import time
import netifaces
import logging
import ipaddress
import select
import atexit

DEFAULT_PORT_RANGE = (1, 65535)
DEFAULT_INTERFACE = "eth0"
LOG_FILE = "portcullis.log"
RULES_FILE = "portcullis.rules"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def check_root():
    """Checks if the script is running with root privileges."""
    return os.geteuid() == 0


def request_root():
    """Prompts the user to run the script with root privileges."""
    response = input(
        "This script requires root privileges. Run with sudo? (yes/no): "
    ).lower()
    if response == "yes":
        try:
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            logging.error(f"Error escalating to root: {e}")
            print(f"Error escalating to root: {e}")
            sys.exit(1)
    else:
        print("Root privileges are required. Exiting.")
        sys.exit(1)


def block_packet_iptables(
    interface,
    protocol,
    s_addr=None,
    d_addr=None,
    s_port=None,
    d_port=None,
    ipv6=False,
):
    """Blocks the packet using iptables."""
    cmd = [
        "iptables" if not ipv6 else "ip6tables",
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
        logging.error(f"Error blocking packet: {e} - Command: {cmd}")


def remove_rule_iptables(
    interface,
    protocol,
    s_addr=None,
    d_addr=None,
    s_port=None,
    d_port=None,
    ipv6=False,
):
    """Removes a specific iptables rule."""
    cmd = [
        "iptables" if not ipv6 else "ip6tables",
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
        logging.error(f"Error removing rule: {e} - Command: {cmd}")


def list_rules_iptables(ipv6=False):
    """Lists all iptables rules for the INPUT chain."""
    try:
        output = subprocess.check_output(
            ["iptables" if not ipv6 else "ip6tables", "-L", "INPUT"]
        )
        logging.info("Listing iptables rules:")
        print(output.decode())
    except subprocess.CalledProcessError as e:
        logging.error(f"Error listing rules: {e}")


def flush_rules_iptables(ipv6=False):
    """Flushes all rules in the iptables INPUT chain."""
    try:
        subprocess.check_call(["iptables" if not ipv6 else "ip6tables", "-F", "INPUT"])
        logging.info("Flushed all iptables rules.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error flushing rules: {e}")


def load_rules(filename=RULES_FILE):
    """Loads iptables rules from a file."""
    if not os.path.exists(filename):
        return

    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    subprocess.check_call(line.split())
                    logging.info(f"Loaded rule: {line}")
                except subprocess.CalledProcessError as e:
                    logging.error(f"Error loading rule: {line} - {e}")


def save_rules(filename=RULES_FILE):
    """Saves the current iptables rules to a file."""
    try:
        with open(filename, "w") as f:
            rules_v4 = subprocess.check_output(["iptables-save"]).decode().splitlines()
            rules_v6 = subprocess.check_output(["ip6tables-save"]).decode().splitlines()
            for rule in rules_v4:
                if rule.startswith("-A INPUT"):
                    f.write(f"# Portguard rule (IPv4)\n{rule}\n")
            for rule in rules_v6:
                if rule.startswith("-A INPUT"):
                    f.write(f"# Portguard rule (IPv6)\n{rule}\n")
        logging.info(f"Saved iptables rules to {filename}")
    except IOError as e:
        logging.error(f"Error saving iptables rules to file: {e}")


def packet_listener(interface, ports, protocols, whitelist, blacklist, verbose=False):
    """Listens for and blocks packets based on specified criteria."""
    try:
        # Create a raw socket for both IPv4 and IPv6
        s4 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s4.bind((interface, 0))
        s6 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x86DD))
        s6.bind((interface, 0))

        if verbose:
            logging.info(
                f"Started packet blocking on interface: {interface}, "
                f"Ports: {ports}, Protocols: {protocols}, "
                f"Whitelist: {whitelist}, Blacklist: {blacklist}"
            )

        while True:
            # Use select to listen on both sockets
            ready_sockets, _, _ = select.select([s4, s6], [], [])

            for sock in ready_sockets:
                packet, _ = sock.recvfrom(65565)

                # Determine IP version
                version = (packet[0] >> 4) & 0xF

                # Handle IPv4 packets
                if version == 4:
                    ip_header = packet[0:20]
                    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])
                    protocol = iph[6]
                    header_length = (iph[0] & 0xF) * 4

                    # Filtering logic for IPv4
                    if protocol in protocols:
                        tcp_udp_header = packet[header_length : header_length + 8]
                        tcph = struct.unpack("!HH", tcp_udp_header)
                        source_port = tcph[0]
                        dest_port = tcph[1]

                        if (source_port in ports or dest_port in ports) and (
                            is_blacklisted(s_addr, blacklist)
                            or is_blacklisted(d_addr, blacklist)
                        ):
                            if not (
                                is_whitelisted(s_addr, whitelist)
                                or is_whitelisted(d_addr, whitelist)
                            ):
                                proto_name = socket.getprotobynumber(protocol)
                                block_packet_iptables(
                                    interface,
                                    proto_name,
                                    s_addr,
                                    d_addr,
                                    source_port,
                                    dest_port,
                                )

                # Handle IPv6 packets
                elif version == 6:
                    ip_header = packet[0:40]
                    iph = struct.unpack("!BBHHBB16s16s", ip_header)
                    s_addr = socket.inet_ntop(socket.AF_INET6, iph[4])
                    d_addr = socket.inet_ntop(socket.AF_INET6, iph[5])
                    protocol = iph[3]
                    header_length = 40

                    # Filtering logic for IPv6
                    if protocol in protocols:
                        try:
                            # Attempt to unpack assuming TCP/UDP header follows
                            tcp_udp_header = packet[header_length : header_length + 8]
                            tcph = struct.unpack("!HH", tcp_udp_header)
                            source_port = tcph[0]
                            dest_port = tcph[1]

                            if (
                                (source_port in ports or dest_port in ports)
                                and (
                                    is_blacklisted(s_addr, blacklist)
                                    or is_blacklisted(d_addr, blacklist)
                                )
                                and not (
                                    is_whitelisted(s_addr, whitelist)
                                    or is_whitelisted(d_addr, whitelist)
                                )
                            ):
                                proto_name = socket.getprotobynumber(protocol)
                                block_packet_iptables(
                                    interface,
                                    proto_name,
                                    s_addr,
                                    d_addr,
                                    source_port,
                                    dest_port,
                                    ipv6=True,  # Specify IPv6 for ip6tables
                                )
                        except struct.error as e:
                            # Handle cases where TCP/UDP doesn't follow IPv6
                            logging.debug(
                                f"Error unpacking TCP/UDP header for IPv6 (likely not TCP/UDP): {e}"
                            )
                            # Add logic here to handle other protocols if needed

                else:
                    logging.warning(f"Unknown IP version: {version}")
                    continue

    except KeyboardInterrupt:
        logging.info("Packet blocking stopped by user.")
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Error in packet listener: {e}")


def parse_ports(port_str):
    """Parses a string of ports and port ranges into a list of integers."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if not part:  # Handle empty parts
            continue
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


def is_valid_ip_network(ip_or_cidr):
    """Checks if a string is a valid IP address or CIDR range."""
    try:
        ipaddress.ip_network(ip_or_cidr)
        return True
    except ValueError:
        return False


def is_whitelisted(ip_address, whitelist):
    """Checks if an IP address is in the whitelist."""
    if not whitelist:
        return False
    return any(
        ipaddress.ip_address(ip_address) in ipaddress.ip_network(allowed_ip)
        for allowed_ip in whitelist
        if is_valid_ip_network(allowed_ip)
    )


def is_blacklisted(ip_address, blacklist):
    """Checks if an IP address is in the blacklist."""
    if not blacklist:
        return False
    return any(
        ipaddress.ip_address(ip_address) in ipaddress.ip_network(blocked_ip)
        for blocked_ip in blacklist
        if is_valid_ip_network(blocked_ip)
    )


def get_network_interfaces():
    """Returns a list of available network interface names."""
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
        help="Comma-separated list of ports or port ranges to block "
        "(e.g., 80,443,1000-2000)",
    )
    parser.add_argument(
        "-proto",
        "--protocols",
        default="6,17",
        help="Comma-separated list of protocol numbers to block " "(e.g., 6,17,1)",
    )
    parser.add_argument(
        "-w",
        "--whitelist",
        default="",
        help="Comma-separated list of allowed IP addresses or CIDR ranges "
        "(e.g., 192.168.1.0/24,10.0.0.1)",
    )
    parser.add_argument(
        "-b",
        "--blacklist",
        default="",
        help="Comma-separated list of blocked IP addresses or CIDR ranges "
        "(e.g., 192.168.1.0/24,10.0.0.1)",
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

    if not check_root():
        request_root()

    if args.list:
        list_rules_iptables()
        list_rules_iptables(ipv6=True)  # List IPv6 rules
        return

    if args.flush:
        flush_rules_iptables()
        flush_rules_iptables(ipv6=True)  # Flush IPv6 rules
        return

    try:
        ports = parse_ports(args.ports)
        protocols = [int(proto.strip()) for proto in args.protocols.split(",")]
        whitelist = [
            ip.strip() for ip in args.whitelist.split(",") if ip.strip()
        ]  # Remove empty strings
        blacklist = [
            ip.strip() for ip in args.blacklist.split(",") if ip.strip()
        ]  # Remove empty strings

        load_rules()

        listener_thread = threading.Thread(
            target=packet_listener,
            args=(
                args.interface,
                ports,
                protocols,
                whitelist,
                blacklist,
                args.verbose,
            ),
        )
        listener_thread.daemon = True
        listener_thread.start()

        # Register save_rules to be called on normal exit
        atexit.register(save_rules)

        print(
            f"Blocking packets on interface: {args.interface}, "
            f"Ports: {ports}, Protocols: {protocols}, "
            f"Whitelist: {whitelist}, Blacklist: {blacklist}"
        )
        print("Press Ctrl+C to stop.")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nPacket blocking stopped.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
