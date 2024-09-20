from scapy.all import *

# Define the target IP address
target_ip = "192.168.1.100"  # Replace with the actual IP address

# Define the packet payload
payload = "Hello from Scapy!"

# Create a raw IP packet
packet = IP(dst=target_ip) / ICMP(type=8, code=0) / payload

# Send the packet
send(packet, verbose=0)

print(f"Packet sent to {target_ip}")
