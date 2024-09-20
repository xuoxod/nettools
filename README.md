# Netsentry: Network Security and Packet Manipulation Toolkit

## Summary

Netsentry is a collection of Python scripts designed for network exploration, security auditing, and controlled packet manipulation. It leverages libraries like Scapy and the socket module to provide functionalities such as port scanning, network traffic blocking, and custom packet crafting.

## Development Environment

Here's a breakdown of the tools used in developing Netsentry:

- **IDE:** Visual Studio Code (version 1.75.0)
- **Operating System:** Ubuntu 22.04.2 LTS
- **Python Version:** Python 3.10.6
- **Key Libraries:**
  - Scapy (version 2.4.5) - For packet crafting and network manipulation.
  - netifaces (version 0.11.0) - For retrieving network interface information.
  - Jinja2 (version 3.1.2) - For generating HTML reports (optional).

## Virtual Environment Setup and Usage

Follow these steps to set up a virtual environment and run the scripts:

```bash
# 1. Create a virtual environment (recommended)
python3 -m venv .venv

# 2. Activate the virtual environment
source .venv/bin/activate

# 3. Install required libraries
pip install -r requirements.txt

# 4. Deactivate the virtual environment (when done)
deactivate
```

```bash
# Running the Scripts
1. netsentry.py (Network Scanner and Blocker)
This script scans a network range for open ports and allows you to selectively block traffic to specific IPs.

python netsentry.py 192.168.1.0/24 -sp 1 -ep 1000 -o scan_results.csv


2. netprobe.py (Network Port Scanner)
This script performs a port scan on a given target IP or range.

python netprobe.py 192.168.1.1 -sp 22 -ep 443 -o results.html -f html


3. portcullis.py (Packet Blocker)
This script blocks incoming packets on specified ports for a given network interface.

python portcullis.py -i eth0 -p 80,443,8080-8085 -v
```
