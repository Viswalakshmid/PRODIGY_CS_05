# PRODIGY_CS_05
Network Packet Sniffer
This is a simple Python-based network packet sniffer that captures and analyzes network traffic. It uses the Scapy library to provide real-time data about network packets, such as source and destination IP addresses, protocols, ports, and raw payload data.

#Features

Real-time packet capture
Displays source and destination IP addresses
Identifies protocols (TCP/UDP)
Shows source and destination ports for TCP/UDP packets
Displays raw payload data if available

#Prerequisites

Before running the script, make sure you have the following:
Python 3 installed on your system. You can check if you have Python 3 by running:

python3 --version
Scapy library installed. Install it using pip:
pip install scapy
Administrator or Root privileges to capture network packets (especially on Linux/macOS).

#How to Run the Script
Clone the Repository: Clone the repository to your local machine:
git clone https://github.com/Viswalakshmid/network-packet-sniffer.git
cd network-packet-sniffer
Install Dependencies: Ensure that Scapy is installed:

#Run the Script: Execute the script using the following command:
sudo python3 packetsniffer.py
Note: Use sudo on Linux/macOS to run the script with elevated privileges.

Output Example: The script will display details of each captured packet:

Packet captured: IP 192.168.1.1 > 192.168.1.2: ICMP
Source IP: 192.168.1.1
Destination IP: 192.168.1.2
Protocol: ICMP

Ethical Use
This tool is designed for educational purposes only. Please use it responsibly and ensure you have permission to sniff packets on any network. Unauthorized packet sniffing may be illegal.





