Packet Sniffer

This packet sniffer captures and analyzes network packets at the Ethernet, IP, ICMP, TCP, and UDP layers. It uses raw sockets to listen to all incoming packets and provides detailed information about each packet's structure and contents.
Table of Contents

    Requirements
    Installation
    Usage

Requirements

    Python 3.x
    Administrative privileges (to create raw sockets)

Installation

Clone the repository and navigate to the project directory:

bash

git clone https://github.com/sujan079/network-sniffer.git
cd network-sniffer

Ensure you have the required permissions to run the script:

bash

sudo python3 sniffer.py

Usage

Run the packet sniffer script:

bash

sudo python3 packet_sniffer.py

The script will start capturing and displaying packet information in the terminal. Use Ctrl + C to stop the script.