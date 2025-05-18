Network Device Scanner
----------------------

This project is a Python-based ARP network scanner that identifies all active devices on a local network. It includes both a command-line version and a web-based interface built with Flask.

Features
--------

- Performs ARP scanning to list IP and MAC addresses of devices on the network
- Looks up vendor/manufacturer information based on MAC addresses
- Provides both a command-line tool and a browser-accessible web interface
- Saves results to a CSV file for further analysis

Requirements
------------

To run this project, you will need to have the following installed:

- Python 3.6+
- Npcap (for packet capturing on Windows)
- The following Python packages:

Run this command to install them:

    pip install scapy tabulate flask mac-vendor-lookup

Usage
-----

Command-line version:

    python network_scanner.py

When prompted, enter the IP range to scan, for example:

    192.168.1.1/24

Web version:

    python scanner_web.py

Then open your browser and go to:

    http://localhost:5000

The web version will display the same scan results in a formatted table.
