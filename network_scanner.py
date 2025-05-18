from scapy.all import ARP, Ether, srp
from tabulate import tabulate
from mac_vendor_lookup import MacLookup
import csv

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    mac_lookup = MacLookup()
    devices = []

    for sent, received in result:
        try:
            vendor = mac_lookup.lookup(received.hwsrc)
        except:
            vendor = "Unknown"

        devices.append({
            'IP Address': received.psrc,
            'MAC Address': received.hwsrc,
            'Vendor': vendor
        })

    return devices

def export_to_csv(devices):
    with open("scan_results.csv", "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=devices[0].keys())
        writer.writeheader()
        writer.writerows(devices)

def main():
    print("Ahmed's Network Scanner")
    target = input("Enter your network IP range (e.g., 192.168.1.1/24): ")
    print("\nScanning...\n")
    devices = scan_network(target)

    if devices:
        print(tabulate(devices, headers="keys"))
        export_to_csv(devices)
        print("\nResults saved to scan_results.csv")
    else:
        print("No devices found.")

if __name__ == "__main__":
    main()
