from flask import Flask, render_template_string
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

app = Flask(__name__)

HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>Network Scanner</title>
    <style>
        body { font-family: Arial; padding: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h2>Devices on Your Network</h2>
    <table>
        <tr><th>IP Address</th><th>MAC Address</th><th>Vendor</th></tr>
        {% for device in devices %}
        <tr>
            <td>{{ device['IP Address'] }}</td>
            <td>{{ device['MAC Address'] }}</td>
            <td>{{ device['Vendor'] }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

def scan_network(ip_range="192.168.1.1/24"):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    mac_lookup = MacLookup()
    devices = []

    for _, received in result:
        try:
            vendor = mac_lookup.lookup(received.hwsrc)
        except:
            vendor = "Unknown"
        devices.append({
            "IP Address": received.psrc,
            "MAC Address": received.hwsrc,
            "Vendor": vendor
        })
    return devices

@app.route("/")
def index():
    devices = scan_network()
    return render_template_string(HTML_TEMPLATE, devices=devices)

if __name__ == "__main__":
    app.run(debug=True)
