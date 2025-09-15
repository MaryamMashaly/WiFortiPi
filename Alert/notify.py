import json 
import requests 
from pathlib import Path 
from datetime import datetime 
import logging 
 
class Potfile: 
    def __init__(self, path: Path): 
        self.path = path 
 
    def get_cracked_passwords(self): 
        if not self.path.exists(): 
            logging.error("Potfile not found at %s", self.path) 
            return [] 
         
        with self.path.open() as f: 
            lines = f.readlines() 
        passwords = [line.strip().split(':') for line in lines] 
        return [{'hash': pwd[0], 'plain': pwd[1]} for pwd in passwords if len(pwd) == 2] 
 
def notify_discord(webhook_url, passwords): 
    for pwd in passwords: 
        payload = { 
            "content": "Password cracked!", 
            "embeds": [ 
                { 
                    "color": 5814783, 
                    "fields": [ 
                        {"name": "Password Hash", "value": f"`{pwd['hash']}`"}, 
                        {"name": "Password Plaintext", "value": f"`{pwd['plain']}`"}, 
                    ], 
                } 
            ], 
            "username": "hcNotify", 
            "attachments": [], 
            "flags": 4096, 
        } 
        response = requests.post(webhook_url, json=payload) 
        if response.status_code == 204: 
            logging.info("Notification sent successfully for %s", pwd['plain']) 
        else: 
            logging.error("Failed to send notification, response code: %s", response.status_code) 
 
def main(): 
    logging.basicConfig(level=logging.INFO) 
     
    # Hardcoded Webhook URL and Potfile Path 
    webhook_url = "https://discord.com/api/webhooks/1240023981189234688/RgTaxs4gBPDTSFv3PRtyvExn89diOI8PYkWg9SB0DKu_yJ_XNbW48CONdEC7GNoMpcry" 
    potfile_path = Path('/home/kali/.hashcat/hashcat.potfile').expanduser() 
     
    potfile = Potfile(potfile_path) 
    cracked_passwords = potfile.get_cracked_passwords() 
     
    if cracked_passwords: 
        notify_discord(webhook_url, cracked_passwords) 
    else: 
        logging.info("No passwords found in the potfile.") 
 
if __name__ == "__main__": 
    main()