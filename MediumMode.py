import subprocess
import os
import threading
from tkinter import messagebox
import RaiseFPS

def cleanup_basic_files():
    print("Optymalizacja: Czyszczenie podstawowych plików...")
    subprocess.call('del /f /s /q %temp%', shell=True)  # Usuwanie tymczasowych plików
    subprocess.call('rmdir /s /q %temp%', shell=True)  # Usuwanie folderu Temp
    # subprocess.call('cleanmgr /sagerun:1', shell=True)  # Uruchomienie narzędzia czyszczącego system

def disable_background_processes():
    print("Optymalizacja: Wyłączanie zbędnych procesów...")
    processes = ["OneDrive.exe", "Skype.exe"]
    for process in processes:
        subprocess.call(f"taskkill /f /im {process}", shell=True)

def disable_services():
    print("Optymalizacja: Wyłączanie niepotrzebnych usług...")
    subprocess.call('sc stop "wuauserv"', shell=True)  # Windows Update
    subprocess.call('sc config "wuauserv" start= disabled', shell=True)
    subprocess.call('sc stop "bits"', shell=True)  # Usługi BITS (Background Intelligent Transfer Service)
    subprocess.call('sc config "bits" start= disabled', shell=True)

def optimize_registry():
    print("Optymalizacja: Optymalizacja ustawień rejestru...")
    subprocess.call('reg add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v "MenuShowDelay" /t REG_DWORD /d 0 /f', shell=True)  # Usuwanie opóźnienia w menu
    subprocess.call('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "ThumbnailCacheSize" /t REG_DWORD /d 0 /f', shell=True)  # Usuwanie cache miniatur

def optimize_power_settings():
    print("Optymalizacja: Optymalizacja ustawień zasilania...")
    subprocess.call('powercfg /change standby-timeout-ac 0', shell=True)  # Wyłączenie timeoutu ekranu
    subprocess.call('powercfg /change monitor-timeout-ac 0', shell=True)  # Wyłączenie auto-wygaszania ekranu

def optimize_medium():
    def run_optimization():
        print("Optymalizacja: Medium Mode w toku...")
        cleanup_basic_files()
        disable_background_processes()
        disable_services()
        optimize_registry()
        optimize_power_settings()

        RaiseFPS.stop_loading()
    optimization_thread = threading.Thread(target=run_optimization)
    optimization_thread.start()
