import subprocess
import os
from tkinter import messagebox
import threading

def advanced_cleanup():
    print("Optymalizacja: Zaawansowane czyszczenie systemu...")
    subprocess.call('del /f /s /q %temp%', shell=True)  # Usuwanie tymczasowych plików
    subprocess.call('rmdir /s /q %temp%', shell=True)  # Usuwanie folderu Temp
    subprocess.call('cleanmgr /sagerun:1', shell=True)  # Uruchomienie narzędzia czyszczącego system
    subprocess.call('del /f /s /q C:\\Windows\\System32\\*.bak', shell=True)  # Usuwanie plików backupowych
    subprocess.call('del /f /s /q C:\\Windows\\System32\\*.log', shell=True)  # Usuwanie logów
    subprocess.call('del /f /s /q C:\\Windows\\System32\\*.tmp', shell=True)  # Usuwanie plików tymczasowych

def optimize_memory():
    print("Optymalizacja: Optymalizacja pamięci RAM...")
    subprocess.call("echo Y | del /f /s /q C:\\Windows\\System32\\MemoryCache\\*", shell=True)  # Czyszczenie pamięci podręcznej
    subprocess.call("rundll32.exe advapi32.dll,ProcessIdleTasks", shell=True)  # Uruchomienie procesu idle tasków

def disable_background_processes():
    print("Optymalizacja: Wyłączanie procesów w tle...")
    processes = ["OneDrive.exe", "Skype.exe", "Discord.exe", "Spotify.exe", "Steam.exe", "EpicGamesLauncher.exe"]
    for process in processes:
        subprocess.call(f"taskkill /f /im {process}", shell=True)

def optimize_drivers():
    print("Optymalizacja: Optymalizacja sterowników...")
    subprocess.call("devmgmt.msc", shell=True)  # Otwórz Menedżer urządzeń do aktualizacji sterowników

def optimize_registry():
    print("Optymalizacja: Optymalizacja ustawień rejestru...")
    subprocess.call('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "ThumbnailCacheSize" /t REG_DWORD /d 0 /f', shell=True)  # Usuwanie cache miniatur
    subprocess.call('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f', shell=True)  # Optymalizacja pamięci
    subprocess.call('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 1 /f', shell=True)  # Czyszczenie pamięci przy zamykaniu systemu

def optimize_gaming():
    print("Optymalizacja: Optymalizacja ustawień gier...")
    subprocess.call('reg add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v "VSync" /t REG_DWORD /d 0 /f', shell=True)  # Wyłączenie V-Sync
    subprocess.call('reg add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v "GameMode" /t REG_DWORD /d 1 /f', shell=True)  # Włączenie trybu gry

def disable_services():
    print("Optymalizacja: Wyłączanie zbędnych usług systemowych...")
    subprocess.call('sc stop "wuauserv"', shell=True)  # Zatrzymywanie usług Windows Update
    subprocess.call('sc config "wuauserv" start= disabled', shell=True)
    subprocess.call('sc stop "bits"', shell=True)  # Usługi BITS
    subprocess.call('sc config "bits" start= disabled', shell=True)

def optimize_power_settings():
    print("Optymalizacja: Ustawienia zasilania...")
    subprocess.call('powercfg /change standby-timeout-ac 0', shell=True)  # Wyłącz auto-zamykanie ekranu
    subprocess.call('powercfg /change monitor-timeout-ac 0', shell=True)  # Wyłącz auto-wygaszanie ekranu
    subprocess.call('powercfg /change hibernate-timeout-ac 0', shell=True)  # Wyłącz hibernację

def optimize_pro():
    def run_optimization():
        print("Optymalizacja: PRO Mode w toku...")
        advanced_cleanup()
        optimize_memory()
        disable_background_processes()
        optimize_drivers()
        optimize_registry()
        optimize_gaming()
        disable_services()
        optimize_power_settings()

        messagebox.showinfo("Optymalizacja", "Optymalizacja PRO zakończona pomyślnie!")

    optimization_thread = threading.Thread(target=run_optimization)
    optimization_thread.start()
