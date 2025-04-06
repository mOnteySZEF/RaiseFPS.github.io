import subprocess
import ctypes
import tkinter as tk
from tkinter import messagebox
import threading

def backup(description):
    if not is_admin():
        messagebox.showerror("Błąd", "Musisz uruchomić jako administrator.")
        return

    if not is_system_protection_enabled():
        messagebox.showerror("Błąd", "Ochrona systemu nie jest włączona. Aby stworzyć punkt przywracania, musisz włączyć ochronę systemu.")
        return

    threading.Thread(target=run_backup, args=(description,)).start()

def run_backup(description):
    try:
        description_fn(description)
        messagebox.showinfo("Kopia zapasowa", "Kopia zapasowa została pomyślnie zrobiona!")
    except Exception as e:
        print(f"Błąd w wątku: {e}")
        messagebox.showerror("Błąd", "Wystąpił problem podczas tworzenia kopii zapasowej.")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(f"Błąd przy sprawdzaniu uprawnień administratora: {e}")
        return False

def is_system_protection_enabled():
    try:
        result = subprocess.run(
            "powershell.exe -Command \"Get-ComputerRestorePoint\"",
            check=True, shell=True, text=True, capture_output=True
        )
        if result.stdout.strip():
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        print(f"Błąd podczas sprawdzania ochrony systemu: {e}")
        return False

def create_restore_point(description):
    command = f"powershell.exe -Command \"Checkpoint-Computer -Description '{description}' -RestorePointType 'MODIFY_SETTINGS'\""
    
    try:
        result = subprocess.run(command, check=True, shell=True, text=True, capture_output=True)
        print(f"PowerShell zwrócił wynik: {result.stdout}")
        print(f"Punkt przywracania stworzony: {description}")
    except subprocess.CalledProcessError as e:
        print(f"Błąd podczas tworzenia punktu przywracania: {e}")
        print(f"Stosowane polecenie PowerShell: {e.cmd}")
        print(f"Wyjście błędu: {e.stderr}")
    except Exception as e:
        print(f"Nieoczekiwany błąd: {e}")

def change_restore_frequency():
    try:
        subprocess.run(
            'powershell.exe -Command "Set-ItemProperty -Path \'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\' -Name \'SystemRestorePointCreationFrequency\' -Value 1"',
            check=True, shell=True, text=True, capture_output=True
        )
        print("Częstotliwość tworzenia punktów przywracania ustawiona na 1 minutę.")
    except subprocess.CalledProcessError as e:
        print(f"Błąd przy zmianie częstotliwości w rejestrze: {e}")
    except Exception as e:
        print(f"Błąd przy zmianie częstotliwości tworzenia punktów przywracania: {e}")

def reset_restore_frequency():
    try:
        subprocess.run(
            'powershell.exe -Command "Set-ItemProperty -Path \'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\' -Name \'SystemRestorePointCreationFrequency\' -Value 1440"',
            check=True, shell=True, text=True, capture_output=True
        )
        print("Częstotliwość tworzenia punktów przywracania została przywrócona do domyślnej wartości (1440 minut).")
    except subprocess.CalledProcessError as e:
        print(f"Błąd przy resetowaniu częstotliwości w rejestrze: {e}")
    except Exception as e:
        print(f"Błąd przy resetowaniu częstotliwości tworzenia punktów przywracania: {e}")

def description_fn(description):
    try:
        change_restore_frequency()
        create_restore_point(description)
    finally:
        reset_restore_frequency()

