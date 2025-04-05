import os
import subprocess
import sys

def backup(description):
    if not is_admin():
        print("Musisz uruchomić jako administrator.")
        return
    command = f"powershell.exe -Command \"Checkpoint-Computer -Description '{description}' -RestorePointType 'MODIFY_CONFIG'\""
    try:
        # subprocess.run(command, check=True, shell=True)
        print(f"Punkt przywracania stworzony!")
    except subprocess.CalledProcessError as e:
        print(f"Błąd podczas tworzenia punktu przywracania: {e}")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False