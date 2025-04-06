import os
import shutil
import ctypes
import subprocess
import threading
from tkinter import Tk, messagebox

def empty_recycle_bin():
    try:
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x00000007)
    except Exception:
        pass

def clean_software_distribution():
    folder = r'C:\Windows\SoftwareDistribution\Download'
    if os.path.exists(folder):
        try:
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path, ignore_errors=True)
                except Exception:
                    pass
        except Exception:
            pass

def clean_browser_cache():
    cache_paths = [
        os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache'), # Chrome
        os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache'), # Edge
        os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles'), # Firefox
        os.path.expandvars(r'%APPDATA%\Opera Software\Opera Stable\Cache'), # Opera
        os.path.expandvars(r'%APPDATA%\Opera Software\Opera GX Stable\Cache'), # Opera GX
        os.path.expandvars(r'%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Cache'), # Brave Browser
        os.path.expandvars(r'%LOCALAPPDATA%\Vivaldi\User Data\Default\Cache'), # Vivaldi
        os.path.expandvars(r'%LOCALAPPDATA%\Yandex\YandexBrowser\User Data\Default\Cache') # Yandex Browser
    ]

    for path in cache_paths:
        if os.path.exists(path):
            try:
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            os.remove(file_path)
                        except Exception:
                            pass
            except Exception:
                pass

def clean_log_files(drive="C:\\"):
    for root, dirs, files in os.walk(drive):
        for file in files:
            if file.lower().endswith('.log'):
                file_path = os.path.join(root, file)
                try:
                    os.remove(file_path)
                except Exception:
                    pass

def clean_download_folder():
    download_folder = os.path.expandvars(r'%USERPROFILE%\Downloads')
    if os.path.exists(download_folder):
        try:
            for filename in os.listdir(download_folder):
                file_path = os.path.join(download_folder, filename)
                if os.path.isfile(file_path):
                    file_extension = os.path.splitext(filename)[1].lower()
                    # Usuwanie plików instalacyjnych i innych zbędnych plików
                    if file_extension in ['.msi', '.cab', '.tmp']:
                        try:
                            os.remove(file_path)
                        except Exception:
                            pass
        except Exception:
            pass

def clean_icon_cache():
    icon_cache_path = os.path.expandvars(r'%USERPROFILE%\AppData\Local\IconCache.db')
    if os.path.exists(icon_cache_path):
        try:
            os.remove(icon_cache_path)
        except Exception:
            pass

def clean_recent_folder():
    recent_folder = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Recent')
    if os.path.exists(recent_folder):
        try:
            for filename in os.listdir(recent_folder):
                file_path = os.path.join(recent_folder, filename)
                try:
                    os.remove(file_path)
                except Exception:
                    pass
        except Exception:
            pass

def clean_delivery_optimization():
    delivery_folder = r'C:\Windows\SoftwareDistribution\DeliveryOptimization'
    if os.path.exists(delivery_folder):
        try:
            for filename in os.listdir(delivery_folder):
                file_path = os.path.join(delivery_folder, filename)
                try:
                    shutil.rmtree(file_path, ignore_errors=True)
                except Exception:
                    pass
        except Exception:
            pass

def clean_shadow_copies():
    try:
        subprocess.run(["vssadmin", "delete", "shadows", "/all", "/quiet"], check=True)
    except Exception:
        pass


def optimize_low():
    def run_optimization():
        print("Optymalizacja: Low Mode w toku...")
        temp_dirs = [
            os.environ.get('TEMP'),
            os.environ.get('TMP'),
            r'C:\Windows\Prefetch'
        ]

        for folder in temp_dirs:
            if folder and os.path.exists(folder):
                try:
                    for filename in os.listdir(folder):
                        file_path = os.path.join(folder, filename)
                        try:
                            if os.path.isfile(file_path) or os.path.islink(file_path):
                                os.unlink(file_path)
                            elif os.path.isdir(file_path):
                                shutil.rmtree(file_path, ignore_errors=True)
                        except Exception:
                            pass
                except Exception:
                    pass
        # Opróżnianie kosza
        empty_recycle_bin()

        # Czyszczenie SoftwareDistribution
        clean_software_distribution()

        # Czyszczenie pamięci podręcznej przeglądarek
        clean_browser_cache()

        # Czyszczenie plików .log na C:
        clean_log_files(drive="C:\\")

        # Czyszczenie folderu Download
        clean_download_folder()

        # Resetowanie pamięci podręcznej ikon
        clean_icon_cache()

        # Czyszczenie folderu "Recent"
        clean_recent_folder()

        # Usuwanie zawartości folderu Delivery Optimization
        clean_delivery_optimization()

        # Wyczyść Shadow Copies
        clean_shadow_copies()

        messagebox.showinfo("Optymalizacja", "Optymalizacja Low Mode zakończona pomyślnie!")

    optimization_thread = threading.Thread(target=run_optimization)
    optimization_thread.start()
