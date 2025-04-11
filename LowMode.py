import os
import shutil
import ctypes
import subprocess
import threading
from tkinter import Tk, messagebox
import RaiseFPS

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

        RaiseFPS.stop_loading()
    optimization_thread = threading.Thread(target=run_optimization)
    optimization_thread.start()

    def PowerShell_funcja():
        print("Optymalizacja2 PRO jest w toku...")
        commands = [
            "PowerShell -Command \"Import-Module -DisableNameChecking $PSScriptRoot\\..\\lib\\force-mkdir.psm1\"",
            "PowerShell -Command \"force-mkdir 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' 'AllowTelemetry' 0\"",
            "PowerShell -Command \"force-mkdir 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR'; Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR' 'AllowgameDVR' 0\"",
            "PowerShell -Command \"New-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer -Name DisableEdgeDesktopShortcutCreation -PropertyType DWORD -Value 1\""
            "PowerShell -Command \"Get-AppxPackage *3DBuilder* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Getstarted* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *WindowsPhone* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *SkypeApp* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.XboxGameCallableUI* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.XboxLive* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage\"",
            ]

        for command in commands:
            try:
                if command.startswith("PowerShell"):
                    elevated_command = f'powershell -Command "Start-Process cmd -ArgumentList \'/c {command}\' -Verb RunAs"'
                    subprocess.call(elevated_command, shell=True)
                else:
                    subprocess.call(command, shell=True)
                print(f"Wykonano: {command}")
            except Exception as e:
                print(f"Błąd podczas wykonywania {command}: {str(e)}")

    optimization3_thread = threading.Thread(target=PowerShell_funcja)
    optimization3_thread.start()


    def Regedity_funcja():
        print("Optymalizacja2 LOW jest w toku...")
        commands = [
                "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v \"AllowTelemetry\" /t REG_DWORD /d 0 /f",
                "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\" /v \"ShowedToastAtLevel\" /t REG_DWORD /d 0 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\" /v \"PowerThrottlingOff\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling\" /v \"PowerThrottlingOff\" /t REG_DWORD /d 1 /f",
                "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableRealtimeMonitoring\" /t REG_DWORD /d 1 /f",
                "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\SettingSync\" /v \"DisableApplicationSettingSync\" /t REG_DWORD /d 2 /f",
                "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People\" /v \"PeopleBand\" /t REG_DWORD /d 0 /f",
                "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"EnableSnapAssistFlyout\" /t REG_DWORD /d 0 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"EnableSuperfetch\" /t REG_DWORD /d 0 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiVirus\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableBehaviorMonitoring\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableRealtimeMonitoring\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"DisableWebSearch\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"AllowCortana\" /t REG_DWORD /d 0 /f",
                "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"TaskbarAnimations\" /t REG_DWORD /d 0 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"DisableIndexing\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DisableAnimations\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"ShowSuperHidden\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v \"DisableCloudOptimizedContent\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v \"DisableCloudOptimizedContent\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\" /v \"Disabled\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"NoLowDiskSpaceChecks\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableSpyware\" /t REG_DWORD /d 1 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v \"LetAppsSyncWithDevices\" /t REG_DWORD /d 0 /f",
                "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v \"AllowClipboardHistory\" /t REG_DWORD /d 0 /f",
            ]

        for command in commands:
            try:
                if command.startswith("PowerShell"):
                    elevated_command = f'powershell -Command "Start-Process cmd -ArgumentList \'/c {command}\' -Verb RunAs"'
                    subprocess.call(elevated_command, shell=True)
                else:
                    subprocess.call(command, shell=True)
                print(f"Wykonano: {command}")
            except Exception as e:
                print(f"Błąd podczas wykonywania {command}: {str(e)}")

    optimization4_thread = threading.Thread(target=Regedity_funcja)
    optimization4_thread.start()