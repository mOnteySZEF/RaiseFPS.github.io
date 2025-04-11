import subprocess
import os
import threading
from tkinter import messagebox
import RaiseFPS

def cleanup_basic_files():
    print("Optymalizacja: Czyszczenie podstawowych plików...")
    subprocess.call('del /f /s /q %temp%', shell=True)  # Usuwanie tymczasowych plików
    subprocess.call('rmdir /s /q %temp%', shell=True)  # Usuwanie folderu Temp

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

    def execute_commands():
        print("Optymalizacja2 MEDIUM jest w toku...")
        commands = [
            "reg add \"HKCU\\System\\GameConfigStore\" /v \"GameDVR_Enabled\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\ApplicationManagement\\AllowGameDVR\" /v \"value\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_FSEBehaviorMode\" /t REG_DWORD /d 2 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_HonorUserFSEBehaviorMode\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_DXGIHonorFSEWindowsCompatible\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_EFSEFeatureFlags\" /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v Affinity /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v BackgroundOnly /t REG_SZ /d False /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v ClockRate /t REG_DWORD /d 10000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v SchedulingCategory /t REG_SZ /d High /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v SFIOPriority /t REG_SZ /d High /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v GPUPriority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v Priority /t REG_DWORD /d 6 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" /v SystemResponsiveness /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching\" /v SearchOrderConfig /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\" /v WaitToKillServiceTimeout /t REG_SZ /d \"2000\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WaitToKillServiceTimeout /t REG_DWORD /d 20000 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\" /v HiberbootEnabled /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\GameDVR\" /v \"AllowgameDVR\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling\" /v PowerThrottlingOff /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling\" /v \"PowerThrottlingOff\" /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" /v SystemResponsiveness /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\" /v WaitToKillServiceTimeout /t REG_SZ /d \"2000\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WaitToKillServiceTimeout /t REG_DWORD /d 20000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution\" /v Affinity /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution\" /v BackgroundOnly /t REG_SZ /d True /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution\" /v ClockRate /t REG_DWORD /d 10000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution\" /v GPUPriority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution\" /v Priority /t REG_DWORD /d 4 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution\" /v SchedulingCategory /t REG_SZ /d Medium /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution\" /v SFIOPriority /t REG_SZ /d Normal /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback\" /v Affinity /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback\" /v BackgroundOnly /t REG_SZ /d False /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback\" /v BackgroundPriority /t REG_DWORD /d 4 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback\" /v ClockRate /t REG_DWORD /d 10000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback\" /v GPUPriority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback\" /v Priority /t REG_DWORD /d 3 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback\" /v SchedulingCategory /t REG_SZ /d Medium /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback\" /v SFIOPriority /t REG_SZ /d Normal /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio\" /v Affinity /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio\" /v BackgroundOnly /t REG_SZ /d False /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio\" /v ClockRate /t REG_DWORD /d 10000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio\" /v GPUPriority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio\" /v Priority /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio\" /v SchedulingCategory /t REG_SZ /d High /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio\" /v SFIOPriority /t REG_SZ /d Normal /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager\" /v Affinity /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager\" /v BackgroundOnly /t REG_SZ /d True /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager\" /v ClockRate /t REG_DWORD /d 10000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager\" /v GPUPriority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager\" /v Priority /t REG_DWORD /d 5 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager\" /v SchedulingCategory /t REG_SZ /d Medium /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager\" /v SFIOPriority /t REG_SZ /d Normal /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio\" /v Affinity /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio\" /v BackgroundOnly /t REG_SZ /d True /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio\" /v ClockRate /t REG_DWORD /d 10000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio\" /v GPUPriority /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio\" /v Priority /t REG_DWORD /d 2 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio\" /v SchedulingCategory /t REG_SZ /d Medium /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio\" /v SFIOPriority /t REG_SZ /d High /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture\" /v Affinity /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture\" /v BackgroundOnly /t REG_SZ /d True /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture\" /v ClockRate /t REG_DWORD /d 10000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture\" /v GPUPriority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture\" /v Priority /t REG_DWORD /d 5 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture\" /v SchedulingCategory /t REG_SZ /d Medium /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture\" /v SFIOPriority /t REG_SZ /d Normal /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing\" /v Affinity /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing\" /v BackgroundOnly /t REG_SZ /d True /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing\" /v BackgroundPriority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing\" /v ClockRate /t REG_DWORD /d 10000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing\" /v GPUPriority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing\" /v Priority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing\" /v SchedulingCategory /t REG_SZ /d High /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing\" /v SFIOPriority /t REG_SZ /d Normal /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\" /v HibernateEnabledDefault /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1\" /v Attributes /t REG_DWORD /d 2 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\75b0ae3f-bce0-45a7-8c89-c9611c25e100\" /v \"Attributes\" /t REG_DWORD /d 2 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1\" /v Attributes /t REG_DWORD /d 2 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e\" /v ACSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e\" /v DCSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\" /v ACSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e\" /v ACSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e\" /v DCSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\" /v ACSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\" /v DCSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GTA5.exe\PerfOptions\" /v CpuPriorityClass /t REG_DWORD /d 3 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\gtavlauncher.exe\PerfOptions\" /v CpuPriorityClass /t REG_DWORD /d 5 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\subprocess.exe\PerfOptions\" /v CpuPriorityClass /t REG_DWORD /d 5 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /v \"AppsUseLightTheme\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /v \"AppsUseLightTheme\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main\" /v \"AllowPrelaunch\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\TabPreloader\" /v \"AllowTabPreloading\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"Win32_AutoGameModeDefaultProfile\" /t REG_BINARY /d \"01000100000000000000000000000000\" /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"Win32_GameModeRelatedProcesses\" /t REG_BINARY /d \"01000000000000000000000000000000\" /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_HonorUserFSEBehaviorMode\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_DXGIHonorFSEWindowsCompatible\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_EFSEFeatureFlags\" /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v \"AllowTelemetry\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\" /v \"ShowedToastAtLevel\" /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableRealtimeMonitoring\" /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\SettingSync\" /v \"DisableApplicationSettingSync\" /t REG_DWORD /d 2 /f",
            "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People\" /v \"PeopleBand\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"EnableSnapAssistFlyout\" /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"AllowCloudSearch\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\" /v \"BingSearchEnabled\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\" /v \"Disabled\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Help\" /v \"DisableWindowsHelp\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableIOAVProtection\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"EnableSuperfetch\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiVirus\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableBehaviorMonitoring\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableRealtimeMonitoring\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"DisableWebSearch\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\" /v \"AllowCortana\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"TaskbarAnimations\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"DisableIndexing\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DisableAnimations\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v \"DisableCloudOptimizedContent\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v \"DisableCloudOptimizedContent\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\" /v \"Disabled\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"NoLowDiskSpaceChecks\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableSpyware\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v \"LetAppsSyncWithDevices\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\" /v \"AllowClipboardHistory\" /t REG_DWORD /d 1 /f",

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

    optimization2_thread = threading.Thread(target=execute_commands)
    optimization2_thread.start()
