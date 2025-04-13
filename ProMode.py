import subprocess
import os
import psutil
from tkinter import messagebox
import threading
import xml.etree.ElementTree as ET
import shutil
import RaiseFPS

proces1 = False
proces2 = False
proces3 = False
proces4 = False
proces5 = False
proces6 = False

def execute_and_handle_errors(command):
    try:
        subprocess.call(command, shell=True)
        print(f"Wykonano: {command}")
    except Exception as e:
        print(f"Błąd podczas wykonywania {command}: {str(e)}")

def advanced_cleanup():
    print("Optymalizacja: Zaawansowane czyszczenie systemu...")
    subprocess.call('del /f /s /q %temp%', shell=True)  # Usuwanie tymczasowych plików
    subprocess.call('rmdir /s /q %temp%', shell=True)  # Usuwanie folderu Temp
    subprocess.call('cleanmgr /sagerun:1', shell=True)  # Uruchomienie narzędzia czyszczącego system
    subprocess.call('del /f /s /q C:\\Windows\\System32\\*.bak', shell=True)  # Usuwanie plików backupowych
    subprocess.call('del /f /s /q C:\\Windows\\System32\\*.log', shell=True)  # Usuwanie logów
    subprocess.call('del /f /s /q C:\\Windows\\System32\\*.tmp', shell=True)  # Usuwanie plików tymczasowych
    subprocess.call('ipconfig /flushdns', shell=True)

def optimize_memory():
    print("Optymalizacja: Optymalizacja pamięci RAM...")
    subprocess.call("echo Y | del /f /s /q C:\\Windows\\System32\\MemoryCache\\*", shell=True)  # Czyszczenie pamięci podręcznej
    subprocess.call("rundll32.exe advapi32.dll,ProcessIdleTasks", shell=True)  # Uruchomienie procesu idle tasków

def fivem_cache():
    user_profile = os.environ.get("USERPROFILE")
    folder_path = os.path.join(user_profile, r"AppData\Local\FiveM\FiveM.app\data")
    
    files_to_delete = ["game-storage", "cache", "nui-storage", "server-cache-priv"]

    for file_name in files_to_delete:
        full_path = os.path.join(folder_path, file_name)

        try:
            if os.path.exists(full_path):
                if os.path.isfile(full_path):
                    os.remove(full_path)
                    print(f"Usunięto plik: {full_path}")
                elif os.path.isdir(full_path):
                    shutil.rmtree(full_path)
                    print(f"Usunięto folder: {full_path}")
            else:
                print(f"Nie znaleziono: {full_path}")
        except Exception as e:
            print(f"Błąd przy usuwaniu {full_path}: {str(e)}")

def changeSettingsGTAV():
    user_profile = os.environ.get('USERPROFILE') 
    settings_file = os.path.join(user_profile, 'Documents', 'Rockstar Games', 'GTA V', 'settings.xml')

    if os.path.exists(settings_file):
        tree = ET.parse(settings_file)
        root = tree.getroot()
        graphics = root.find('graphics')
    
        graphics.find('Tessellation').set('value', '0')
        graphics.find('LodScale').set('value', '0.500000')
        graphics.find('PedLodBias').set('value', '0.000000')
        graphics.find('VehicleLodBias').set('value', '0.000000')
        graphics.find('ShadowQuality').set('value', '0')
        graphics.find('ReflectionQuality').set('value', '0')
        graphics.find('ReflectionMSAA').set('value', '0')
        graphics.find('SSAO').set('value', '0')
        graphics.find('AnisotropicFiltering').set('value', '0')
        graphics.find('MSAA').set('value', '0')
        graphics.find('MSAAFragments').set('value', '0')
        graphics.find('MSAAQuality').set('value', '0')
        graphics.find('SamplingMode').set('value', '0')
        graphics.find('TextureQuality').set('value', '1')
        graphics.find('ParticleQuality').set('value', '0')
        graphics.find('WaterQuality').set('value', '0')
        graphics.find('GrassQuality').set('value', '0')
        graphics.find('ShaderQuality').set('value', '0')
        graphics.find('Shadow_SoftShadows').set('value', '0')
        graphics.find('UltraShadows_Enabled').set('value', 'false')
        graphics.find('Shadow_ParticleShadows').set('value', 'false')
        graphics.find('Shadow_Distance').set('value', '0.500000')
        graphics.find('Shadow_LongShadows').set('value', 'false')
        graphics.find('Shadow_SplitZStart').set('value', '0.930000')
        graphics.find('Shadow_SplitZEnd').set('value', '0.890000')
        graphics.find('Shadow_aircraftExpWeight').set('value', '0.990000')
        graphics.find('Shadow_DisableScreenSizeCheck').set('value', 'true')
        graphics.find('Reflection_MipBlur').set('value', 'false')
        graphics.find('FXAA_Enabled').set('value', 'false')
        graphics.find('TXAA_Enabled').set('value', 'false')
        graphics.find('Lighting_FogVolumes').set('value', 'false')
        graphics.find('Shader_SSA').set('value', 'false')
        graphics.find('DX_Version').set('value', '2')
        graphics.find('CityDensity').set('value', '0.500000')
        graphics.find('PedVarietyMultiplier').set('value', '0.500000')
        graphics.find('VehicleVarietyMultiplier').set('value', '0.500000')
        graphics.find('PostFX').set('value', '0')
        graphics.find('DoF').set('value', 'false')
        graphics.find('HdStreamingInFlight').set('value', 'false')
        graphics.find('MaxLodScale').set('value', '0.100000')
        graphics.find('MotionBlurStrength').set('value', '0.000000')    

        video = root.find('video')
        video.find('VSync').set('value', '0')   

        tree.write(settings_file)  

        print("Ustawienia zostały zmienione na optymalne pod wydajność (FPS).")
    else:
        print(f"Plik settings.xml nie został znaleziony w {settings_file}.")

def disable_background_processes():
    print("Optymalizacja: Wyłączanie procesów w tle...")
    processes = ["OneDrive.exe", "Skype.exe"]
    for process in processes:
        subprocess.call(f"taskkill /f /im {process}", shell=True)

def optimize_registry():
    print("Optymalizacja: Optymalizacja ustawień rejestru...")
    subprocess.call('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "ThumbnailCacheSize" /t REG_DWORD /d 0 /f', shell=True)  # Usuwanie cache miniatur
    subprocess.call('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v "IconsOnly" /t REG_DWORD /d 0 /f', shell=True)
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


def threshold_RAM():
    ram = psutil.virtual_memory().total / (1024 * 1024 * 1024)  # GB

    if ram < 4:
        wartosc = 4194304
    elif ram < 6:
        wartosc = 6291456
    elif ram < 8:
        wartosc = 8388608
    elif ram < 12:
        wartosc = 12582912
    elif ram < 16:
        wartosc = 16777216
    elif ram < 32:
        wartosc = 33554432
    elif ram < 64:
        wartosc = 67108864
    elif ram < 128:
        wartosc = 134217728
    elif ram < 192:
        wartosc = 201326592
    elif ram < 256:
        wartosc = 268435456
    elif ram < 512:
        wartosc = 536870912

    polecenie = f'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d {wartosc} /f'
    subprocess.run(polecenie, shell=True)

def optimize_power_settings():
    print("Optymalizacja: Ustawienia zasilania...")
    subprocess.call('powercfg /change standby-timeout-ac 0', shell=True)  # Wyłącz auto-zamykanie ekranu
    subprocess.call('powercfg /change monitor-timeout-ac 0', shell=True)  # Wyłącz auto-wygaszanie ekranu
    subprocess.call('powercfg /change hibernate-timeout-ac 0', shell=True)  # Wyłącz hibernację

def check_all_processes_complete():
    global proces1, proces2, proces3, proces4, proces5, proces6
    if proces1 and proces2 and proces3 and proces4 and proces5 and proces6:
        RaiseFPS.stop_loading()
        restart = messagebox.askyesno("Optymalizacja zakończona!", "Aby wprowadzić wszystkie zmiany, zalecany jest restart.\nCzy chcesz teraz ponownie uruchomić komputer?")
        if restart:
            os.system("shutdown /r /t 0")

def optimize_pro():
    def run_optimization():
        global proces1
        print("Optymalizacja: PRO Mode w toku...")
        advanced_cleanup()
        optimize_memory()
        disable_background_processes()
        optimize_registry()
        optimize_gaming()
        disable_services()
        fivem_cache()
        threshold_RAM()
        optimize_power_settings()
        changeSettingsGTAV()

        proces1 = True
        check_all_processes_complete()

    optimization_thread = threading.Thread(target=run_optimization)
    optimization_thread.start()

    def regedity_funkcje():
        global proces2
        print("Optymalizacja2 PRO jest w toku...")
        commands = [
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v UploadUserActivities /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v PublishUserActivities /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlyoutMenuSettingsr" /v ShowHibernateOption /t REG_DWORD /d 0 /f',
        'reg add "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Overrides\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration" /v Status /t REG_DWORD /d 0 /f',
        'reg add "HKLM:\\SYSTEM\\Maps" /v AutoUpdateEnabled /t REG_DWORD /d 0 /f',

        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\EdgeUpdate" /v CreateDesktopShortcutDefault /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v PersonalizationReportingEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v ShowRecommendationsEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v UserFeedbackAllowed /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v ConfigureDoNotTrack /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v AlternateErrorPagesEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v EdgeCollectionsEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v EdgeShoppingAssistantEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v MicrosoftEdgeInsiderPromotionEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v PersonalizationReportingEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v ShowMicrosoftRewards /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v WebWidgetAllowed /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v DiagnosticData /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v EdgeAssetDeliveryServiceEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v EdgeCollectionsEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v CryptoWalletEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge" /v WalletDonationEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f',

        'reg add "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f',
        'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f',
        'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f',
        'reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f',
        'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f',
        'reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d 1 /f'
        'reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_DWORD /d 1 /f'
        'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 400 /f'
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d 30 /f',
        'reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f',
    
        'reg add "HKLM\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowWiFiHotSpotReporting" /v Value /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowAutoConnectToWiFiSenseHotspots" /v Value /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f',
        'reg add "HKCU\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 0 /f',
        'reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 200 /f',
        'reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f',
        'reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 3 /f',
        'reg add "HKCU\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarDeveloperSettings" /v TaskbarEndTask /t REG_DWORD /d 1 /f',
        'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\Software\\Policies\\Microsoft\\Windows\\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v ShowCopilotButton /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\System\\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f',
        'reg add "HKCU\\System\\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\System\\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\System\\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters" /v "DisabledComponents" /t REG_DWORD /d 255 /f',
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\System\\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f',
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Search" /v "BingSearchEnabled" /t REG_DWORD /d 1 /f',
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v "BingSearchEnabled" /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Attributes" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_USERS\S-1-5-18\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f',
        'reg add "HKEY_USERS\S-1-5-18\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f',
        'reg add "HKEY_USERS\S-1-5-18\Control Panel\Desktop" /v "FontSmoothingOrientation" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_USERS\S-1-5-18\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_USERS\S-1-5-18\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9e3e038012000000" /f',
        'reg add "HKEY_USERS\S-1-5-18\Control Panel\Desktop" /v "LockScreenAutoLockActive" /t REG_SZ /d "0" /f',
        'reg add "HKEY_USERS\S-1-5-18\Control Panel\Desktop\WindowMetrics" /f',
        'reg add "HKEY_USERS\S-1-5-18\Control Panel\Desktop\MuiCached" /v "MachinePreferredUILanguages" /t REG_BINARY /d "656e2d55530000" /f',
        'reg add "HKEY_USERS\S-1-5-18\Software\Microsoft\MPEG2Demultiplexer" /v "StreamType" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_USERS\S-1-5-18\Software\Microsoft\MPEG2Demultiplexer" /v "WriteCapture" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_USERS\S-1-5-18\Software\Microsoft\MPEG2Demultiplexer" /v "WriteCaptureDir" /t REG_SZ /d "c:\dm.capture\" /f',
        'reg add "HKEY_USERS\S-1-5-18\Software\Microsoft\MPEG2Demultiplexer" /v "WriteCapturePath" /t REG_SZ /d "" /f',
        'reg add "HKEY_CURRENT_CONFIG\System\CurrentControlSet\SERVICES\TSDDD\DEVICE0" /v "Attach.ToDesktop" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "" /t REG_SZ /d "@main.cpl,-1020" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "AppStarting" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f776f726b696e672e616e69" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "Arrow" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "Crosshair" /t REG_BINARY /d "0000" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "Hand" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f6c696e6b2e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "Help" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f68656c7073656c2e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "IBeam" /t REG_BINARY /d "0000" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "No" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f756e617661696c2e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "NWPen" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f70656e2e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "Scheme Source" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "SizeAll" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f6d6f76652e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "SizeNESW" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f6e6573772e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "SizeNS" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f6e732e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "SizeNWSE" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f6e7773652e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "SizeWE" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f65772e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "UpArrow" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f75702e637572" /f',
        'reg add "HKEY_USERS\.DEFAULT\Control Panel\Cursors" /v "Wait" /t REG_BINARY /d "2573797374656d526f6f74255c637572736f725c6165726f5f627573792e616e69" /f',

        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f',
        'reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" /f',
        'reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /t REG_BINARY /d "01 00 00 00" /f',
        'reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 40 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ConvertibleSlateMode" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f',

        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Description" /t REG_BINARY /d "40002500730079007300740065006d0072006f006f00740025005c00730079007300740065006d00330032005c0070006f0077007200700072006f0066002e0064006c006c002c002d0037003600360036002c005300700065006300690066007900200074006800650020006d0069006e0069006d0075006d0020006e0075006d0062006500720020006f006600200075006e007000610072006b0065006400200063006f007200650073002f007000610063006b006100670065007300200061006c006c006f007700650064002000280069006e002000700065007200630065006e007400610067006500290063000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "FriendlyName" /t REG_BINARY /d "40002500730079007300740065006d0072006f006f00740025005c00730079007300740065006d00330032005c0070006f0077007200700072006f0066002e0064006c006c002c002d0037003600370036002c00500072006f0063006500730073006f007200200070006500720066006f0072006d0061006e0063006500200063006f007200650020007000610072006b0069006e00670020006d0069006e00200063006f0072006500730000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueIncrement" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 256 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueUnits" /t REG_BINARY /d "40002500730079007300740065006d0072006f006f00740025005c00730079007300740065006d00330032005c0070006f0077007200700072006f0066002e0064006c006c002c002d00380031000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d 100 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d 10 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ProvAcSettingIndex" /t REG_DWORD /d 100 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ProvDcSettingIndex" /t REG_DWORD /d 100 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d 100 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d 100 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\a1841308-3541-4fab-bc81-f71556f20b4a" /v "AcSettingIndex" /t REG_DWORD /d 10 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\a1841308-3541-4fab-bc81-f71556f20b4a" /v "DcSettingIndex" /t REG_DWORD /d 10 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\a1841308-3541-4fab-bc81-f71556f20b4a" /v "ProvAcSettingIndex" /t REG_DWORD /d 100 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\a1841308-3541-4fab-bc81-f71556f20b4a" /v "ProvDcSettingIndex" /t REG_DWORD /d 100 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\aaa3ffd9-7563-4345-8d15-13f25a74249c" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "AcPolicy" /t REG_BINARY /d "0100000006000000030000000000000002000000030000000000000002000000010000000000000000000000001805f06000200000001000000000000000000000000300000010000000020000000000000000000000000000000000000000300000000000000000000000000000000b00400000000000000000000000000000000000000000c91b0400000000000000000000000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "AcProcessorPolicy" /t REG_BINARY /d "0100000000000000000000000003000000a0860100a0860100a0860100283200000002000000a0860100a0860100a0860100283c00000003000000a0860100a0860100a0860100285000000001000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "DcPolicy" /t REG_BINARY /d "01000000060000000300000000000000020000000300000000000000020000000100000001000000313200020000000000000000000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "DcProcessorPolicy" /t REG_BINARY /d "0100000003000000000000000003000000a0860100a0860100a08601000a1400000002000000a0860100a0860100a0860100142800000003000000a0860100a0860100a0860100144600000001000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HBFlagsSwitch" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "PowerSettingProfile" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDeviceAccountingLevel" /t REG_DWORD /d 4 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "WatchdogResumeTimeout" /t REG_DWORD /d 120 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "WatchdogSleepTimeout" /t REG_DWORD /d 300 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "POSTTime" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "BootmgrUserInputTime" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "FwPOSTTime" /t REG_DWORD /d 8909 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SystemPowerPolicy" /t REG_BINARY /d "01000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "TotalResumeTime" /t REG_DWORD /d 12400 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeBootMgrTime" /t REG_DWORD /d 304 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeAppTime" /t REG_DWORD /d 632 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeAppStartTimestamp" /t REG_DWORD /d 9528 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeLibraryInitTime" /t REG_DWORD /d 39 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeInitTime" /t REG_DWORD /d 109 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeHiberFileTime" /t REG_DWORD /d 427 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeRestoreImageStartTimestamp" /t REG_DWORD /d 9658 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeIoTime" /t REG_DWORD /d 185 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeDecompressTime" /t REG_DWORD /d 204 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeMapTime" /t REG_DWORD /d 37 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeUnmapTime" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeUserInOutTime" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeAllocateTime" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeKernelSwitchTimestamp" /t REG_DWORD /d 1000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelReturnFromHandlerTimestamp" /t REG_DWORD /d 999 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleeperThreadEndTimestamp" /t REG_DWORD /d 120 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "TimeStampCounterAtSwitchTime" /t REG_DWORD /d 610 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelReturnSystemPowerState" /t REG_DWORD /d 785 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberHiberFileTime" /t REG_DWORD /d 284 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberInitTime" /t REG_DWORD /d 988 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberSharedBufferTime" /t REG_DWORD /d 4 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "TotalHibernateTime" /t REG_DWORD /d 2890 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelResumeHiberFileTime" /t REG_DWORD /d 517 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelResumeInitTime" /t REG_DWORD /d 186 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelResumeSharedBufferTime" /t REG_DWORD /d 10 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "DeviceResumeTime" /t REG_DWORD /d 442 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelAnimationTime" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelPagesProcessed" /t REG_DWORD /d 4849190 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelPagesWritten" /t REG_BINARY /d "0c85020000000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "BootPagesProcessed" /t REG_DWORD /d 44017 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "BootPagesWritten" /t REG_BINARY /d "8949000000000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberWriteRate" /t REG_DWORD /d 267 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberCompressRate" /t REG_DWORD /d 36 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeReadRate" /t REG_DWORD /d 443 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeDecompressRate" /t REG_DWORD /d 131 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "FileRuns" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "NoMultiStageResumeReason" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "MaxHuffRatio" /t REG_DWORD /d 99 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SecurePagesProcessed" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberChecksumTime" /t REG_DWORD /d 157 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberChecksumIoTime" /t REG_DWORD /d 9 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeChecksumTime" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeChecksumIoTime" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelChecksumTime" /t REG_DWORD /d 108 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelChecksumIoTime" /t REG_DWORD /d 7 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "KernelResumeIoCpuTime" /t REG_DWORD /d 1156 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberIoCpuTime" /t REG_DWORD /d 551 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "ResumeCompleteTimestamp" /t REG_BINARY /d "b78ff90200000000" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HybridBootAnimationTime" /t REG_DWORD /d 1998 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "AwayModeEnabled" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HibernateEnabled" /t REG_DWORD /d 1 /f',
        

        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D" /v "MaxPreRenderedFrames" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers\Direct3D HAL" /v "Base" /t REG_SZ /d "hal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers\Direct3D HAL" /v "Description" /t REG_SZ /d "Microsoft Direct3D Hardware acceleration through Direct3D HAL" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers\Direct3D HAL" /v "GUID" /t REG_BINARY /d "e03de684aa46cf11816f0000c020156e" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers\Ramp Emulation" /v "Base" /t REG_SZ /d "ramp" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers\Ramp Emulation" /v "Description" /t REG_SZ /d "Microsoft Direct3D Mono(Ramp) Software Emulation" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers\Ramp Emulation" /v "GUID" /t REG_BINARY /d "206b08f29f25cf11a31a00aa00b93356" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers\RGB Emulation" /v "Base" /t REG_SZ /d "rgb" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers\RGB Emulation" /v "Description" /t REG_SZ /d "Microsoft Direct3D RGB Software Emulation" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers\RGB Emulation" /v "GUID" /t REG_BINARY /d "605c66a47326cf11a31a00aa00b93356" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\DX6TextureEnumInclusionList" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\DX6TextureEnumInclusionList\16 bit Bump DuDv" /v "ddpf" /t REG_SZ /d "00080000 0 16 ff ff00 0 0" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\DX6TextureEnumInclusionList\16 bit BumpLum DuDv" /v "ddpf" /t REG_SZ /d "000C0000 0 16 1f 3e0 fc00 0" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\DX6TextureEnumInclusionList\16 bit Luminance Alpha" /v "ddpf" /t REG_SZ /d "00020001 0 16 ff 0 0 ff00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\DX6TextureEnumInclusionList\24 bit BumpLum DuDv" /v "ddpf" /t REG_SZ /d "000C0000 0 24 ff ff00 ff0000 0" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\DX6TextureEnumInclusionList\8 bit Luminance" /v "ddpf" /t REG_SZ /d "00020000 0  8 ff 0 0 0" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Direct3D\MostRecentApplication" /v "Name" /t REG_SZ /d "get-graphics-offsets32.exe" /f',

        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DataBasePath" /t REG_BINARY /d "25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Domain" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ForwardBroadcasts" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ICSDomain" /t REG_SZ /d "mshome.net" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NameServer" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SyncDomainWithMembership" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "Mubeen" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "Mubeen" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SearchList" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "UseDomainNameDevolution" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DeadGWDetectDefault" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DontAddDefaultGatewayDefault" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d 65535 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpCacheLife" /t REG_DWORD /d 1800 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpCacheMinReferencedLife" /t REG_DWORD /d 3600 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpCacheSize" /t REG_DWORD /d 200 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d 30 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d 48 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPEnableRouter" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NameSrvQueryTimeout" /t REG_DWORD /d 3000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d 100 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DhcpNameServer" /t REG_SZ /d "168.192.3.1" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "LLInterface" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "IpConfig" /t REG_BINARY /d "54 00 63 00 70 00 69 00 70 00 5c 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 5c 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 73 00 5c 00 7b 00 33 00 33 00 42 00 46 00 32 00 45 00 30 00 38 00 2d 00 46 00 34 00 38 00 41 00 2d 00 34 00 39 00 42 00 35 00 2d 00 41 00 41 00 34 00 36 00 2d 00 31 00 37 00 37 00 37 00 45 00 42 00 43 00 37 00 44 00 31 00 42 00 30 00 7d 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "LLInterface" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "IpConfig" /t REG_BINARY /d "54 00 63 00 70 00 69 00 70 00 5c 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 5c 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 73 00 5c 00 7b 00 38 00 42 00 46 00 31 00 33 00 41 00 38 00 36 00 2d 00 31 00 31 00 38 00 43 00 2d 00 34 00 31 00 43 00 31 00 2d 00 39 00 36 00 45 00 44 00 2d 00 33 00 43 00 41 00 34 00 37 00 36 00 42 00 42 00 45 00 30 00 43 00 42 00 7d 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "LLInterface" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "IpConfig" /t REG_BINARY /d "54 00 63 00 70 00 69 00 70 00 5c 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 5c 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 73 00 5c 00 7b 00 41 00 43 00 44 00 38 00 43 00 34 00 35 00 37 00 2d 00 45 00 44 00 38 00 46 00 2d 00 34 00 34 00 41 00 44 00 2d 00 41 00 37 00 44 00 38 00 2d 00 42 00 37 00 38 00 42 00 35 00 44 00 43 00 33 00 38 00 35 00 39 00 32 00 7d 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{e1977e62-1b70-4cc3-8c20-34aa2c71792e}" /v "LLInterface" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{e1977e62-1b70-4cc3-8c20-34aa2c71792e}" /v "IpConfig" /t REG_BINARY /d "54 00 63 00 70 00 69 00 70 00 5c 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 5c 00 49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 73 00 5c 00 7b 00 45 00 31 00 39 00 37 00 37 00 45 00 36 00 32 00 2d 00 31 00 42 00 37 00 30 00 2d 00 34 00 43 00 43 00 33 00 2d 00 38 00 43 00 32 00 30 00 2d 00 33 00 34 00 41 00 41 00 32 00 43 00 37 00 31 00 37 00 39 00 32 00 45 00 7d 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters" /f',

        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpDelAckTicks" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DisableTaskOffload" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "EnableDHCP" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "Domain" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "NameServer" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpIPAddress" /t REG_SZ /d "168.192.3.102" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpSubnetMask" /t REG_SZ /d "255.255.255.0" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpServer" /t REG_SZ /d "168.192.3.1" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "Lease" /t REG_DWORD /d 43000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "LeaseObtainedTime" /t REG_DWORD /d 1740233856 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "T1" /t REG_DWORD /d 1740235592 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "T2" /t REG_DWORD /d 1740236505 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "LeaseTerminatesTime" /t REG_DWORD /d 1740237794 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "AddressType" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "IsServerNapAware" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpConnForceBroadcastFlag" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpInterfaceOptions" /t REG_BINARY /d "fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 77 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 2f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 2e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 2c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 2b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 1f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9a 7b 00 00 06 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 3a 27 a8 c0 a8 c0 03 01 03 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 3a 27 a8 c0 a8 c0 03 01 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 3a 27 a8 c0 ff ff ff 00 33 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 3a 27 a8 c0 00 00 a8 c0 36 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 3a 27 a8 c0 a8 c0 03 01 35 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 3a 27 a8 c0 05 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "RegistrationEnabled" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "RegisterAdapterName" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpNameServer" /t REG_SZ /d "168.192.3.1" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpDefaultGateway" /t REG_BINARY /d "31 00 36 00 38 00 2e 00 31 00 39 00 32 00 2e 00 33 00 2e 00 31 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpSubnetMaskOpt" /t REG_BINARY /d "32 00 35 00 35 00 2e 00 32 00 35 00 35 00 2e 00 32 00 35 00 35 00 2e 00 30 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpGatewayHardware" /t REG_BINARY /d "a8 c0 03 01 06 00 00 00 de b8 4b d2 fc 71" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{33bf2e08-f48a-49b5-aa46-1777ebc7d1b0}" /v "DhcpGatewayHardwareCount" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "EnableDHCP" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "Domain" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "NameServer" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpIPAddress" /t REG_SZ /d "192.168.100.63" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpSubnetMask" /t REG_SZ /d "255.255.255.0" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpServer" /t REG_SZ /d "192.168.100.1" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "Lease" /t REG_DWORD /d 86400 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "LeaseObtainedTime" /t REG_DWORD /d 1740236047 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "T1" /t REG_DWORD /d 1740237673 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "T2" /t REG_DWORD /d 1740238553 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "LeaseTerminatesTime" /t REG_DWORD /d 1740240029 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "AddressType" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "IsServerNapAware" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpConnForceBroadcastFlag" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpInterfaceOptions" /t REG_BINARY /d "fc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 77 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 2f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 2e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 2c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 2b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 1f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1b 12 00 00 06 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 1b 12 0c 1f 01 51 80 c0 a8 64 01 03 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 1b 12 0c 1f 01 51 80 c0 a8 64 01 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 1b 12 0c 1f 01 51 80 ff ff ff 00 33 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 1b 12 0c 1f 01 51 80 00 00 a8 c0 36 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 1b 12 0c 1f 01 51 80 c0 a8 64 01 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 1b 12 0c 1f 01 51 80 05 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "RegistrationEnabled" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "RegisterAdapterName" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpNameServer" /t REG_SZ /d "192.168.100.1" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpDefaultGateway" /t REG_BINARY /d "31 00 39 00 32 00 2e 00 31 00 36 00 38 00 2e 00 31 00 30 00 30 00 2e 00 31 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpSubnetMaskOpt" /t REG_BINARY /d "32 00 35 00 35 00 2e 00 32 00 35 00 35 00 2e 00 32 00 35 00 35 00 2e 00 30 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpGatewayHardware" /t REG_BINARY /d "c0 a8 64 01 0, 00 00 00 bc 3f 8f 4f 8b 9b" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{8bf13a86-118c-41c1-96ed-3ca476bbe0cb}" /v "DhcpGatewayHardwareCount" /t REG_DWORD /d 1 /f',

        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "EnableDHCP" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "Domain" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "NameServer" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "DhcpIPAddress" /t REG_SZ /d "192.168.143.192" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "DhcpSubnetMask" /t REG_SZ /d "255.255.255.0" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "DhcpServer" /t REG_SZ /d "192.168.143.240" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "Lease" /t REG_DWORD /d 603 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "LeaseObtainedTime" /t REG_DWORD /d 1740207212 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "T1" /t REG_DWORD /d 1740207404 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "T2" /t REG_DWORD /d 1740207514 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "LeaseTerminatesTime" /t REG_DWORD /d 1740207518 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "AddressType" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "IsServerNapAware" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "DhcpConnForceBroadcastFlag" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "DhcpNameServer" /t REG_SZ /d "192.168.143.240" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "DhcpDefaultGateway" /t REG_BINARY /d "31 00 39 00 32 00 2e 00 31 00 36 00 38 00 2e 00 31 00 34 00 33 00 2e 00 32 00 34 00 30 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "DhcpSubnetMaskOpt" /t REG_BINARY /d "32 00 35 00 35 00 2e 00 32 00 35 00 35 00 2e 00 32 00 35 00 35 00 2e 00 30 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "DhcpGatewayHardware" /t REG_BINARY /d "c0 a8 8f f0 06 00 00 00 e2 e9 55 60 ba 0b" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{acd8c457-ed8f-44ad-a7d8-b78b5dc38592}" /v "DhcpGatewayHardwareCount" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{d02fa20f-5819-11ee-be6f-806e6f6e6963}" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{e1977e62-1b70-4cc3-8c20-34aa2c71792e}" /v "EnableDHCP" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{e1977e62-1b70-4cc3-8c20-34aa2c71792e}" /v "Domain" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{e1977e62-1b70-4cc3-8c20-34aa2c71792e}" /v "NameServer" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{e1977e62-1b70-4cc3-8c20-34aa2c71792e}" /v "RegistrationEnabled" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{e1977e62-1b70-4cc3-8c20-34aa2c71792e}" /v "RegisterAdapterName" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes" /f',

        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "UseDelayedAcceptance" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d 16 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d 16 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "HelperDllName" /t REG_BINARY /d "25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 73 00 68 00 74 00 63 00 70 00 69 00 70 00 2e 00 64 00 6c 00 6c 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "ProviderGUID" /t REG_BINARY /d "a0 1a 0f e7 8b ab cf 11 8c a3 00 80 5f 48 a1 92" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "OfflineCapable" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "Mapping" /t REG_BINARY /d "08 00 00 00 03 00 00 00 02 00 00 00 01 00 00 00 06 00 00 00 02 00 00 00 01 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 06 00 00 00 02 00 00 00 02 00 00 00 11 00 00 00 02 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 11 00 00 00 02 00 00 00 03 00 00 00 ff 00 00 00 02 00 00 00 03 00 00 00 00 00 00 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "Version" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "AddressFamily" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "MaxSockAddrLength" /t REG_DWORD /d 16 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "MinSockAddrLength" /t REG_DWORD /d 16 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "SocketType" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "Protocol" /t REG_DWORD /d 6 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "ProtocolMaxOffset" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "ByteOrder" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "MessageSize" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "szProtocol" /t REG_BINARY /d "40 00 25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 77 00 73 00 6f 00 63 00 6b 00 2e 00 64 00 6c 00 6c 00 2c 00 2d 00 36 00 30 00 31 00 30 00 30 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "ProviderFlags" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\0" /v "ServiceFlags" /t REG_DWORD /d 0x00020066 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "Version" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "AddressFamily" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "MaxSockAddrLength" /t REG_DWORD /d 16 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "MinSockAddrLength" /t REG_DWORD /d 16 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "SocketType" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "Protocol" /t REG_DWORD /d 11 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "ProtocolMaxOffset" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "ByteOrder" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "MessageSize" /t REG_DWORD /d 65527 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "szProtocol" /t REG_BINARY /d "40 00 25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 77 00 73 00 6f 00 63 00 6b 00 2e 00 64 00 6c 00 6c 00 2c 00 2d 00 36 00 30 00 31 00 30 00 31 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "ProviderFlags" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\1" /v "ServiceFlags" /t REG_DWORD /d 0x00020609 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "Version" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "AddressFamily" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "MaxSockAddrLength" /t REG_DWORD /d 16 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "MinSockAddrLength" /t REG_DWORD /d 16 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "SocketType" /t REG_DWORD /d 3 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "Protocol" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "ProtocolMaxOffset" /t REG_DWORD /d 255 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "ByteOrder" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "MessageSize" /t REG_DWORD /d 32768 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "szProtocol" /t REG_BINARY /d "40 00 25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 77 00 73 00 6f 00 63 00 6b 00 2e 00 64 00 6c 00 6c 00 2c 00 2d 00 36 00 30 00 31 00 30 00 32 00" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "ProviderFlags" /t REG_DWORD /d 12 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock\2" /v "ServiceFlags" /t REG_DWORD /d 0x00020609 /f',
    

        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "BackgroundPriority" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "NoLazyMode" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 14 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SchedulingCategory" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "FSIO Priority" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 16 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d 6 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d 5 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d 4 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "BackgroundPriority" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "NoLazyMode" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "BackgroundPriority" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d 4 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d 3 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d 5 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 14 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d 6 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d 5 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',

        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d 4 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "BackgroundPriority" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "NoLazyMode" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 14 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SchedulingCategory" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "FSIO Priority" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "BackgroundPriority" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d 4 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d 3 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d 10000 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d 8 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d 5 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f',


        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Debugging" /v "EnableHyperThreading" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Debugging" /v "EnableTurboBoost" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemProfile" /v "PowerSaver" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemProfile" /v "MaximumPerformance" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemProfile" /v "LowLatency" /t REG_DWORD /d 1 /f',
        "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\" /v \"HighPerformance\" /t REG_DWORD /d 1 /f",
        "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v \"NoAutoUpdate\" /t REG_DWORD /d 1 /f",
        "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"NoAutoUpdate\" /t REG_DWORD /d 1 /f",
        "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\" /v \"NoAutoUpdate\" /t REG_DWORD /d 1 /f",
        "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiVirus\" /t REG_DWORD /d 1 /f",
        "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v \"DisableSearchBoxSuggestions\" /t REG_DWORD /d 1 /f",
        "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v \"DisableSearchBoxSuggestions\" /t REG_DWORD /d 1 /f",
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "Shadow" /t REG_SZ /d "0" /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "DoubleClickHeight" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "VisualFX" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "SnapSizing" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /v "MaxRecentDocs" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex" /v "CleanIndex" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMI" /v "Start" /t REG_DWORD /d 4 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSync" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "SomeApp" /t REG_SZ /d "" /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoDisconnect" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableOpLock" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MinAnimate" /t REG_SZ /d "0" /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneEnabled" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v "AudioMuted" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration" /v "TdrDelay" /t REG_DWORD /d 10 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\{A0A02271-20AF-4BB8-A724-319D3A69A41D}\{6D7B0EA2-019A-4934-A684-38C9E3F8C3E1}" /v "PowerSettingValue" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d 128 /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "DisableThumbnailCache" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnsevent" /v "EventID" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "FontSmoothing" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" /v "Counter" /t REG_DWORD /d 1000 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "BackgroundAppUsage" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EventLog" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisableSoftKey" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingExecutive" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisabledHotkeys" /t REG_SZ /d "" /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoUpdate" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NoDeviceTracking" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "90 12 01 80" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfDisk\Performance" /v "Disable Performance Counters" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsStore" /v "AutoUpdate" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d 4 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxSuggestionsEnabled" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech\Voices\Tokens\.VoiceName" /v "Name" /t REG_SZ /d "" /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "BackgroundAccessApplicationsEnabled" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Disk" /v "Timeout" /t REG_DWORD /d 30 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\QualityOfService" /v "EnableQoS" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d 65534 /f',
        'reg add "HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\.Default\.Current" /v "" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\{12E1D2D8-A1E7-4874-BB9D-D028A400001E}" /v "PowerSettingValue" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DhcpConnForceBroadcastFlag" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "UseWUServer" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableCaching" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main" /v "UseSSL" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanworkstation\parameters" /v "MaxCmds" /t REG_DWORD /d 20 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLED" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d 65534 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "EfsEnabled" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d 4 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\OneDrive" /v "DisableSkyDrive" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_SZ /d "C:\pagefile.sys 2048 4096" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d 86400 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoVideo" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP" /v "SkipRearm" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local" /v "EFS" /t REG_BINARY /d 00 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PeerNetworking\Parameters" /v "Enable" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ChangeStartMenuAnimation" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoViewContextMenu" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartMenuAnimation" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d 30 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "BackgroundTimer" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /ve /t REG_SZ /d "" /f',
        'reg add "HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Colors" /v "Background" /t REG_SZ /d "0 0 0" /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "" /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "TileWallpaper" /t REG_SZ /d "0" /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WallpaperStyle" /t REG_SZ /d "0" /f',

        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "PowerMizerEnable" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "PowerMizerDefault" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "PowerMizerMaxPerf" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "SyncToVBlank" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "MultiGPU" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "AnisotropicFiltering" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Software\NVIDIA Corporation\Global\NVTweak" /v "MaxPerformance" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Software\NVIDIA Corporation\Global\NVTweak" /v "PreferMaxPerformance" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Software\NVIDIA Corporation\Global\NVTweak" /v "AppProfileEnabled" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_CURRENT_USER\Software\NVIDIA Corporation\Global\NVTweak" /v "DisableEffects" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "Direct3D" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "SetColorDepth" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NVTweak" /v "GameProfileEnable" /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v PowerMizerLevel /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v PowerMizerLevelAC /t REG_DWORD /d 1 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v PerfLevelSrc /t REG_DWORD /d 2 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v EnablePerfLevelAC /t REG_DWORD /d 1 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v LowLatencyMode /t REG_DWORD /d 2 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v OGL_ThreadControl /t REG_DWORD /d 2 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v TextureFilteringQuality /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v VSYNCMODE /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v OGL_TripleBuffer /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v FlipQueueSize /t REG_DWORD /d 1 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v ThreadedOptimization /t REG_DWORD /d 1 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v ShaderCache /t REG_DWORD /d 1 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v ShaderCacheSize /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v AllowGSYNC /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v PrerenderLimit /t REG_DWORD /d 1 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v PowerSavingMode /t REG_DWORD /d 0 /f',
        'reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak" /v EnableUlps /t REG_DWORD /d 0 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v TdrLevel /t REG_DWORD /d 0 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v TdrDelay /t REG_DWORD /d 10 /f',
        'reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v TdrDdiDelay /t REG_DWORD /d 10 /f',
        'reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "VisualFXSetting" /t REG_DWORD /d 2 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 26 /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "LatencySensitive" /t REG_SZ /d "True" /f',
        'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search" /v "SetupCompleted" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "StartupApp" /t REG_SZ /d "" /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableCaching" /t REG_DWORD /d 1 /f',
        'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 0 /f',
    
    ]

        for command in commands:
            try:
                subprocess.call(command, shell=True)
                print(f"Wykonano: {command}")
            except Exception as e:
                print(f"Błąd podczas wykonywania {command}: {str(e)}")

        proces2 = True
        check_all_processes_complete()

    optimization8_thread = threading.Thread(target=regedity_funkcje)
    optimization8_thread.start()


    def PowerShell_funcja():
        global proces3
        print("Optymalizacja2 PRO jest w toku...")
        commands = [
            "PowerShell -Command \"Import-Module -DisableNameChecking $PSScriptRoot\\..\\lib\\force-mkdir.psm1\"",
            "PowerShell -Command \"force-mkdir 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection'\"",
            "PowerShell -Command \"$hosts_file = '$env:SystemRoot\\System32\\drivers\\etc\\hosts'; \
    $domains = @(\n"
            + "\"184-86-53-99.deploy.static.akamaitechnologies.com\",\n"
            + "\"a-0001.a-msedge.net\",\n"
            + "\"a-0002.a-msedge.net\",\n"
            + "\"a-0003.a-msedge.net\",\n"
            + "\"a-0004.a.msedge.net\",\n"
            + "\"a-0005.a-msedge.net\",\n"
            + "\"a-0006.a-msedge.net\",\n"
            + "\"a-0007.a-msedge.net\",\n"
            + "\"a-0008.a-msedge.net\",\n"
            + "\"a-0009.a-msedge.net\",\n"
            + "\"a1621.g.akamai.net\",\n"
            + "\"a1856.g2.akamai.net\",\n"
            + "\"a1961.g.akamai.net\",\n"
            + "\"a978.i6g1.akamai.net\",\n"
            + "Write-Output '' | Out-File -Encoding ASCII -Append $hosts_file;"
            + "foreach ($domain in $domains) { if (-Not (Select-String -Path $hosts_file -Pattern $domain)) { Write-Output \"0.0.0.0 $domain\" | Out-File -Encoding ASCII -Append $hosts_file } }\"",
            
            # Dodawanie IP do zapory
            "PowerShell -Command \"Write-Output 'Adding telemetry ips to firewall'; \
            $ips = @('134.170.30.202', '137.116.81.24', '157.56.106.189', '184.86.53.99', '2.22.61.43', '2.22.61.66', \
            '204.79.197.200', '23.218.212.69', '65.39.117.230', '65.55.108.23', '64.4.54.254'); \
            Remove-NetFirewallRule -DisplayName 'Block Telemetry IPs' -ErrorAction SilentlyContinue; \
            New-NetFirewallRule -DisplayName 'Block Telemetry IPs' -Direction Outbound -Action Block -RemoteAddress ([string[]]$ips)\"",

            # Wyłączenie usług
            "PowerShell -Command \"$services = @('diagnosticshub.standardcollector.service', 'DiagTrack', 'dmwappushservice', \
            'HomeGroupListener', 'HomeGroupProvider', 'lfsvc', 'MapsBroker', 'NetTcpPortSharing', 'RemoteAccess', \
            'RemoteRegistry', 'SharedAccess', 'TrkWks', 'WbioSrvc', 'WMPNetworkSvc', 'wscsvc', 'XblAuthManager', \
            'XblGameSave', 'XboxNetApiSvc', 'ndu'); \
            foreach ($service in $services) { \
            Write-Output 'Trying to disable ' + $service; \
            Get-Service -Name $service | Set-Service -StartupType Disabled }\"",

            "PowerShell -Command \"Import-Module -DisableNameChecking $PSScriptRoot\\..\\lib\\take-own.psm1\"",
            "PowerShell -Command \"Write-Output 'Elevating privileges for this process'\"",
            "PowerShell -Command \"do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)\"",
            "PowerShell -Command \"$tasks = @('\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance', \
            '\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup', \
            '\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan', \
            '\\Microsoft\\Windows\\Windows Defender\\Windows Defender Verification')\"",
            "PowerShell -Command \"foreach ($task in $tasks) { \
                $parts = $task.split('\\'); \
                $name = $parts[-1]; \
                $path = $parts[0..($parts.length-2)] -join '\\'; \
                Write-Output 'Trying to disable scheduled task ' + $name; \
                Disable-ScheduledTask -TaskName \"$name\" -TaskPath \"$path\" \
            }\"",
            "PowerShell -Command \"Write-Output 'Disabling Windows Defender via Group Policies'\"",
            "PowerShell -Command \"force-mkdir 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender' 'DisableAntiSpyware' 1\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender' 'DisableRoutinelyTakingAction' 1\"",
            "PowerShell -Command \"force-mkdir 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection'\"",
            "PowerShell -Command \"Write-Output 'Disabling Windows Defender Services'\"",
            "PowerShell -Command \"Takeown-Registry('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend')\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SYSTEM\\CurrentControlSet\\Services\\WinDefend' 'Start' 4\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SYSTEM\\CurrentControlSet\\Services\\WinDefend' 'AutorunsDisabled' 3\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc' 'Start' 4\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc' 'AutorunsDisabled' 3\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SYSTEM\\CurrentControlSet\\Services\\Sense' 'Start' 4\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SYSTEM\\CurrentControlSet\\Services\\Sense' 'AutorunsDisabled' 3\"",
            "PowerShell -Command \"Write-Output 'Removing Windows Defender context menu item'\"",
            "PowerShell -Command \"Set-Item 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Classes\\CLSID\\{09A47860-11B0-4DA5-AFA5-26D86198A780}\\InprocServer32' ''\"",
            "PowerShell -Command \"Write-Output 'Removing Windows Defender GUI / tray from autorun'\"",
            "PowerShell -Command \"Remove-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' 'WindowsDefender' -ea 0\"",           

            "PowerShell -Command \"Write-Output 'Force removing system apps'\""
            "PowerShell -Command \"$needles = @('BioEnrollment', 'ContactSupport', 'Cortana', 'Defender', 'Feedback', 'Flash', 'Gaming', 'InternetExplorer', 'Maps', 'OneDrive', 'SecHealthUI', 'Wallet')\""
            "PowerShell -Command \"foreach ($needle in $needles) {\""
            "PowerShell -Command \"Write-Output 'Trying to remove all packages containing ' + $needle\""
            "PowerShell -Command \"$pkgs = (Get-ChildItem 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages' | Where-Object Name -Like '*$needle*')\""
            "PowerShell -Command \"foreach ($pkg in $pkgs) {\""
            "PowerShell -Command \"$pkgname = $pkg.Name.split('\\')[-1]\""
            "PowerShell -Command \"Takeown-Registry($pkg.Name)\""
            "PowerShell -Command \"Takeown-Registry($pkg.Name + '\\Owners')\""
            "PowerShell -Command \"Set-ItemProperty -Path ('HKEY_LOCAL_MACHINE:' + $pkg.Name.Substring(18)) -Name Visibility -Value 1\""
            "PowerShell -Command \"New-ItemProperty -Path ('HKEY_LOCAL_MACHINE:' + $pkg.Name.Substring(18)) -Name DefVis -PropertyType DWord -Value 2\""
            "PowerShell -Command \"Remove-Item -Path ('HKEY_LOCAL_MACHINE:' + $pkg.Name.Substring(18) + '\\Owners')\""
            "PowerShell -Command \"dism.exe /Online /Remove-Package /PackageName:$pkgname /NoRestart\""
            "PowerShell -Command \"}\""
            "PowerShell -Command \"}\""


            "PowerShell -Command \"force-mkdir 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Personalization\\Settings'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Personalization\\Settings' 'AcceptedPrivacyPolicy' 0\"",
            "PowerShell -Command \"force-mkdir 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\InputPersonalization\\TrainedDataStore'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\InputPersonalization\\TrainedDataStore' 'HarvestContacts' 0\"",
            "PowerShell -Command \"force-mkdir 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\InputPersonalization'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\InputPersonalization' 'RestrictImplicitInkCollection' 1\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\InputPersonalization' 'RestrictImplicitTextCollection' 1\"",
            "PowerShell -Command \"force-mkdir 'HKEY_CURRENT_USER:\\SOFTWARE\\Classes\\Local Settings\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\Main'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Classes\\Local Settings\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\Main' 'DoNotTrack' 1\"",
            "PowerShell -Command \"force-mkdir 'HKEY_CURRENT_USER:\\SOFTWARE\\Classes\\Local Settings\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\User\\Default\\SearchScopes'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Classes\\Local Settings\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\User\\Default\\SearchScopes' 'ShowSearchSuggestionsGlobal' 0\"",
            "PowerShell -Command \"force-mkdir 'HKEY_CURRENT_USER:\\SOFTWARE\\Classes\\Local Settings\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\FlipAhead'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Classes\\Local Settings\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\FlipAhead' 'FPEnabled' 0\"",
            "PowerShell -Command \"force-mkdir 'HKEY_CURRENT_USER:\\SOFTWARE\\Classes\\Local Settings\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\PhishingFilter'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Classes\\Local Settings\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\PhishingFilter' 'EnabledV9' 0\"",
            "PowerShell -Command \"foreach ($key in Get-ChildItem 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications') { Set-ItemProperty (\"HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications\\\" + $key.PSChildName) 'Disabled' 1 }\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceAccess\\Global\\LooselyCoupled' 'Value' 'Deny'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceAccess\\Global\\LooselyCoupled' 'Type' 'LooselyCoupled'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceAccess\\Global\\LooselyCoupled' 'InitialAppValue' 'Unspecified'\"",
            "PowerShell -Command \"force-mkdir 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Permissions\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Permissions\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' 'SensorPermissionState' 0\"",
            "PowerShell -Command \"Takeown-Registry 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet'; Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet' 'SpyNetReporting' 0; Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet' 'SubmitSamplesConsent' 0\"",
            "PowerShell -Command \"force-mkdir 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\features\\' + (New-Object System.Security.Principal.NTAccount($env:UserName).Translate([System.Security.Principal.SecurityIdentifier]).Value)\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\features\\' + (New-Object System.Security.Principal.NTAccount($env:UserName).Translate([System.Security.Principal.SecurityIdentifier]).Value) 'FeatureStates' 0x33c\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\features' 'WiFiSenseCredShared' 0\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\features' 'WiFiSenseOpen' 0\"",
            "PowerShell -Command \"force-mkdir 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR'; Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR' 'AllowgameDVR' 0\"",
            "PowerShell -Command \"New-ItemProperty HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer -Name DisableEdgeDesktopShortcutCreation -PropertyType DWORD -Value 1\""
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
            "PowerShell -Command \"Get-AppxPackage | Where-Object {$_.Name -notlike '*Microsoft.*'} | Remove-AppxPackage\"",
            "PowerShell -Command \"Remove-Item -Path $env:TEMP\\* -Recurse -Force\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' 'DisableLockWorkstation' 1\"",
            "PowerShell -Command \"Clear-WebBrowserIE; Clear-WebBrowserCache\"",
            "PowerShell -Command \"Get-StartupProcess | Where-Object { $_.Enabled -eq 'True' } | Disable-StartupProcess\"",
            "PowerShell -Command \"Set-Service -Name WSearch -StartupType Disabled; Stop-Service -Name WSearch\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Store' 'AutoUpdate' 0\"",
            "PowerShell -Command \"Set-Service -Name PNRPsvc -StartupType Disabled; Stop-Service -Name PNRPsvc\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_LOCAL_MACHINE:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc' 'DisableUnifiedPolicy' 1\"",
            "PowerShell -Command \"Set-Service -Name WerSvc -StartupType Disabled; Stop-Service -Name WerSvc\"",
            "PowerShell -Command \"Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage\"",
            "PowerShell -Command \"Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage\"",
            "PowerShell -Command \"Set-Service -Name wuauserv -StartupType Disabled\""
            "PowerShell -Command \"sc config WerSvc start= disabled\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SettingSync' 'SyncDisabled' 1\"",
            "PowerShell -Command \"schtasks /Change /TN '\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start' /DISABLE\"",
            "PowerShell -Command \"Get-WindowsFeature -Name Media* | Remove-WindowsFeature\"",
            "PowerShell -Command \"Set-ItemProperty 'HKEY_CURRENT_USER:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo' 'Enabled' 0\"",
            "PowerShell -Command \"Clear-WebBrowserIE\"",
            "PowerShell -Command \"Set-Service -Name SysMain -StartupType Disabled; Stop-Service -Name SysMain\"",
            "PowerShell -Command \"bcdedit /set {current} bootstatuspolicy ignoreallfailures\"",

            "PowerShell -Command \"Get-WmiObject -Query 'SELECT * FROM Win32_Product WHERE Name LIKE ''McAfee%''' | ForEach-Object { $_.Uninstall() }\"",
            "PowerShell -Command \"Remove-Item 'C:\Program Files\McAfee' -Recurse -Force; Remove-Item 'C:\Program Files (x86)\McAfee' -Recurse -Force; Remove-Item 'C:\ProgramData\McAfee' -Recurse -Force\"",
            "PowerShell -Command \"Remove-Item 'HKLM:\SOFTWARE\McAfee' -Recurse -Force -ErrorAction SilentlyContinue\"",
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

        proces3 = True
        check_all_processes_complete()

    optimization3_thread = threading.Thread(target=PowerShell_funcja)
    optimization3_thread.start()


    def bcdedit_funcja():
        global proces4
        print("Optymalizacja2 PRO jest w toku...")
        commands = [
            "bcdedit /set disabledynamictick yes > nul",
            "bcdedit /set useplatformtick yes > nul",
            "bcdedit /set tscsyncpolicy enhanced > nul",
            "bcdedit /set tpmbootentropy ForceDisable > nul",
            "bcdedit /set hypervisorlaunchtype off > nul",
            "bcdedit /set quietboot yes > nul",
            "bcdedit /timeout 0 > nul",
            "bcdedit /set allowedinmemorysettings 0x0 > nul",
            "bcdedit /set isolatedcontext No > nul",
            "bcdedit /set nx alwaysoff > nul",
            "bcdedit /set bootux disabled > nul",
            "bcdedit /set bootmenupolicy legacy > nul",
            "bcdedit /set x2apicpolicy disable > nul",
            "bcdedit /set uselegacyapicmode yes > nul",
            "bcdedit /set disabledynamictick No",
            "bcdedit /set useplatformclock No",
            "bcdedit /set allowedinmemorysettings 0",
            "bcdedit /deletevalue useplatformtick",
            "bcdedit /set tscsyncpolicy Enhanced",
            "bcdedit /set x2apicpolicy Enable",
            "bcdedit /set perfmem 0",
            "bcdedit /set uselegacyapicmode No",
            "bcdedit /set MSI Default",
            "bcdedit /set hypervisorlaunchtype off",
            "bcdedit /set tpmbootentropy ForceDisable",
            "bcdedit /set useplatformclock no",
            "bcdedit /set x2apicpolicy enable",
            "bcdedit /set tscsyncpolicy legacy",
            "bcdedit /set tscsyncpolicy Legacy",
            "bcdedit /deletevalue useplatformclock"
            "bcdedit /set bootstatuspolicy IgnoreAllFailures > nul",
            "bcdedit /set debug on > nul",
            "bcdedit /set nointegritychecks on > nul",
            "bcdedit /set msisupported Yes > nul",
            "bcdedit /set recoveryenabled No > nul",
            "bcdedit /set testsigning on > nul",
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

        proces4 = True
        check_all_processes_complete()

    optimization4_thread = threading.Thread(target=bcdedit_funcja)
    optimization4_thread.start()


    def sc_funcja():
        global proces5
        print("Optymalizacja2 PRO jest w toku...")
        commands = [
            'sc config HomeGroupListener start= demand',
            'sc config HomeGroupProvider start= demand',

            'sc config AJRouter start= disabled',
            'sc config ALG start= manual',
            'sc config AppIDSvc start= manual',
            'sc config AppMgmt start= manual',
            'sc config AppReadiness start= manual',
            'sc config AppVClient start= disabled',
            'sc config AppXSvc start= manual',
            'sc config Appinfo start= manual',
            'sc config AssignedAccessManagerSvc start= disabled',
            'sc config AudioEndpointBuilder start= automatic',
            'sc config AudioSrv start= automatic',
            'sc config Audiosrv start= automatic',
            'sc config AxInstSV start= manual',
            'sc config BDESVC start= manual',
            'sc config BFE start= automatic',
            'sc config BITS start= delayed-auto'
            'sc config BTAGService start= manual',
            'sc config BrokerInfrastructure start= automatic',
            'sc config Browser start= manual',
            'sc config BthAvctpSvc start= automatic',
            'sc config BthHFSrv start= automatic',
            'sc config CDPSvc start= manual',

            'sc config COMSysApp start= manual',
            'sc config CertPropSvc start= manual',
            'sc config ClipSVC start= manual',
            'sc config CoreMessagingRegistrar start= automatic',
            'sc config CryptSvc start= automatic',
            'sc config CscService start= manual',
            'sc config DPS start= automatic',
            'sc config DcomLaunch start= automatic',
            'sc config DcpSvc start= manual',
            'sc config DevQueryBroker start= manual',
            'sc config DeviceAssociationService start= manual',
            'sc config DeviceInstall start= manual',
            'sc config Dhcp start= automatic',
            'sc config DiagTrack start= disabled',
            'sc config DialogBlockingService start= disabled',
            'sc config DispBrokerDesktopSvc start= automatic',
            'sc config DisplayEnhancementService start= manual',
            'sc config DmEnrollmentSvc start= manual',
            'sc config Dnscache start= automatic',
            'sc config EFS start= manual',
            'sc config EapHost start= manual',

            'sc config EntAppSvc start= manual',
            'sc config EventLog start= automatic',
            'sc config EventSystem start= automatic',
            'sc config FDResPub start= manual',
            'sc config Fax start= manual',
            'sc config FontCache start= automatic',
            'sc config FrameServer start= manual',
            'sc config FrameServerMonitor start= manual',
            'sc config GraphicsPerfSvc start= manual',
            'sc config HomeGroupListener start= manual',
            'sc config HomeGroupProvider start= manual',
            'sc config HvHost start= manual',
            'sc config IEEtwCollectorService start= manual',
            'sc config IKEEXT start= manual',
            'sc config InstallService start= manual',
            'sc config InventorySvc start= manual',
            'sc config IpxlatCfgSvc start= manual',
            'sc config KeyIso start= automatic',
            'sc config KtmRm start= manual',
            'sc config LSM start= automatic',
            'sc config LanmanServer start= automatic',
            'sc config LanmanWorkstation start= automatic',
            'sc config LicenseManager start= manual',
            'sc config LxpSvc start= manual',
            'sc config MSDTC start= manual',
            'sc config MSiSCSI start= manual',
            'sc config MapsBroker start= delayed-auto',
            'sc config McpManagementService start= manual',
            'sc config MicrosoftEdgeElevationService start= manual',
            'sc config MixedRealityOpenXRSvc start= manual',
            'sc config MpsSvc start= automatic',
            'sc config MsKeyboardFilter start= manual',
            'sc config NaturalAuthentication start= manual',
            'sc config NcaSvc start= manual',

            'sc config NcbService start= manual',
            'sc config NcdAutoSetup start= manual',
            'sc config NetSetupSvc start= manual',
            'sc config NetTcpPortSharing start= manual',
            'sc config Netlogon start= manual',
            'sc config Netman start= manual',
            'sc config NgcCtnrSvc start= manual',
            'sc config NgcSvc start= manual',
            'sc config NlaSvc start= manual',
            'sc config PNRPAutoReg start= manual',
            'sc config PNRPsvc start= manual',
            'sc config PcaSvc start= manual',
            'sc config PeerDistSvc start= manual',
            'sc config PerfHost start= manual',
            'sc config PhoneSvc start= manual',
            'sc config PlugPlay start= manual',
            'sc config PolicyAgent start= manual',
            'sc config Power start= automatic',
            'sc config PrintNotify start= manual',
            'sc config ProfSvc start= automatic',
            'sc config PushToInstall start= manual',

            'sc config QWAVE start= manual',
            'sc config RasAuto start= manual',
            'sc config RasMan start= manual',
            'sc config RemoteAccess start= disabled',
            'sc config RemoteRegistry start= disabled',
            'sc config RetailDemo start= manual',
            'sc config RmSvc start= manual',
            'sc config RpcEptMapper start= automatic',
            'sc config RpcLocator start= manual',
            'sc config RpcSs start= automatic',
            'sc config SCPolicySvc start= manual',
            'sc config SCardSvr start= manual',
            'sc config SDRSVC start= manual',
            'sc config SEMgrSvc start= manual',
            'sc config SENS start= automatic',
            'sc config SNMPTRAP start= manual',
            'sc config SNMPTrap start= manual',
            'sc config SSDPSRV start= manual',
            'sc config SamSs start= automatic',
            'sc config ScDeviceEnum start= manual',
            'sc config Schedule start= automatic',
            'sc config SecurityHealthService start= manual',
            'sc config Sense start= manual',
            'sc config SensorDataService start= manual',
            'sc config SensorService start= manual',
            'sc config SensrSvc start= manual',
            'sc config SessionEnv start= manual',
            'sc config SharedAccess start= manual',
            'sc config SharedRealitySvc start= manual',
            'sc config ShellHWDetection start= automatic',
            'sc config SmsRouter start= manual',
            'sc config Spooler start= automatic',

            'sc config SstpSvc start= manual',
            'sc config StiSvc start= manual',
            'sc config StorSvc start= manual',
            'sc config SysMain start= automatic',
            'sc config SystemEventsBroker start= automatic',
            'sc config TabletInputService start= manual',
            'sc config TapiSrv start= manual',
            'sc config TermService start= automatic',
            'sc config Themes start= automatic',
            'sc config TieringEngineService start= manual',
            'sc config TimeBroker start= manual',
            'sc config TimeBrokerSvc start= manual',
            'sc config TokenBroker start= manual',
            'sc config TrkWks start= automatic',
            'sc config TroubleshootingSvc start= manual',
            'sc config TrustedInstaller start= manual',
            'sc config UI0Detect start= manual',
            'sc config UevAgentService start= disabled',
            'sc config UmRdpService start= manual',
            'sc config UserManager start= automatic',
            'sc config UsoSvc start= manual',
            'sc config VGAuthService start= automatic',
            'sc config VMTools start= automatic',
            'sc config VSS start= manual',
            'sc config VacSvc start= manual',
            'sc config VaultSvc start= automatic',
            'sc config W32Time start= manual',
            'sc config WEPHOSTSVC start= manual',
            'sc config WFDSConMgrSvc start= manual',
            'sc config WMPNetworkSvc start= manual',
            'sc config WManSvc start= manual',
            'sc config WPDBusEnum start= manual',
            'sc config WSService start= manual',
            'sc config WSearch start= delayed-auto',
            'sc config WaaSMedicSvc start= manual',
            'sc config WalletService start= manual',
            'sc config WarpJITSvc start= manual',
            'sc config WbioSrvc start= manual',
            'sc config Wcmsvc start= automatic',
            'sc config WcsPlugInService start= manual',
            'sc config WdNisSvc start= manual',
            'sc config WdiServiceHost start= manual',
            'sc config WdiSystemHost start= manual',
            'sc config WebClient start= manual',
            'sc config Wecsvc start= manual',
            'sc config WerSvc start= manual',
            'sc config WiaRpc start= manual',
            'sc config WinDefend start= automatic',
            'sc config WinHttpAutoProxySvc start= manual',
            'sc config WinRM start= manual',
            'sc config Winmgmt start= automatic',
            'sc config WlanSvc start= automatic',
            'sc config WpcMonSvc start= manual',
            'sc config WpnService start= manual',
            'sc config XblAuthManager start= manual',
            'sc config XblGameSave start= manual',
            'sc config XboxGipSvc start= manual',
            'sc config XboxNetApiSvc start= manual',
            'sc config autotimesvc start= manual',
            'sc config bthserv start= manual',
            'sc config camsvc start= manual',
            'sc config cloudidsvc start= manual',
            'sc config dcsvc start= manual',
            'sc config defragsvc start= manual',
            'sc config diagnosticshub.standardcollector.service start= manual',
            'sc config diagsvc start= manual',
            'sc config dmwappushservice start= manual',
            'sc config dot3svc start= manual',
            'sc config edgeupdate start= manual',
            'sc config edgeupdatem start= manual',
            'sc config embeddedmode start= manual',
            'sc config fdPHost start= manual',
            'sc config fhsvc start= manual',
            'sc config gpsvc start= automatic',

            'sc config hidserv start= manual',
            'sc config icssvc start= manual',
            'sc config iphlpsvc start= automatic',
            'sc config lfsvc start= manual',
            'sc config lltdsvc start= manual',
            'sc config lmhosts start= manual',
            'sc config mpssvc start= automatic',
            'sc config msiserver start= manual',
            'sc config netprofm start= manual',
            'sc config nsi start= automatic',
            'sc config p2pimsvc start= manual',
            'sc config p2psvc start= manual',
            'sc config perceptionsimulation start= manual',
            'sc config pla start= manual',
            'sc config seclogon start= manual',
            'sc config shpamsvc start= disabled',
            'sc config smphost start= manual',
            'sc config spectrum start= manual',
            'sc config sppsvc start= delayed-auto',
            'sc config ssh-agent start= disabled',
            'sc config svsvc start= manual',
            'sc config swprv start= manual',
            'sc config tiledatamodelsvc start= automatic',
            'sc config tzautoupdate start= disabled',
            'sc config uhssvc start= disabled',
            'sc config upnphost start= manual',
            'sc config vds start= manual',
            'sc config vm3dservice start= manual',
            'sc config vmicguestinterface start= manual',
            'sc config vmicheartbeat start= manual',
            'sc config vmickvpexchange start= manual',

            'sc config vmicrdv start= manual',
            'sc config vmicshutdown start= manual',
            'sc config vmictimesync start= manual',
            'sc config vmicvmsession start= manual',
            'sc config vmicvss start= manual',
            'sc config vmvss start= manual',
            'sc config wbengine start= manual',
            'sc config wcncsvc start= manual',
            'sc config webthreatdefsvc start= manual',
            'sc config wercplsupport start= manual',
            'sc config wisvc start= manual',
            'sc config wlidsvc start= manual',
            'sc config wlpasvc start= manual',
            'sc config wmiApSrv start= manual',
            'sc config workfolderssvc start= manual',
            'sc config wscsvc start= delayed-auto',
            'sc config wuauserv start= manual',
            'sc config wudfsvc start= manual',

            'sc config AGSService start= disabled',
            'sc config AGMService start= disabled',
            'sc config AdobeUpdateService start= manual',
            'sc config "Adobe Acrobat Update" start= demand',
            'sc config "Adobe Genuine Monitor Service" start= disabled',
            'sc config AdobeARMservice start= manual',
            'sc config "Adobe Licensing Console" start= manual',
            'sc config CCXProcess start= manual',
            'sc config AdobeIPCBroker start= manual',
            'sc config CoreSync start= manual',
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
            
        proces5 = True
        check_all_processes_complete()

    optimization5_thread = threading.Thread(target=sc_funcja)
    optimization5_thread.start()

    def schtasks_funkcja():
        global proces6
        print("Optymalizacja2 PRO jest w toku...")
        commands = [
            "schtasks /Change /TN \"Microsoft\\Windows\\AppID\\SmartScreenSpecific\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\AitAgent\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\StartupAppTask\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Autochk\\Proxy\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\CloudExperienceHost\\CreateObjectTask\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\BthSQM\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\Uploader\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\DiskFootprint\\Diagnostics\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\FileHistory\\File History (maintenance mode)\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Maintenance\\WinSAT\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\PI\\Sqm-Tasks\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Shell\\FamilySafetyMonitor\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Shell\\FamilySafetyRefresh\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Shell\\FamilySafetyUpload\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Windows Error Reporting\\QueueReporting\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\WindowsUpdate\\Automatic App Update\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\License Manager\\TempSignedLicenseExchange\" /disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Clip\\License Validation\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\ApplicationData\\DsSvcCleanup\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\PushToInstall\\LoginCheck\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\PushToInstall\\Registration\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\Shell\\FamilySafetyMonitor\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\Shell\\FamilySafetyMonitorToastTask\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\Shell\\FamilySafetyRefreshTask\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\Subscription\\EnableLicenseAcquisition\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\Subscription\\LicenseAcquisition\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\Diagnosis\\RecommendedTroubleshootingScanner\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\Diagnosis\\Scheduled\" /disable",
            "schtasks /Change /TN \"\\Microsoft\\Windows\\NetTrace\\GatherNetworkInfo\" /disable",
            "schtasks /DELETE /TN \"AMDInstallLauncher\" /f",
            "schtasks /DELETE /TN \"AMDLinkUpdate\" /f",
            "schtasks /DELETE /TN \"AMDRyzenMasterSDKTask\" /f",
            "schtasks /DELETE /TN \"Driver Easy Scheduled Scan\" /f",
            "schtasks /DELETE /TN \"ModifyLinkUpdate\" /f",
            "schtasks /DELETE /TN \"SoftMakerUpdater\" /f",
            "schtasks /DELETE /TN \"StartCN\" /f",
            "schtasks /DELETE /TN \"StartDVR\" /f",
            "schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\PcaPatchDbTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Autochk\\Proxy\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Defrag\\ScheduledDefrag\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Device Information\\Device\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Device Information\\Device User\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Diagnosis\\RecommendedTroubleshootingScanner\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Diagnosis\\Scheduled\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\DiskCleanup\\SilentCleanup\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\DiskFootprint\\Diagnostics\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\DiskFootprint\\StorageSense\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\EnterpriseMgmt\\MDMMaintenenceTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Feedback\\Siuf\\DmClient\" /Disable",
            "schtasks /end /tn \"Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
            "schtasks /Change /TN \"Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\FileHistory\\File History (maintenance mode)\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Flighting\\FeatureConfig\\ReconcileFeatures\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Flighting\\FeatureConfig\\UsageDataFlushing\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Flighting\\FeatureConfig\\UsageDataReporting\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Flighting\\OneSettings\\RefreshCache\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Input\\LocalUserSyncDataAvailable\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Input\\MouseSyncDataAvailable\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Input\\PenSyncDataAvailable\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Input\\TouchpadSyncDataAvailable\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\International\\Synchronize Language Settings\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\LanguageComponentsInstaller\\Installation\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\LanguageComponentsInstaller\\ReconcileLanguageResources\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\LanguageComponentsInstaller\\Uninstallation\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\License Manager\\TempSignedLicenseExchange\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Management\\Provisioning\\Cellular\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Management\\Provisioning\\Logon\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Maintenance\\WinSAT\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Maps\\MapsToastTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Maps\\MapsUpdateTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Mobile Broadband Accounts\\MNO Metadata Parser\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\MUI\\LPRemove\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\NetTrace\\GatherNetworkInfo\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\PI\\Sqm-Tasks\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Power Efficiency Diagnostics\\AnalyzeSystem\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\PushToInstall\\Registration\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Ras\\MobilityManager\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\RecoveryEnvironment\\VerifyWinRE\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\RemoteAssistance\\RemoteAssistanceTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\RetailDemo\\CleanupOfflineContent\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Servicing\\StartComponentCleanup\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\SettingSync\\NetworkStateChangeTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Setup\\SetupCleanupTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Setup\\SnapshotCleanupTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\SpacePort\\SpaceAgentTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\SpacePort\\SpaceManagerTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Speech\\SpeechModelDownloadTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Storage Tiers Management\\Storage Tiers Management Initialization\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Sysmain\\ResPriStaticDbSync\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Sysmain\\WsSwapAssessmentTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Task Manager\\Interactive\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Time Synchronization\\ForceSynchronizeTime\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Time Synchronization\\SynchronizeTime\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Time Zone\\SynchronizeTimeZone\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\TPM\\Tpm-HASCertRetr\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\TPM\\Tpm-Maintenance\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\UPnP\\UPnPHostConfig\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\User Profile Service\\HiveUploadTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\WDI\\ResolutionHost\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Windows Filtering Platform\\BfeOnServiceStartTypeChange\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\WOF\\WIM-Hash-Management\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\WOF\\WIM-Hash-Validation\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Work Folders\\Work Folders Logon Synchronization\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Work Folders\\Work Folders Maintenance Work\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Workplace Join\\Automatic-Device-Join\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\WwanSvc\\NotificationTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\WwanSvc\\OobeDiscovery\" /Disable",
            "schtasks /Change /TN \"Microsoft\\XblGameSave\\XblGameSaveTask\" /Disable",
            "schtasks /end /tn \"\Microsoft\\Office\\OfficeTelemetryAgentFallBack2016\"",
            "schtasks /change /tn \"\Microsoft\\Office\\OfficeTelemetryAgentFallBack2016\" /disable",
            "schtasks /end /tn \"\Microsoft\\Office\\OfficeTelemetryAgentLogOn2016\"",
            "schtasks /change /tn \"\Microsoft\\Office\\OfficeTelemetryAgentLogOn2016\" /disable",
            "schtasks /end /tn \"\Microsoft\\Office\\OfficeTelemetryAgentFallBack\"",
            "schtasks /change /tn \"\Microsoft\\Office\\OfficeTelemetryAgentFallBack\" /disable",
            "schtasks /end /tn \"\Microsoft\\Office\\OfficeTelemetryAgentLogOn\"",
            "schtasks /change /tn \"\Microsoft\\Office\\OfficeTelemetryAgentLogOn\" /disable",

            'schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\Application Experience\MareBackup" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable',
            'schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable',
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

        proces6 = True
        check_all_processes_complete()

    optimization6_thread = threading.Thread(target=schtasks_funkcja)
    optimization6_thread.start()
