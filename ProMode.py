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
    processes = ["OneDrive.exe", "Skype.exe"]
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
    def execute_commands():
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
            "ipconfig /flushdns",
            "sc delete diagnosticshub.standardcollector.service",
            "sc delete DiagTrack",
            "sc delete dmwappushservice",
            "sc delete WerSvc",
            "sc delete OneSyncSvc",
            "sc delete MessagingService",
            "sc delete wercplsupport",
            "sc delete PcaSvc",
            "sc config wlidsvc start=demand",
            "sc delete wisvc",
            "sc delete RetailDemo",
            "sc delete diagsvc",
            "sc delete shpamsvc",
            "sc delete TermService",
            "sc delete UmRdpService",
            "sc delete SessionEnv",
            "sc delete TroubleshootingSvc",
            'for /f "tokens=1" %I in ("reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services" /k /f "wscsvc" ^| find /i "wscsvc") do (reg delete %I /f)',
            'for /f "tokens=1" %I in ("reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc") do (reg delete %I /f)',
            'for /f "tokens=1" %I in ("reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services" /k /f "MessagingService" ^| find /i "MessagingService") do (reg delete %I /f)',
            'for /f "tokens=1" %I in ("reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc") do (reg delete %I /f)',
            'for /f "tokens=1" %I in ("reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc") do (reg delete %I /f)',
            'for /f "tokens=1" %I in ("reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc") do (reg delete %I /f)',
            'for /f "tokens=1" %I in ("reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService") do (reg delete %I /f)',
            'for /f "tokens=1" %I in ("reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker") do (reg delete %I /f)',
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\" /v Disabled /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\" /v Disabled /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableSoftLanding /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\DataCollection\" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\Software\\Policies\\Microsoft\\WindowsInkWorkspace\" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\" /v SmartScreenEnabled /t REG_SZ /d \"Off\" /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AppHost\" /v \"EnableWebContentEvaluation\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\PhishingFilter\" /v \"EnabledV9\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" /v SpyNetReporting /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f",
            "reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Sense\" /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\MRT\" /v \"DontReportInfectionInformation\" /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\MRT\" /v \"DontOfferThroughWUAU\" /t REG_DWORD /d 1 /f",
            "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"SecurityHealth\" /f",
            "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\" /v \"SecurityHealth\" /f",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SecHealthUI.exe\" /v Debugger /t REG_SZ /d \"%windir%\\System32\\taskkill.exe\" /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Siuf\\Rules\" /v \"NumberOfSIUFInPeriod\" /t REG_DWORD /d 0 /f",
            "reg delete \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Siuf\\Rules\" /v \"PeriodInNanoSeconds\" /f",
            "reg add \"HKLM\\SYSTEM\\ControlSet001\\Control\\WMI\\AutoLogger\\AutoLogger-Diagtrack-Listener\" /v Start /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v AITEnable /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v DisableInventory /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v DisablePCA /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\" /v DisableUAR /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\" /v \"EnabledV9\" /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v \"EnableSmartScreen\" /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\PhishingFilter\" /v \"EnabledV9\" /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoRecentDocsHistory\" /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\CompatTelRunner.exe\" /v Debugger /t REG_SZ /d \"%windir%\\System32\\taskkill.exe\" /f",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DeviceCensus.exe\" /v Debugger /t REG_SZ /d \"%windir%\\System32\\taskkill.exe\" /f",
            "install_wim_tweak /o /c Windows-Defender /r",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance\" /v \"Enabled\" /t REG_DWORD /d 0 /f",
            "reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService\" /f",
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
            "del /F /Q \"C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SettingSync\\*\"",
            "bcdedit /set useplatformclock No",
            "bcdedit /set allowedinmemorysettings 0",
            "bcdedit /deletevalue useplatformtick",
            "bcdedit /set tscsyncpolicy Enhanced",
            "bcdedit /set disabledynamictick Yes",
            "bcdedit /set x2apicpolicy Enable",
            "bcdedit /set perfmem 0",
            "bcdedit /set uselegacyapicmode No",
            "bcdedit /set MSI Default",
            "bcdedit /set debug No",
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
            "rmdir /s /q \"C:\\Windows\\System32\\drivers\\NVIDIA Corporation\"",
            "cd /d \"C:\\Windows\\System32\\DriverStore\\FileRepository\\\"",
            "dir NvTelemetry64.dll /a /b /s",
            "del NvTelemetry64.dll /a /s",
            "powercfg.exe /hibernate off",
            "bcdedit /set hypervisorlaunchtype off",
            "bcdedit /set tpmbootentropy ForceDisable",
            "bcdedit /set useplatformclock no",
            "bcdedit /set useplatformtick yes",
            "bcdedit /set x2apicpolicy enable",
            "bcdedit /set uselegacyapicmode no",
            "bcdedit /set tscsyncpolicy legacy",
            "sc stop MapsBroker",
            "sc config MapsBroker start= disabled",
            "sc stop DoSvc",
            "sc config DoSvc start= disabled",
            "sc stop WSearch",
            "sc config WSearch start= disabled",
            "lodctr /r",
            "[{000214A0-0000-0000-C000-000000000046}]",
            "Prop3=19,0",
            "[InternetShortcut]",
            "IDList=",
            "URL=ms-settings:signinoptions",
            "reg add \"HKLM\\System\\CurrentControlSet\\Services\\PimIndexMaintenanceSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
            "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WinHttpAutoProxySvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
            "reg add \"HKLM\\System\\CurrentControlSet\\Services\\BcastDVRUserService\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
            "reg add \"HKLM\\System\\CurrentControlSet\\Services\\xbgm\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR\" /v \"AppCaptureEnabled\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR\" /v \"AudioCaptureEnabled\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR\" /v \"CursorCaptureEnabled\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR\" /v \"MicrophoneCaptureEnabled\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKCU\\System\\GameConfigStore\" /v \"GameDVR_FSEBehavior\" /t REG_DWORD /d \"2\" /f",
            "reg add \"HKCU\\System\\GameConfigStore\" /v \"GameDVR_HonorUserFSEBehaviorMode\" /t REG_DWORD /d \"2\" /f",
            "reg add \"HKCU\\System\\GameConfigStore\" /v \"GameDVR_Enabled\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\GameDVR\" /v \"AllowgameDVR\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKCU\\Software\\Microsoft\\GameBar\" /v \"AutoGameModeEnabled\" /t REG_DWORD /d \"0\" /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableSoftLanding /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f",
            "bcdedit /set tscsyncpolicy Legacy",
            "bcdedit /set disabledynamictick yes",
            "sc config wlidsvc start= disabled",
            "sc config DisplayEnhancementService start= disabled",
            "sc config DiagTrack start= disabled",
            "sc config DusmSvc start= disabled",
            "sc config TabletInputService start= disabled",
            "sc config RetailDemo start= disabled",
            "sc config Fax start= disabled",
            "sc config SharedAccess start= disabled",
            "sc config lfsvc start= disabled",
            "sc config WpcMonSvc start= disabled",
            "sc config SessionEnv start= disabled",
            "sc config MicrosoftEdgeElevationService start= disabled",
            "sc config edgeupdate start= disabled",
            "sc config edgeupdatem start= disabled",
            "sc config autotimesvc start= disabled",
            "sc config CscService start= disabled",
            "sc config TermService start= disabled",
            "sc config SensorDataService start= disabled",
            "sc config SensorService start= disabled",
            "sc config SensrSvc start= disabled",
            "sc config shpamsvc start= disabled",
            "sc config diagnosticshub.standardcollector.service start= disabled",
            "sc config PhoneSvc start= disabled",
            "sc config TapiSrv start= disabled",
            "sc config UevAgentService start= disabled",
            "sc config WalletService start= disabled",
            "sc config TokenBroker start= disabled",
            "sc config WebClient start= disabled",
            "sc config MixedRealityOpenXRSvc start= disabled",
            "sc config stisvc start= disabled",
            "sc config WbioSrvc start= disabled",
            "sc config icssvc start= disabled",
            "sc config Wecsvc start= disabled",
            "sc config XboxGipSvc start= disabled",
            "sc config XblAuthManager start= disabled",
            "sc config XboxNetApiSvc start= disabled",
            "sc config XblGameSave start= disabled",
            "sc config SEMgrSvc start= disabled",
            "sc config iphlpsvc start= disabled",
            "sc config Backupper Service start= disabled",
            "sc config BthAvctpSvc start= disabled",
            "sc config BDESVC start= disabled",
            "sc config cbdhsvc start= disabled",
            "sc config CDPSvc start= disabled",
            "sc config CDPUserSvc start= disabled",
            "sc config DevQueryBroker start= disabled",
            "sc config DevicesFlowUserSvc start= disabled",
            "sc config dmwappushservice start= disabled",
            "sc config DispBrokerDesktopSvc start= disabled",
            "sc config TrkWks start= disabled",
            "sc config dLauncherLoopback start= disabled",
            "sc config EFS start= disabled",
            "sc config fdPHost start= disabled",
            "sc config FDResPub start= disabled",
            "sc config IKEEXT start= disabled",
            "sc config NPSMSvc start= disabled",
            "sc config WPDBusEnum start= disabled",
            "sc config PcaSvc start= disabled",
            "sc config RasMan start= disabled",
            "sc config SstpSvc start= disabled",
            "sc config ShellHWDetection start= disabled",
            "sc config SSDPSRV start= disabled",
            "sc config SysMain start= disabled",
            "sc config OneSyncSvc start= disabled",
            "sc config lmhosts start= disabled",
            "sc config UserDataSvc start= disabled",
            "sc config UnistoreSvc start= disabled",
            "sc config Wcmsvc start= disabled",
            "sc config FontCache start= disabled",
            "sc config W32Time start= disabled",
            "sc config tzautoupdate start= disabled",
            "sc config DsSvc start= disabled",
            "sc config DevicesFlowUserSvc_5f1ad start= disabled",
            "sc config diagsvc start= disabled",
            "sc config DialogBlockingService start= disabled",
            "sc config PimIndexMaintenanceSvc_5f1ad start= disabled",
            "sc config MessagingService_5f1ad start= disabled",
            "sc config AppVClient start= disabled",
            "sc config MsKeyboardFilter start= disabled",
            "sc config NetTcpPortSharing start= disabled",
            "sc config ssh-agent start= disabled",
            "sc config OneSyncSvc_5f1ad start= disabled",
            "sc config wercplsupport start= disabled",
            "sc config WMPNetworkSvc start= disabled",
            "sc config WerSvc start= disabled",
            "sc config WpnUserService_5f1ad start= disabled",
            "sc config WinHttpAutoProxySvc start= disabled",
            "sc config DsmSvc start= disabled",
            "sc config DeviceAssociationService start= disabled",
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
            "schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Application Experience\\StartupAppTask\" /Disable",
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
            "schtasks /Change /TN \"Microsoft\\Windows\\DUSM\\dusmtask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\EnterpriseMgmt\\MDMMaintenenceTask\" /Disable",
            "schtasks /Change /TN \"Microsoft\\Windows\\Feedback\\Siuf\\DmClient\" /Disable",
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
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v \"LargeSystemCache\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\75b0ae3f-bce0-45a7-8c89-c9611c25e100\" /v \"Attributes\" /t REG_DWORD /d 2 /f",
            "reg add \"HKEY_USERS\\S-1-5-18\\Control Panel\\Desktop\" /v \"DragFullWindows\" /t REG_SZ /d \"1\" /f",
            "reg add \"HKEY_USERS\\S-1-5-18\\Control Panel\\Desktop\" /v \"FontSmoothing\" /t REG_SZ /d \"2\" /f",
            "reg add \"HKEY_USERS\\S-1-5-18\\Control Panel\\Desktop\" /v \"FontSmoothingOrientation\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_USERS\\S-1-5-18\\Control Panel\\Desktop\" /v \"FontSmoothingType\" /t REG_DWORD /d 2 /f",
            "reg add \"HKEY_USERS\\S-1-5-18\\Control Panel\\Desktop\" /v \"UserPreferencesMask\" /t REG_BINARY /d \"9e3e038012000000\" /f",
            "reg add \"HKEY_USERS\\S-1-5-18\\Control Panel\\Desktop\" /v \"LockScreenAutoLockActive\" /t REG_SZ /d \"0\" /f",
            "reg add \"HKEY_USERS\\S-1-5-18\\Control Panel\\Desktop\\WindowMetrics\" /f",
            "reg add \"HKEY_USERS\\S-1-5-18\\Control Panel\\Desktop\\MuiCached\" /f",
            "reg add \"HKEY_USERS\\S-1-5-18\\Control Panel\\Desktop\\MuiCached\" /v \"MachinePreferredUILanguages\" /t REG_BINARY /d \"65006e002d005500530000\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Processor\" /v \"Cstates\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Processor\" /v \"Capabilities\" /t REG_DWORD /d 0x7e066 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\" /v \"HighPerformance\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\" /v \"HighestPerformance\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\" /v \"MinimumThrottlePercent\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\" /v \"MaximumThrottlePercent\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\" /v \"MaximumPerformancePercent\" /t REG_DWORD /d 100 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\" /v \"Class1InitialUnparkCount\" /t REG_DWORD /d 100 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\" /v \"InitialUnparkCount\" /t REG_DWORD /d 100 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling\" /v \"PowerThrottlingOff\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\" /v \"fDisablePowerManagement\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PDC\\Activators\\Default\\VetoPolicy\" /v \"EA:EnergySaverEngaged\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\PDC\\Activators\\28\\VetoPolicy\" /v \"EA:PowerStateDischarging\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Misc\" /v \"DeviceIdlePolicy\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"PerfEnergyPreference\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CPMinCores\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CPMaxCores\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CPMinCores1\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CPMaxCores1\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CpLatencyHintUnpark1\" /t REG_DWORD /d 100 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CPDistribution\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CpLatencyHintUnpark\" /t REG_DWORD /d 100 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"MaxPerformance1\" /t REG_DWORD /d 100 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"MaxPerformance\" /t REG_DWORD /d 100 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CPDistribution1\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CPHEADROOM\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power\\Policy\\Settings\\Processor\" /v \"CPCONCURRENCY\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /v \"AppsUseLightTheme\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wdboot\" /v \"Start\" /t REG_DWORD /d 4 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wdfilter\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wdnisdrv\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mssecflt\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Sense\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wscsvc\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"DisableRoutinelyTakingAction\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v \"ServiceKeepAlive\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableBehaviorMonitoring\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableIOAVProtection\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableOnAccessProtection\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableRealtimeMonitoring\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting\" /v \"DisableEnhancedNotifications\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications\" /v \"DisableNotifications\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\" /v \"NoToastApplicationNotification\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\" /v \"NoToastApplicationNotificationOnLockScreen\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_Enabled\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_FSEBehaviorMode\" /t REG_DWORD /d 2 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_HonorUserFSEBehaviorMode\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_DXGIHonorFSEWindowsCompatible\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_CURRENT_USER\\System\\GameConfigStore\" /v \"GameDVR_EFSEFeatureFlags\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\ApplicationManagement\\AllowGameDVR\" /v \"value\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v \"AllowGameDVR\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR\" /v \"AppCaptureEnabled\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MapsBroker\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoInstrumentation\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v \"AllowTelemetry\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Privacy\" /v \"TailoredExperiencesWithDiagnosticDataEnabled\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\EventTranscriptKey\" /v \"EnableEventTranscript\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\" /v \"ShowedToastAtLevel\" /t REG_DWORD /d 1 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v \"PublishUserActivities\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v \"UploadUserActivities\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\" /v \"EnablePrefetcher\" /t REG_DWORD /d 3 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\" /v \"EnableSuperfetch\" /t REG_DWORD /d 0 /f",
            "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl\" /v \"Win32PrioritySeparation\" /t REG_DWORD /d 40 /f",


            # Nowe polecenia dotyczące telemetryki
            "PowerShell -Command \"Import-Module -DisableNameChecking $PSScriptRoot\\..\\lib\\force-mkdir.psm1\"",
            "PowerShell -Command \"force-mkdir 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' 'AllowTelemetry' 0\"",
            
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
            + "\"... (więcej domen)\");\n"
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


            # Wyłączanie zaplanowanych zadań Windows Defender
            "PowerShell -Command \"Import-Module -DisableNameChecking $PSScriptRoot\\..\\lib\\force-mkdir.psm1; \
            Import-Module -DisableNameChecking $PSScriptRoot\\..\\lib\\take-own.psm1; \
            Write-Output 'Elevating privileges for this process'; \
            do {} until (Elevate-Privileges SeTakeOwnershipPrivilege); \
            $tasks = @('\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance', \
            '\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup', \
            '\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan', \
            '\\Microsoft\\Windows\\Windows Defender\\Windows Defender Verification'); \
            foreach ($task in $tasks) { \
            $parts = $task.split('\\'); \
            $name = $parts[-1]; \
            $path = $parts[0..($parts.length-2)] -join '\\'; \
            Write-Output 'Trying to disable scheduled task ' + $name; \
            Disable-ScheduledTask -TaskName \"$name\" -TaskPath \"$path\" }; \
            Write-Output 'Disabling Windows Defender via Group Policies'; \
            force-mkdir 'HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender'; \
            Set-ItemProperty 'HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender' 'DisableAntiSpyware' 1; \
            Set-ItemProperty 'HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender' 'DisableRoutinelyTakingAction' 1; \
            force-mkdir 'HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection'; \
            Set-ItemProperty 'HKLM:\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' 'DisableRealtimeMonitoring' 1; \
            Write-Output 'Disabling Windows Defender Services'; \
            Takeown-Registry('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend'); \
            Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WinDefend' 'Start' 4; \
            Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WinDefend' 'AutorunsDisabled' 3; \
            Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc' 'Start' 4; \
            Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc' 'AutorunsDisabled' 3; \
            Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Sense' 'Start' 4; \
            Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Sense' 'AutorunsDisabled' 3; \
            Write-Output 'Removing Windows Defender context menu item'; \
            Set-Item 'HKLM:\\SOFTWARE\\Classes\\CLSID\\{09A47860-11B0-4DA5-AFA5-26D86198A780}\\InprocServer32' ''; \
            Write-Output 'Removing Windows Defender GUI / tray from autorun'; \
            Remove-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' 'WindowsDefender' -ea 0\"",


            # Usuwanie aplikacji systemowych
            "PowerShell -Command \"Import-Module -DisableNameChecking $PSScriptRoot\\..\\lib\\take-own.psm1; \
            Write-Output 'Elevating privileges for this process'; \
            do {} until (Elevate-Privileges SeTakeOwnershipPrivilege); \
            Write-Output 'Force removing system apps'; \
            $needles = @('BioEnrollment', 'ContactSupport', 'Cortana', 'Defender', 'Feedback', 'Flash', 'Gaming', 'InternetExplorer', 'Maps', 'OneDrive', 'SecHealthUI', 'Wallet'); \
            foreach ($needle in $needles) { \
            Write-Output 'Trying to remove all packages containing ' + $needle; \
            $pkgs = (Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages' | \
            Where-Object Name -Like '*$needle*'); \
            foreach ($pkg in $pkgs) { \
            $pkgname = $pkg.Name.split('\\')[-1]; \
            Takeown-Registry($pkg.Name); \
            Takeown-Registry($pkg.Name + '\\Owners'); \
            Set-ItemProperty -Path ('HKLM:' + $pkg.Name.Substring(18)) -Name Visibility -Value 1; \
            New-ItemProperty -Path ('HKLM:' + $pkg.Name.Substring(18)) -Name DefVis -PropertyType DWord -Value 2; \
            Remove-Item -Path ('HKLM:' + $pkg.Name.Substring(18) + '\\Owners'); \
            dism.exe /Online /Remove-Package /PackageName:$pkgname /NoRestart } }\"",


            "PowerShell -Command \"Import-Module -DisableNameChecking $PSScriptRoot\\..\\lib\\force-mkdir.psm1\"",
            "PowerShell -Command \"force-mkdir 'HKCU:\\SOFTWARE\\Microsoft\\Personalization\\Settings'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Personalization\\Settings' 'AcceptedPrivacyPolicy' 0\"",
            "PowerShell -Command \"force-mkdir 'HKCU:\\SOFTWARE\\Microsoft\\InputPersonalization\\TrainedDataStore'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\InputPersonalization\\TrainedDataStore' 'HarvestContacts' 0\"",
            "PowerShell -Command \"force-mkdir 'HKCU:\\SOFTWARE\\Microsoft\\InputPersonalization'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\InputPersonalization' 'RestrictImplicitInkCollection' 1\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\InputPersonalization' 'RestrictImplicitTextCollection' 1\"",
            "PowerShell -Command \"force-mkdir 'HKCU:\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\Main'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\Main' 'DoNotTrack' 1\"",
            "PowerShell -Command \"force-mkdir 'HKCU:\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\User\\Default\\SearchScopes'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\User\\Default\\SearchScopes' 'ShowSearchSuggestionsGlobal' 0\"",
            "PowerShell -Command \"force-mkdir 'HKCU:\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\FlipAhead'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\FlipAhead' 'FPEnabled' 0\"",
            "PowerShell -Command \"force-mkdir 'HKCU:\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\PhishingFilter'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\PhishingFilter' 'EnabledV9' 0\"",
            "PowerShell -Command \"foreach ($key in Get-ChildItem 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications') { Set-ItemProperty (\"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications\\\" + $key.PSChildName) 'Disabled' 1 }\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceAccess\\Global\\LooselyCoupled' 'Value' 'Deny'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceAccess\\Global\\LooselyCoupled' 'Type' 'LooselyCoupled'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceAccess\\Global\\LooselyCoupled' 'InitialAppValue' 'Unspecified'\"",
            "PowerShell -Command \"force-mkdir 'HKCU:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Permissions\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'\"",
            "PowerShell -Command \"Set-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Permissions\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' 'SensorPermissionState' 0\"",
            "PowerShell -Command \"Takeown-Registry 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet'; Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet' 'SpyNetReporting' 0; Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Spynet' 'SubmitSamplesConsent' 0\"",
            "PowerShell -Command \"force-mkdir 'HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\features\\' + (New-Object System.Security.Principal.NTAccount($env:UserName).Translate([System.Security.Principal.SecurityIdentifier]).Value)\"",
            "PowerShell -Command \"Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\features\\' + (New-Object System.Security.Principal.NTAccount($env:UserName).Translate([System.Security.Principal.SecurityIdentifier]).Value) 'FeatureStates' 0x33c\"",
            "PowerShell -Command \"Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\features' 'WiFiSenseCredShared' 0\"",
            "PowerShell -Command \"Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\features' 'WiFiSenseOpen' 0\"",
            "PowerShell -Command \"force-mkdir 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR'; Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR' 'AllowgameDVR' 0\"",
            "PowerShell -Command \"New-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer -Name DisableEdgeDesktopShortcutCreation -PropertyType DWORD -Value 1\""


            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\75b0ae3f-bce0-45a7-8c89-c9611c25e100\" /v Attributes /t REG_DWORD /d 2 /f"
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v Affinity /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v BackgroundOnly /t REG_SZ /d False /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v ClockRate /t REG_DWORD /d 10000 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v SchedulingCategory /t REG_SZ /d High /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v SFIOPriority /t REG_SZ /d High /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v GPUPriority /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games\" /v Priority /t REG_DWORD /d 6 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GTA5.exe\PerfOptions\" /v CpuPriorityClass /t REG_DWORD /d 3 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\gtavlauncher.exe\PerfOptions\" /v CpuPriorityClass /t REG_DWORD /d 5 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\subprocess.exe\PerfOptions\" /v CpuPriorityClass /t REG_DWORD /d 5 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1\" /v Attributes /t REG_DWORD /d 2 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e\" /v ACSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e\" /v DCSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\" /v ACSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e\" /v ACSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e\" /v DCSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\" /v ACSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c\" /v DCSettingIndex /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching\" /v SearchOrderConfig /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\" /v HiberbootEnabled /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling\" /v PowerThrottlingOff /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\Power\" /v HibernateEnabledDefault /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency\" /v \"\" /t REG_SZ /d \"\" /f",
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
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl\" /v IRQ8Priority /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl\" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f",
            "reg add \"HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows\" /v CEIPEnable /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat\" /v AITEnable /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GTA5.exe\PerfOptions\" /v CpuPriorityClass /t REG_DWORD /d 6 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f",
            "reg add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" /v SystemResponsiveness /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\" /v DisableRoutinelyTakingAction /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\" /v ServiceKeepAlive /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv\" /v Start /t REG_DWORD /d 4 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend\" /v Start /t REG_DWORD /d 4 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService\" /v Start /t REG_DWORD /d 4 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc\" /v Start /t REG_DWORD /d 4 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Services\Sense\" /v Start /t REG_DWORD /d 4 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Services\wscsvc\" /v Start /t REG_DWORD /d 4 /f",
            "reg add \"HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" /v NoToastApplicationNotification /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v ActiveWndTrackTimeout /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v BlockSendInputResets /t REG_SZ /d \"0\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v CaretTimeout /t REG_DWORD /d 5000 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v CaretWidth /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v ClickLockTime /t REG_DWORD /d 120 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v CoolSwitchColumns /t REG_SZ /d \"7\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v CoolSwitchRows /t REG_SZ /d \"3\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v CursorBlinkRate /t REG_SZ /d \"530\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v DockMoving /t REG_SZ /d \"1\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v DragFromMaximize /t REG_SZ /d \"1\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v DragFullWindows /t REG_SZ /d \"1\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v DragHeight /t REG_DWORD /d 4 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v DragWidth /t REG_DWORD /d 4 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v FocusBorderHeight /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v FocusBorderWidth /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v FontSmoothing /t REG_SZ /d \"2\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v FontSmoothingGamma /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v FontSmoothingOrientation /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v FontSmoothingType /t REG_DWORD /d 2 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v ForegroundFlashCount /t REG_DWORD /d 7 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v ForegroundLockTimeout /t REG_DWORD /d 300000 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v LeftOverlapChars /t REG_SZ /d \"3\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v MenuShowDelay /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v MouseWheelRouting /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v PaintDesktopVersion /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v Pattern /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v RightOverlapChars /t REG_SZ /d \"3\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v ScreenSaveActive /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v SnapSizing /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v TileWallpaper /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WallPaper /t REG_SZ /d \"C:\\Users\\danyt\\AppData\\Local\\Microsoft\\Windows\\Themes\\RoamedThemeFiles\\DesktopBackground\\wallpaper.png\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WallpaperOriginX /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WallpaperOriginY /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WallpaperStyle /t REG_SZ /d \"10\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WheelScrollChars /t REG_DWORD /d 3 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WheelScrollLines /t REG_DWORD /d 3 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WindowArrangementActive /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v Win8DpiScaling /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v DpiScalingVer /t REG_DWORD /d 256 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v UserPreferencesMask /t REG_BINARY /d \"hex:90,12,03,80,10,00,00,00\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v MaxVirtualDesktopDimension /t REG_DWORD /d 1920 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v MaxMonitorDimension /t REG_DWORD /d 1920 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v TranscodedImageCount /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v LastUpdated /t REG_DWORD /d 4294967295 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v TranscodedImageCache /t REG_BINARY /d \"hex:7a,c3,01,00,2c,f3,0e,00,8a,0a,00,00,ed,05,00,00,4e,3b,bc,b3,cf,fb,d6,01,43,00,3a,00,5c,00,55,00,73,00,65,00,72,00,73,00,5c,00,64,00,61,00,6e,00,79,00,74,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,4c,00,6f,00,63,00,61,00,6c,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,00,54,00,68,00,65,00,6d,00,65,00,73,00,5c,00,52,00,6f,00,61,00,6d,00,65,00,64,00,54,00,68,00,65,00,6d,00,65,00,46,00,69,00,6c,00,65,00,73,00,5c,00,44,00,65,00,73,00,6b,00,74,00,6f,00,70,00,42,00,61,00,63,00,6b,00,67,00,72,00,6f,00,75,00,6e,00,64,00,5c,00,77,00,61,00,6c,00,6c,00,70,00,61,00,70,00,65,00,72,00,2e,00,70,00,6e,00,67,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v AutoColorization /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v ImageColor /t REG_DWORD /d 97c87657 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v AutoEndTasks /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v HungAppTimeout /t REG_DWORD /d 4000 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v LowLevelHooksTimeout /t REG_DWORD /d 1000 /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WaitToKillAppTimeout /t REG_DWORD /d 5000 /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v ActiveBorder /t REG_SZ /d \"212 208 200\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v ActiveTitle /t REG_SZ /d \"10 36 106\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v AppWorkSpace /t REG_SZ /d \"128 128 128\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v ButtonAlternateFace /t REG_SZ /d \"181 181 181\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v ButtonDkShadow /t REG_SZ /d \"64 64 64\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v ButtonFace /t REG_SZ /d \"212 208 200\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v ButtonHiLight /t REG_SZ /d \"255 255 255\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v ButtonLight /t REG_SZ /d \"212 208 200\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v ButtonShadow /t REG_SZ /d \"128 128 128\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v ButtonText /t REG_SZ /d \"0 0 0\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v GradientActiveTitle /t REG_SZ /d \"166 202 240\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v GradientInactiveTitle /t REG_SZ /d \"192 192 192\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v GrayText /t REG_SZ /d \"128 128 128\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v Hilight /t REG_SZ /d \"10 36 106\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v HilightText /t REG_SZ /d \"255 255 255\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v HotTrackingColor /t REG_SZ /d \"0 0 128\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v InactiveBorder /t REG_SZ /d \"212 208 200\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v InactiveTitle /t REG_SZ /d \"128 128 128\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v InactiveTitleText /t REG_SZ /d \"212 208 200\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v InfoText /t REG_SZ /d \"0 0 0\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v InfoWindow /t REG_SZ /d \"255 255 255\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v Menu /t REG_SZ /d \"212 208 200\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v MenuText /t REG_SZ /d \"0 0 0\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v Scrollbar /t REG_SZ /d \"212 208 200\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v TitleText /t REG_SZ /d \"255 255 255\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v Window /t REG_SZ /d \"255 255 255\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v WindowFrame /t REG_SZ /d \"0 0 0\" /f",
            "reg add \"HKCU\Control Panel\Desktop\Colors\" /v WindowText /t REG_SZ /d \"0 0 0\" /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v BorderWidth /t REG_DWORD /d -15 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v CaptionFont /t REG_BINARY /d \"hex:f4,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,00,90,01,00,00,00,00,00,01,00,00,05,00,53,00,65,00,67,00,6f,00,65,00,20,00,55,00,49,00,00,00,00\" /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v CaptionHeight /t REG_DWORD /d -330 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v CaptionWidth /t REG_DWORD /d -330 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v IconFont /t REG_BINARY /d \"hex:f4,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,00,90,01,00,00,00,00,00,01,00,00,05,00,53,00,65,00,67,00,6f,00,65,00,20,00,55,00,49,00,00,00,00\" /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v IconTitleWrap /t REG_SZ /d \"1\" /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v MenuFont /t REG_BINARY /d \"hex:f4,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,00,90,01,00,00,00,00,00,01,00,00,05,00,53,00,65,00,67,00,6f,00,65,00,20,00,55,00,49,00,00,00,00\" /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v MenuHeight /t REG_DWORD /d -285 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v MenuWidth /t REG_DWORD /d -285 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v MessageFont /t REG_BINARY /d \"hex:f4,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,00,90,01,00,00,00,00,00,01,00,00,05,00,53,00,65,00,67,00,6f,00,65,00,20,00,55,00,49,00,00,00,00\" /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v ScrollHeight /t REG_DWORD /d -255 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v ScrollWidth /t REG_DWORD /d -255 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v Shell Icon Size /t REG_SZ /d \"32\" /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v SmCaptionFont /t REG_BINARY /d \"hex:f4,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,00,90,01,00,00,00,00,00,01,00,00,05,00,53,00,65,00,67,00,6f,00,65,00,20,00,55,00,49,00,00,00,00\" /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v SmCaptionHeight /t REG_DWORD /d -330 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v SmCaptionWidth /t REG_DWORD /d -330 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v StatusFont /t REG_BINARY /d \"hex:f4,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,00,90,01,00,00,00,00,00,01,00,00,05,00,53,00,65,00,67,00,6f,00,65,00,20,00,55,00,49,00,00,00,00\" /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v PaddedBorderWidth /t REG_DWORD /d -60 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v AppliedDPI /t REG_DWORD /d 96 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v IconSpacing /t REG_DWORD /d -1125 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v IconVerticalSpacing /t REG_DWORD /d -1125 /f",
            "reg add \"HKCU\Control Panel\Desktop\WindowMetrics\" /v MinAnimate /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\Control Panel\Desktop\MuiCached\" /v MachinePreferredUILanguages /t REG_BINARY /d \"hex:65,00,6e,00,2d,00,55,00,53,00,00,00\" /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 67108864 /f",
            "reg add \"HKLM\SYSTEM\CurrentControlSet\Control\" /v WaitToKillServiceTimeout /t REG_SZ /d \"2000\" /f",
            "reg add \"HKCU\Control Panel\Desktop\" /v WaitToKillServiceTimeout /t REG_DWORD /d 20000 /f",
        ]

        for command in commands:
            try:
                if command.startswith("PowerShell"):
                    subprocess.call(command, shell=True)
                else:
                    subprocess.call(command, shell=True)
                print(f"Wykonano: {command}")
            except Exception as e:
                print(f"Błąd podczas wykonywania {command}: {str(e)}")

    optimization2_thread = threading.Thread(target=execute_commands)
    optimization2_thread.start()