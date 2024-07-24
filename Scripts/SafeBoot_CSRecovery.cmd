@echo off
echo CrowdStrike boot recovery
echo This script will clean up potentially problematic Falcon channel files from drive C:,
echo then boot the system back into Windows normally.
echo *************************
echo.

echo [+] Checking for administrative permissions

fsutil dirty query %systemdrive% >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Administrative permissions confirmed
) else (
    echo [-] This script has not been run with administrator permissions.
    echo [-] Please right click it, and then click Run as Administrator.
    goto end
)

del /F /Q C:\Windows\System32\drivers\CrowdStrike\C-00000291*.sys

bcdedit /deletevalue {default} safeboot

echo [+] Done! System will reboot in 10 seconds...

shutdown /r /t 10

:end
pause >nul
