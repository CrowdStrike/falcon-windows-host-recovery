@echo off
echo CrowdStrike boot recovery
echo This script will clean up potentially problematic Falcon channel files from drive C:,
echo then boot the system back into Windows normally.
echo *************************
echo.

echo [+] Attempting to delete potentially problematic channel file(s)

del /F /Q C:\Windows\System32\drivers\CrowdStrike\C-00000291*.sys

bcdedit /deletevalue {default} safeboot

echo [+] Done! System will reboot in 10 seconds...

shutdown /r /t 10

:end
pause >nul
