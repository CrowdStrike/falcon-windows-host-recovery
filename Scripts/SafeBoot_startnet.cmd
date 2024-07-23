@echo off
echo CrowdStrike Safe Mode Boot Utility
echo **********************************

echo [+] Starting Windows PE
wpeinit

echo [+] Enabling Safe Mode with Networking
bcdedit /set {default} safeboot network

echo [+] Rebooting into Windows in 5 seconds
echo     Do not boot from CD/USB again, and allow Windows to boot up in Safe Mode

REM timeout command does not work in WinPE, so we use PowerShell to run Start-Sleep -Seconds 5
powershell -ExecutionPolicy Unrestricted -EncodedCommand "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAANQA="

echo [+] Rebooting
wpeutil reboot
