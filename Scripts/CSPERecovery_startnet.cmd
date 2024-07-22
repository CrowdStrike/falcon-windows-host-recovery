@echo off
echo "CrowdStrike Preinstallation Environment Recovery Utility"
echo "********************************************************"
echo "[+] Starting Windows PE"
wpeinit

echo "[+] Changing to the high performance power plan"
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

echo "[+] Launching Repair Tool"
powershell -executionpolicy Unrestricted -noexit -File ".\CSPERecovery.ps1"

echo "[+] Rebooting"
wpeutil reboot
