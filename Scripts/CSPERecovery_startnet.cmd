@echo off
echo CrowdStrike Preinstallation Environment Recovery Utility
echo ********************************************************
echo [+] Starting Windows PE
wpeinit

echo [+] Changing to the high performance power plan
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

echo [+] Trusting CrowdStrike's Authenticode code signing certificate in Windows PE
certutil -f -addstore TrustedPublisher .\CSAuthenticodePublicKey.pem

echo [+] Launching Repair Tool
powershell -ExecutionPolicy RemoteSigned -noexit -File ".\CSPERecovery.ps1"

echo [+] Rebooting
wpeutil reboot
