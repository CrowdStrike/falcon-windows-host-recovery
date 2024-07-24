# Falcon Windows Host Recovery

Build bootable images to remediate Windows hosts impacted by the recent [Falcon Content Update](https://www.crowdstrike.com/falcon-content-update-remediation-and-guidance-hub/). 

### What's New
**Release 1.2**
- **OPTIONAL** - Automated BitLocker Recovery Key support via CSV file 
- CSPERecovery image now supports multiple drives and automated drive selection
- Quality and reliability improvements

## Features

### Build Tools

- Automated builds of bootable Windows PE images with CrowdStrike recovery tools
- Device driver options: default, minimal, limited and custom (user defined)
- OPTIONAL: BitLocker Recovery Keys support via CSV file 

### Host Recovery Images

Two bootable images are available - use the image that best suits your needs.

_CSSafeBoot_
- Automated host remediation using Safe Mode with Networking 
- Manual host remediation using Safe Mode with Networking

_CSPERecovery_
- Automated host remediation with prompt for manual entry of BitLocker Recovery Key 
- Automated host remediation with automated entry of BitLocker Recovery Key

 
## Building Bootable Images

Use this project to build bootable Windows PE images using the latest Microsoft ADK and Windows PE add-ons and drivers. 

**Requirements**
- A Windows 10 (or higher) 64-bit client with at least 8GB of free space, and administrative privileges.

### Default - Build ISO (All Device Drivers)

Build bootable images with device drivers from all of the following: Red Hat/Virtio, Dell, HP, VMWare and Microsoft Surface (Models: Pro 8, 9, 10, Laptop 4 (Intel/AMD), 5.6).

_**NOTE**: may take upwards of 30 minutes to build based on network and disk performance_

1. Download the [falcon-windows-host-recovery](https://github.com/CrowdStrike/falcon-windows-host-recovery) github project as a ZIP file.
   1. Click the green Code button and select _Download ZIP_
2. Extract falcon-windows-host-recovery-main.zip file contents to a directory of your choosing 
   1. Example: `C:\falcon-windows-host-recovery` 
   2. IMPORTANT: path cannot contain spaces or special characters
3. Open a Windows PowerShell command prompt (as Administrator) and run script to build ISO images 
   1. `cd C:\falcon-windows-host-recovery` 
   2. `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` 
   3. `.\BuildISO.ps1` - downloads device drivers and creates ISO images 
4. Build output ISO images 
   1. `C:\falcon-windows-host-recovery\CSPERecovery_x64.iso` 
   2. `C:\falcon-windows-host-recovery\CSSafeBoot_x64.iso`

### Optional - BuildISO with Customer Drivers
Builds bootable images with default WinPE drivers and preferred device drivers.

1. Open a Windows PowerShell command prompt  
   1. Change into your extracted file directory 
      1. `cd C:\falcon-windows-host-recovery`
2. Custom drivers - download and unpack device drivers of your choosing into  
   1. `C:\falcon-windows-host-recovery\Drivers` 
   2. NOTE: drivers in this folder _will always be installed_, regardless of command-line arguments.
3. Command-line Arguments for `BuildISO.ps1` script
   1. Optional drivers - include one or more driver sets (any combination supported)
      1. `-IncludeDellDrivers` 
      2. `-IncludeHPDrivers` 
      3. `-IncludeSurfaceDrivers` 
      4. `-IncludeVMwareDrivers`
   2. Minimal drivers - skip all included driver sets (NOTE: overrides any `-Include*` args)
      1. `-SkipThirdPartyDriverDownloads`
4. Create bootable ISO images
   1. `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`
   2. `.\BuildISO.ps1 -<Command-line Arguments>` 
5. Build output ISO images 
   1. `C:\falcon-windows-host-recovery\CSPERecovery_x64.iso`
   2. `C:\falcon-windows-host-recovery\CSSafeBoot_x64.iso`

### Optional - BuildISO with BitLocker Recovery Keys
Builds bootable images with your BitLocker Recovery Keys in the CSPERecovery image

**WARNING: BitLocker Recovery Keys should be rotated after host remediation**

_**BitLocker Keys via CSV**_ 
Example of your Recovery Keys in a CSV file 
- IMPORTANT: column headers KeyID and RecoveryKey are required and case sensitive

| KeyID      | RecoveryKey |
| ----------- | ----------- |
| 3ca7495e-4252-432b-baf1-SAMPLE | 001317-088010-034473-667247-160608-471717-100894-INVALD  |
| 92e89e08-ad6e-4a98-e584-SAMPLE | 509542-050497-158529-325316-496853-372340-593355-INVALID |
| 72E460C8-4FE8-4249-99CF-SAMPLE | 529408-021370-702581-530739-028721-610907-461582-INVALID |
| 72E460C8-4FE8-4249-99CF-SAMPLE | 529408-021370-702581-530739-028721-610907-461582-INVALID |

1. Open a Windows PowerShell command prompt 
   1. Change into your extracted file directory
      1. `cd C:\falcon-windows-host-recovery`
2. BitLocker Recovery Keys - provide keys via CSV file named `BitLockerKeys.csv` 
   1. `C:\falcon-windows-host-recovery\BitLockerKeys.csv`
   2. IMPORTANT: safe handling and destruction of BitLocker Recovery Keys required 
3. Create bootable images 
   1. `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`
   2. .\BuildISO.ps1 -<Command-line Arguments>
4. Build output 
   5. `C:\falcon-windows-host-recovery\CSPERecovery_x64.iso` 
   6. `C:\falcon-windows-host-recovery\CSSafeBoot_x64.iso`

## Using Bootable Images

### Write ISO Files to a USB Drive

1. Download Rufus, an open-source utility for creating bootable USB sticks from https://rufus.ie/en/
2. Open Rufus:
   1. Use the “Device” menu to select the desired USB drive target 
      1. **WARNING: USB drive will be wiped clean**
   2. Use the “Select” button (next to “Boot Selection”) and choose the CSPERecovery or CSSafeBoot ISO file
   3. Use “Partition scheme” dropdown menu and select “GPT” 
   4. Use the “Target System” dropdown menu to select “UEFI (non CSM)” 
   5. Press Start
      1. **IMPORTANT**: If prompted to write in ISO mode or ESP mode, please read the following guidance carefully:
      2. ISO mode should be attempted **first**. 
         1. It offers the most complete user experience, supports both MBR and UEFI booting, and enables the automated cleanup script for the CSSafeBoot ISO. 
            1. The CSPERecovery ISO is not impacted. 
      3. ESP mode should be tried _if the machine does not see the bootable USB drive_, particularly on older UEFI systems 
         1. Go back to Step 2 and  repeat these steps and select ESP mode. 
         2. The automated cleanup script will be unavailable for the CSSafeBoot ISO, but manual remediation steps are still available and will succeed. 
            1. The CSPERecovery ISO is not impacted.

### Booting Windows host from USB

Once you have created a bootable USB drive using https://rufus.ie/en/ (in section above)

1. Once complete, insert the USB drive into the impacted system 
2. Confirm the host has network access, preferably via wired ethernet 
3. Reboot the target system and enter the UEFI boot Menu
   1. Usually the F1, F2, F8, F11, or F12 key 
4. Prepare to select the USB Flash Drive. 
   1. If given both a MBR and UEFI option with the same label, prepare to select UEFI 
5. Wait while Windows PE loads 
6. Use the appropriate "Recover..." guide below for _CSSafeBoot_ or _CSPERecovery_ 

#### Recover Windows Hosts using CSPERecovery
_CSPERecovery_ image will automatically remediate

1. Select recovery image drive mount in BootManager
   1. If more than one drive is detected, select the drive letter associated with the impacted OS. 
2. If BitLocker enabled
   1. **WARNING: BitLocker Recovery Keys should be rotated after host remediation**
      1. If prompted, enter your BitLocker Recovery Key to unlock the volume
      2. If BitLocker Recovery Keys CSV is available in recovery image, 
3. Recovery script will remove the impacted Channel File 291 sys file 
   1. Deletes all files starting with `C-00000291*` located in the `C:\Windows\System32\drivers\CrowdStrike\folder` 
   2. The device will automatically reboot 
4. Windows host should load successfully.

#### Recover Windows Hosts using CSSafeBoot

_CSSafeBoot_ image will automatically reconfigure the bootloader on the machine to boot into Safe Mode with Networking and reboot. 

1. Select recovery image drive mount in BootManager
   1. NOTE: If your system reboots into the Windows Recovery environment as a part of a prior boot loop, select Continue. 
   1. The machine will reboot into Safe Mode after the next boot. 
2. Log in as an user with _Local Administrator_ permissions 
3. Confirm the Safe Mode banner is displayed on the desktop
4. Remediation
   1. To perform remediation steps automatically
      1. Open Windows Explorer and navigate to drive letter for your bootable image mount (e.g. D:)
         1. If your bootable image is not listed as a drive letter in Windows Explorer, please skip to the next section titled “To execute remediation steps manually” as your specific configuration may preclude the use of the automatic remediation script. 
      2. Right-click on the file `CSRecovery.cmd` and _Run as administrator_
         1. Script will delete all files starting with `C-00000291*` located in the `C:\Windows\System32\drivers\CrowdStrike\folder`
         2. The device will automatically reboot and load the operating system.
   2. To execute remediation steps manually 
      1. Open Windows Explorer and navigate to `C:\Windows\System32\drivers\Crowdstrike`
      2. Delete all files starting with `C-00000291*` located in the `C:\Windows\System32\drivers\CrowdStrike\folder`
      3. Right-click on Command Prompt and select _Run as administrator_
      4. Type the following command and press enter 
         1. `bcdedit /deletevalue {default} safeboot`
      5. Reboot the device and verify the operating system loads successfully.


#### Recovering Windows Hosts using PXE

For PXE booting, these ISO files can be deployed and booted through existing PXE booting capability deployed at your business. 

Due to significant differences in network and software configurations with PXE booting, we cannot recommend specific generic PXE booting instructions.

## Best Practices
### Using BitLocker Recovery Keys
**WARNING: BitLocker Recovery Keys should be rotated after host remediation**

**_Safe Handling_**
Bootable Images with BitLocker Recovery Keys
- should only be accessible to those who absolutely need it.
- should be stored on password protected storage devices with disk encryption
- should be transferred over encrypted communication channels 

**_Secure Destruction_**
Bootable Images with BitLocker Recovery Keys
- Digital ISO Image files must be destroyed using software designed for secure deletion to ensure data cannot be recovered 
- Physical storage media containing ISO images should be destroyed using methods such as shredding, incineration or crushing

## Troubleshooting

### Dual boot Windows OS
_CSPERecovery_ on dual boot Windows OS systems only remediates the first drive found 
- _the second Windows OS boot drive will not be automatically remediated_

### BitLocker Recovery Key CSV
- Verify your CSV has column headers KeyID and RecoveryKey 
- Verify your CSV column header case sensitivity for KeyID and RecoveryKey

## License

Copyright (c) CrowdStrike, Inc.

By accessing or using this image, script, sample code, application programming interface, tools, and/or associated documentation (if any) (collectively, “Tools”), You (i) represent and warrant that You are entering into this Agreement on behalf of a company, organization or another legal entity (“Entity”) that is currently a customer or partner of CrowdStrike, Inc. (“CrowdStrike”), and (ii) have the authority to bind such Entity and such Entity agrees to be bound by this Agreement. CrowdStrike grants Entity a non-exclusive, non-transferable, non-sublicensable, royalty free and limited license to access and use the Tools solely for Entity’s internal business purposes, including without limitation the rights to copy and modify the Tools as necessary for your internal purposes. Any third-party software, files, drivers or other components accessed and/or downloaded by You when using a Tool may be governed by additional terms or by a separate license provided or maintained by the third party provider. THE TOOLS ARE PROVIDED “AS-IS” WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY OR OTHERWISE. CROWDSTRIKE SPECIFICALLY DISCLAIMS ALL SUPPORT OBLIGATIONS AND ALL WARRANTIES, INCLUDING WITHOUT LIMITATION, ALL IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL CROWDSTRIKE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE TOOLS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. THIS TOOL IS NOT ENDORSED BY ANY THIRD PARTY.
