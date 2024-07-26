# Falcon Windows Host Recovery

Build bootable images to remediate Windows hosts impacted by the recent [Falcon Content Update](https://www.crowdstrike.com/falcon-content-update-remediation-and-guidance-hub/).

Watch the [CrowdStrike Host Remediation with Bootable USB Drive](https://www.youtube.com/watch?v=TZlUrXXVxc8) video for a demonstration.

### What's New

#### Release 1.3.1

- *CSPERecovery*: Removes prompt to accept CrowdStrike signing certificate during remediation
- *CSPERecovery*: Disables `safeboot` after successful remediation, allowing Windows to boot normally

## Features

### Build Tools

- Default - Image with Device Drivers
- Optional - Image with Custom Drivers: minimal, limited and custom (user defined)
- Optional - Image with Custom BitLocker Recovery support via CSV

### BitLocker Tools
- Optional - Create CSV of BitLocker Recovery Keys from Active Directory/Entra ID

### Host Remediation Tools

Two bootable images are available - use the image that best suits your needs.

- _CSPERecovery_ - automated host remediation with manual or automatic BitLocker recovery keys.
- _CSSafeBoot_ - automated and manual host remediation using Safe Mode with Networking (administrator account required).

 
## Build Tools

Use this project to build bootable Windows PE images using the latest Microsoft ADK, Windows PE add-ons, drivers, and CrowdStrike's remediation scripts.

### Requirements

- A Windows 10 (or higher) 64-bit client with at least 16GB of free space, and administrative privileges.

1. Download the [falcon-windows-host-recovery](https://github.com/CrowdStrike/falcon-windows-host-recovery) GitHub project as a ZIP file.
   1. Click the green Code button and select _Download ZIP_
2. Extract the contents of `falcon-windows-host-recovery-main.zip` to a directory of your choosing.
   1. Example: `C:\falcon-windows-host-recovery-main`.
   2. IMPORTANT: _path cannot contain spaces or special characters_

### Default - Image with Device Drivers

Build bootable images with device drivers for all the following:

Red Hat/VirtIO VMs, Dell systems, HP systems, VMWare VMs, Microsoft Surface devices (Pro 8, 9, 10, Laptop 4 (Intel/AMD), 5, 6), common AMD SATA controllers, and common Intel / LSI MegaSAS RAID cards.

_**NOTE**: may take upwards of 30 minutes to build based on network and disk performance_

1. Open a Windows PowerShell command prompt (as Administrator), set execution policy and build images
   1. `cd C:\falcon-windows-host-recovery-main` 
   2. `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`  
   3. `.\BuildISO.ps1` - downloads default set of device drivers and creates ISO images 
2. Optional Command-line Arguments for `BuildISO.ps1` script
   1. `-SkipBootPrompt` - Disable the "press any key to boot from [media]" prompt when the system boots
      1. This feature may not work on all systems
3. Output: images 
   1. `C:\falcon-windows-host-recovery-main\CSPERecovery_x64.iso` 
   2. `C:\falcon-windows-host-recovery-main\CSSafeBoot_x64.iso`

_**NOTE**: may take upwards of 30 minutes to build based on network and disk performance_

### Optional - Image with Custom Device Drivers

Build bootable images with minimal drivers only, a limited set of drivers, or with your own custom device drivers.

1. Open a Windows PowerShell command prompt (as Administrator)
   1. `cd C:\falcon-windows-host-recovery-main`
2. Custom drivers - download and unpack device drivers into
   1. `C:\falcon-windows-host-recovery-main\Drivers` 
   2. NOTE: drivers in `\Drivers` _will always be installed_, regardless of command-line arguments.
3. Command-line Arguments for `BuildISO.ps1` script
   1. Optional drivers - include one or more driver sets (any combination supported)
      1. `-IncludeCommonDrivers` -- various common CrowdStrike customer device drivers
      2. `-IncludeDellDrivers` 
      3. `-IncludeHPDrivers` 
      4. `-IncludeSurfaceDrivers` 
      5. `-IncludeVMwareDrivers`
   2. Minimal drivers - skip all included driver sets (NOTE: overrides any `-Include*` args)
      1. `-SkipThirdPartyDriverDownloads`
4. Build bootable images
   1. `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`
   2. `.\BuildISO.ps1 <Command-line Arguments>` 
5. Output: images 
   1. `C:\falcon-windows-host-recovery-main\CSPERecovery_x64.iso`
   2. `C:\falcon-windows-host-recovery-main\CSSafeBoot_x64.iso`

### Optional - Image with BitLockerKeys.csv

Build bootable images with BitLocker Recovery Keys in the _CSPERecovery_ image.

**WARNING: BitLocker Recovery Keys should be rotated after host remediation**

_**BitLocker Keys via CSV**_ 
Example of your Recovery Keys in a CSV file 
- IMPORTANT: column headers KeyID and RecoveryKey are required and case-sensitive

| KeyID                          | RecoveryKey                                              |
|--------------------------------|----------------------------------------------------------|
| 3ca7495e-4252-432b-baf1-SAMPLE | 001317-088010-034473-667247-160608-471717-100894-INVALID |
| 92e89e08-ad6e-4a98-e584-SAMPLE | 509542-050497-158529-325316-496853-372340-593355-INVALID |
| 72E460C8-4FE8-4249-99CF-SAMPLE | 529408-021370-702581-530739-028721-610907-461582-INVALID |

1. Open a Windows PowerShell command prompt 
   1. Change into your extracted file directory
      1. `cd C:\falcon-windows-host-recovery-main`
2. Include BitLocker Recovery Keys - via CSV file named `BitLockerKeys.csv` 
   1. `C:\falcon-windows-host-recovery-main\BitLockerKeys.csv`
   2. IMPORTANT: see _Best Practices_ section below for safe handling and destruction of BitLocker Recovery Keys 
3. Create bootable images 
   1. `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`
   2. `.\BuildISO.ps1 <Command-line Arguments>`
4. Output: images
   1. `C:\falcon-windows-host-recovery-main\CSPERecovery_x64.iso`
   2. `C:\falcon-windows-host-recovery-main\CSSafeBoot_x64.iso`

## BitLocker Tools

***Requirements***
- Powershell 7.0 or higher
- Server Manager -> Local Server: _disable_ `IE Enhanced Security Configuration`
- Active Directory export requires a Domain Administrator user on a domain-joined Windows Server OS
- Entra ID export script requires connectivity to Microsoft Graph, and a cloud user with OAuth scopes `BitLockerKey.ReadBasic.All` and `Device.Read.All`
   
### Optional - Automated BitLocker Recovery Key Export from Active Directory or Entra ID

Generates a `BitLockerKeys.csv` via automated export of BitLocker Recovery Keys

1. Open a Windows PowerShell command prompt (as Administrator)
   1. Change into your extracted file directory
      1. `cd C:\falcon-windows-host-recovery-main`
2. Command-line Arguments for `Export-BitLockerRecoveryKeys.ps1` script
   1. `-ActiveDirectory` - extract BitLocker keys from Active Directory
   2. `-ActiveDirectory -OU` - extract BitLocker keys for specific Organizational Unit
   3. `-EntraID` - extract BitLocker keys from Entra ID
   4. `-ActiveDirectory -EntraID` - extract BitLocker keys from both Active Directory and Entra ID
3. Extract BitLocker Recovery keys from source
   1. `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`
   2. `.\Export-BitLockerRecoveryKeys.ps1 <Command-line Arguments>`
      1. OU Example `.\Export-BitLockerRecoveryKeys.ps1 -ActiveDirectory "OU=OurComputers,CN=Computers,DC=company,DC=local"`
4. Follow prompts to collect accounts 
5. Output: CSV file: `BitLockerKeys.csv`
6. Build a new image with this CSV using the **Optional - Image with Custom BitLockerKeys.csv** section above  

_NOTE:_ 
- Use OU flag for large Active Directory environments where base domain searches return 1000s of computers.

## Host Remediation Tools

### Write ISO Files to a USB Drive

1. Download Rufus, an open-source utility for creating bootable USB sticks from https://rufus.ie/en/
2. Open Rufus:
   1. Use the _Device_ menu to select the desired USB drive target 
      1. **WARNING: USB drive will be wiped clean**
   2. Click the _Select_ button (next to _Boot Selection_) and choose the _CSPERecovery_ or _CSSafeBoot_ ISO file
   3. Use the _Partition scheme_ dropdown menu to select "GPT"
   4. Use the _Target System_ dropdown menu to select "UEFI (non CSM)"
   5. Press _Start_
   6. **IMPORTANT** - **please carefully read the following**:
      1. If prompted to write in _ISO mode_ or _ESP mode_
         1. _ISO mode_ -  **use this first!** 
            1. Most complete user experience, supports both MBR and UEFI booting, and enables the automated cleanup script _CSSafeBoot_ ISO. 
               1. The _CSPERecovery_ ISO is not impacted. 
         2. _ESP mode_ - **use if host cannot recognize bootable USB drive** (particularly on older UEFI systems) 
            1. Go back to Step 2 and repeat these steps and select ESP mode. 
            2. The automated cleanup script will be unavailable in _CSSafeBoot_ ISO, but manual remediation steps are still available and will succeed. 
               1. The CSPERecovery ISO is not impacted.

### Booting Windows Host from USB

Once you have created a bootable USB drive using https://rufus.ie/en/ (in section above)

1. Insert USB drive into the impacted host
2. Reboot the host and enter the UEFI boot Menu using the F12 key
   1. You may also try the F1, F2, F10 or F11 keys (depending on the BIOS manufacturer)
3. Select the USB drive
   1. Prepare to select _UEFI_ if given a choice between MBR and UEFI option with the same label 
4. Wait while Windows PE loads 
5. Proceed to the appropriate "Recover..." section below for using _CSSafeBoot_ or _CSPERecovery_ 

### Recover Windows Hosts using CSPERecovery

_CSPERecovery_ image remediates systems automatically, and includes support for BitLocker.

1. Select recovery image USB drive in BootManager. 
   1. **IMPORTANT**: *YOU DO NOT NEED TO MODIFY UEFI FIRMWARE SETTINGS* (especially boot order)
2. If BitLocker is enabled:
   1. **WARNING: BitLocker Recovery Keys should be rotated after host remediation**
      1. If prompted, manually enter your BitLocker Recovery Key to unlock the volume.
      2. If `BitLockerKeys.csv` in use, the Recovery Key for the device will be applied.
3. The recovery script will automatically remove the defective Channel File 291.
   1. Deletes all files starting with `C-00000291*` located in the `C:\Windows\System32\drivers\CrowdStrike` folder.
   2. The device will automatically reboot.
4. The Windows host should start up normally.

### Recover Windows Hosts using CSSafeBoot

_CSSafeBoot_ image modifies the default Windows boot configuration to boot into _Safe Mode with Networking_, and reboots. 

1. Select recovery image USB drive in BootManager
   1. **IMPORTANT**: *YOU DO NOT NEED TO MODIFY UEFI FIRMWARE SETTINGS* (especially boot order)
   2. NOTE: Select _Continue_ if your system reboots into the Windows Recovery environment as a part of a prior boot loop. 
   3. The host will reboot into _Safe Mode_ after the next boot. 
2. Login as user with _Local Administrator_ permissions.
3. Confirm the _Safe Mode_ banner is displayed on the desktop.
4. Remediation
   1. Automatic Remediation:
      1. Open Windows Explorer and select the recovery USB drive.
         1. If recovery USB drive is not displayed in Windows Explorer, skip to Manual Remediation 
      2. Locate and right-click on the file `CSRecovery.cmd`, and select _Run as Administrator_. 
      3. The script will:
            1. Delete all files starting with `C-00000291*` located in the `C:\Windows\System32\drivers\CrowdStrike` folder.
            2. Restore Windows boot configuration back to _Normal Mode_
            3. Host will reboot automatically.
            4. Verify Windows loads successfully
   2. Manual Remediation:
      1. Open Windows Explorer and navigate to `C:\Windows\System32\drivers\Crowdstrike`.
      2. Delete all files starting with `C-00000291*` located in the `C:\Windows\System32\drivers\CrowdStrike` folder.
      3. Right-click on the Start menu, and click either `Windows PowerShell (Admin)`, `Command Prompt (Admin)`, or `Terminal (Admin)`.
      4. At the prompt, type the following command and press Enter:
         1. `bcdedit /deletevalue {default} safeboot`
      5. Reboot the device
      6. Verify Windows loads successfully.


### Recovering Windows Hosts using PXE

The host remediation ISO files can be deployed and booted through existing PXE booting capability deployed at your business. 

Due to significant differences in network and software configurations with PXE booting, we cannot recommend specific generic PXE booting instructions.

## Best Practices
### Using BitLocker Recovery Keys

**WARNING: BitLocker Recovery Keys should be rotated after host remediation**

**_Safe Handling_**

Bootable images with BitLocker Recovery Keys
- should only be accessible to those who absolutely need them
- should be stored on password protected storage devices with disk encryption
- should be transferred over encrypted communication channels 

**_Secure Destruction_**

Bootable images with BitLocker Recovery Keys
- Digital ISO Image files must be destroyed using software designed for secure deletion to ensure data cannot be recovered 
- Physical storage media containing ISO images should be destroyed using methods such as shredding, incineration or crushing

## Troubleshooting

### Host Reboots to USB Drive Only After Remediation

If host continues to boot to recovery USB drive _after remediation_
- Solution: reconfirm the boot order in the UEFI firmware settings are correct, and pull the USB drive _after remediation_  
- _NOTE: CrowdStrike remediation script **does not change the UEFI boot order** to avoid unnecessary BitLocker steps._ 

1. **IMPORTANT**: *YOU DO NOT NEED TO MODIFY UEFI FIRMWARE SETTINGS* (especially boot order)
   1. Doing so may cause additional BitLocker recovery steps.


### Frozen CrowdStrike Safe Mode Boot Utility

If _CSPERecovery_ or _CSSafeBoot_ script is unresponsive after starting Windows PE.
- Solution: Hit Enter

### Recovery Image Size and Device Drivers

If  `-SkipThirdPartyDriverDownloads` flag was used to build the recovery image, and drivers that were not chosen are included.
  - Solution: move (or remove) any device drivers from the `\Drivers` folder you do not want in your image

- **NOTE**: CrowdStrike only provides open source drivers for libvirt-based virtual machines (e.g., OpenStack and KVM). 
  - All vendor device drivers are downloaded directly from vendor websites, using HTTPS, and cryptographically verified, at build time.

### Dual and Multi Boot Windows OS and BitLocker

If CSV is not in use, the _CSPERecovery_ script will only automatically remediate one Windows OS installation on hosts with dual/multi-boot configurations
- Solution: repeat steps from **Recover Windows Hosts using CSPERecovery** section (above) for each Windows OS installation drive letter you want to remediate. 
  - NOTE: each Windows OS installation device drive requires a BitLocker recovery key.
- The tool will only automatically remediate all unencrypted drives, or BitLocker protected devices if the `BitLockerKeys.csv` is used.
  - NOTE: if host is dual/multi OS boot, with BitLocker, and recovery image has CSV, all drives having keys in `BitLockerKeys.csv` will be remediated.  

### BitLocker Recovery Key export from Active Directory/Entra ID
- Existing CSV 
  - If `.\Export-BitLockerRecoveryKeys.ps1` fails with a CSV file exists error.
    - Solution: move existing file outside your work directory (e.g. `C:\falcon-windows-host-recovery-main`).
    - The script will not automatically overwrite this file.
- Active Directory Export:
  - If `.\Export-BitLockerRecoveryKeys.ps1` fails due to _permissions_.
    - Solution: user must have Domain Administrator permissions, or be a member of a group delegated with read access to BitLocker Recovery Keys.
  - If AD stored keys do not appear when script run from host not connected to domain.
    - Solution: run `.\Export-BitLockerRecoveryKeys.ps1` script from a domain-joined server host.
    - Entra ID stored keys can also be exported if the AD-joined server has the required outbound network connectivity.
- Entra ID Export:
  - If `.\Export-BitLockerRecoveryKeys.ps1` fails due to permission errors.
    - Solution: the user running the script must have Administrator permissions for the required scopes.
    - Solution: the user running the script must have the `BitLockerKey.ReadBasic.All` and `Device.Read.All` scopes assigned. 
      - NOTE: Global Administrator approval is required for scope assignment.
  - If `.\Export-BitLockerRecoveryKeys.ps1` fails due to a network error.
    - Solution: run `.\Export-BitLockerRecoveryKeys.ps1` from a host with connectivity to the Microsoft Graph API.
    
### BitLocker Recovery Key CSV
- Verify your CSV file has column headers that exactly match `KeyID` and `RecoveryKey`.

## License

Copyright (c) CrowdStrike, Inc.

By accessing or using this image, script, sample code, application programming interface, tools, and/or associated documentation (if any) (collectively, “Tools”), You (i) represent and warrant that You are entering into this Agreement on behalf of a company, organization or another legal entity (“Entity”) that is currently a customer or partner of CrowdStrike, Inc. (“CrowdStrike”), and (ii) have the authority to bind such Entity and such Entity agrees to be bound by this Agreement. CrowdStrike grants Entity a non-exclusive, non-transferable, non-sublicensable, royalty free and limited license to access and use the Tools solely for Entity’s internal business purposes, including without limitation the rights to copy and modify the Tools as necessary for your internal purposes. Any third-party software, files, drivers or other components accessed and/or downloaded by You when using a Tool may be governed by additional terms or by a separate license provided or maintained by the third party provider. THE TOOLS ARE PROVIDED “AS-IS” WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY OR OTHERWISE. CROWDSTRIKE SPECIFICALLY DISCLAIMS ALL SUPPORT OBLIGATIONS AND ALL WARRANTIES, INCLUDING WITHOUT LIMITATION, ALL IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL CROWDSTRIKE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE TOOLS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. THIS TOOL IS NOT ENDORSED BY ANY THIRD PARTY.
