# Falcon Windows Host Recovery

Build your own bootable image files to automate the recovery of Windows hosts affected by the recent [Falcon Content Update](https://www.crowdstrike.com/falcon-content-update-remediation-and-guidance-hub/). 

## Create Bootable Images

The following procedure will produce two bootable ISO images using the latest Microsoft ADK and Windows PE add-ons and drivers, along with common storage and input drivers for enterprise storage controllers including VirtIO, Intel RAID, VMware accelerated virtual storage, etc. These ISO images will also include the Falcon Windows Sensor host recovery scripts.

### Requirements

- Windows 10 (or higher) 64-bit client with at least 8Gb of free space, and administrative privileges.

### Build ISO

#### Default
Builds two bootable ISO images with device drivers downloaded from Dell, HP and VMWare

1. Download the [falcon-windows-host-recovery](https://github.com/CrowdStrike/falcon-windows-host-recovery) github project as a ZIP file.
2. Extract falcon-windows-host-recovery-main.zip file contents to a directory of your choosing 
   1. Example: `C:\falcon-windows-host-recovery` 
3. Open a Windows PowerShell command prompt (as Administrator) and run script to build ISO images 
   1. `cd C:\falcon-windows-host-recovery` 
   2. `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process` 
   3. `.\BuildISO.ps1` - downloads device drivers and creates ISO images 
4. Build output ISO images 
   1. `C:\falcon-windows-host-recovery\CSPERecovery_x64.iso` 
   2. `C:\falcon-windows-host-recovery\CSSafeBoot_x64.iso`


#### WinPE Drivers Only or with Customer-supplied Drivers
Builds two bootable ISO images with WinPE only or with your preferred device drivers

1. Create bootable ISO images with WinPE only or with your preferred drivers 
   1. `cd C:\falcon-windows-host-recovery` 
   2. If preferred drivers, download and unpack into `C:\falcon-windows-host-recovery\Drivers` 
   3. `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process` 
   4. `.\BuildISO.ps1 -SkipThirdPartyDriverDownloads` 
2. Build output ISO images 
   1. `C:\falcon-windows-host-recovery\CSPERecovery_x64.iso`
   2. `C:\falcon-windows-host-recovery\CSSafeBoot_x64.iso`


## Using Bootable Images

#### Write ISO Files to Bootable USB Drive

1. Download Rufus, an open-source utility for creating bootable USB sticks from https://rufus.ie/en/
2. Open Rufus:
   3. Select the desired USB Flash Drive target using the “Device” dropdown menu (NOTE: this USB Flash Drive will be wiped clean, make sure it’s the correct one)
   4. Select the either the CSPERecovery or CSSafeBoot ISO file using the SELECT button beside “Boot Selection” label
   5. Select “GPT” for the using the “Partition scheme” dropdown menu
   6. Select “UEFI (non CSM)” using the “Target System” dropdown menu
   7. Press Start
      8. If prompted to write in ISO mode or ESP mode, select ESP Mode. ESP mode is more likely to be compatible with older hardware.
9. Once complete, connect the USB Flash Drive to the intended target system
10. Confirm that the target host has network access, preferably via wired ethernet.
11. Reboot the target system and enter the UEFI boot Menu (usually F1, F2, F8, F11, or F12).
12. Prepare to select the USB Flash Drive. If given both a MBR and UEFI option with the same label, prepare to select UEFI
13. Wait while Windows PE loads and follow next sections for Running CSSafeBoot or CSPERecovery respectively

#### Recovering Windows Hosts using CSSafeBoot

1. CSSafeBoot will automatically reconfigure the bootloader on the machine to boot into Safe Mode with Networking and reboot. 
2. If your system reboots into the Windows Recovery environment as a part of a prior boot loop, select Continue. The machine will reboot into safe mode on the next boot. 
3. Log in as an user with Local Administrator permissions 
4. Confirm the Safe mode banner is displayed on the desktop 
5. Open Windows Explorer and navigate to C:\Windows\System32\drivers\Crowdstrike 
6. Delete all offending files that start with C-00000291*
7. Open command prompt (Right click -> Run as administrator)
8. Type bcdedit /deletevalue {default} safeboot, then press Enter 
9. Reboot the device and verify the operating system loads successfully.

#### Recovering Windows Hosts using CSPERecovery

1. If more than one drive is detected, select the drive letter associated with the impacted OS. 
2. If prompted, enter your BitLocker Recovery Key to unlock the volume 
3. Let the utility find and remove the impacted Channel File 291 sys file 
4. The utility will reboot the device and the operating system should load successfully.

#### Recovering Windows Hosts using PXE

For PXE booting, these ISO files can be deployed and booted through existing PXE booting capability deployed at your business. 

Due to significant differences in network and software configurations with PXE booting, we cannot recommend specific generic PXE booting instructions.

## Contents
### Drivers

- VMware Storage Driver
- Libvirt VirtIO Storage Driver (Red Hat/Fedora signed WHQL version)
- Libvirt Input Driver (Red Hat/Fedora signed WHQL version)
- HP Client Driver Pack
- Dell WinPE Driver Pack

### Installed WinPE Components

- WMI / WMI_en-us
- StorageWMI / StorageWMI_en-us
- Scripting / Scripting_en-us
- NetFX / NetFX_en-us
- PowerShell / PowerShell_en-us
- DismCmdlets / DismCmdlets_en-us
- FMAPI
- SecureBootCmdlets
- EnhancedStorage / EnhancedStorage_en-us
- SecureStartup / SecureStartup_en-us

### WinPE Configuration Settings

- Time Zone: GMT
- Locale: en-us

Copyright (c) CrowdStrike, Inc.

By accessing or using this image, script, sample code, application programming interface, tools, and/or associated documentation (if any) (collectively, "Tools"), You (i) represent and warrant that You are entering into this Agreement on behalf of a company, organization or another legal entity ("Entity") that is currently a customer or partner of CrowdStrike, Inc. ("CrowdStrike"), and (ii) have the authority to bind such Entity and such Entity agrees to be bound by this Agreement. CrowdStrike grants Entity a non-exclusive, non-transferable, non-sublicensable, royalty free and limited license to access and use the Tools solely for Entity's internal business purposes, including without limitation the rights to copy and modify the Tools as necessary for your internal purposes. Any third-party software, files, drivers or other components accessed and/or downloaded by You when using a Tool may be governed by additional terms or by a separate license provided or maintained by the third party provider. THE TOOLS ARE PROVIDED "AS-IS" WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY OR OTHERWISE. CROWDSTRIKE SPECIFICALLY DISCLAIMS ALL SUPPORT OBLIGATIONS AND ALL WARRANTIES, INCLUDING WITHOUT LIMITATION, ALL IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL CROWDSTRIKE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE TOOLS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. THIS TOOL IS NOT ENDORSED BY ANY THIRD PARTY.