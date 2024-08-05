<# CrowdStrike Preinstallation Environment Recovery ISO Builder
.SYNOPSIS
    Build recovery disks to support customers in recovering from the July 2024 CrowdStrike incident
.DESCRIPTION
    This script will build ISOs to assist CrowdStrike customers in deleting potentially problematic
    channel files from a boot-looping Windows system. Storage drivers for common hardware can be
    downloaded and automatically built into the images.
.EXAMPLE
    .\BuildISO.ps1
    .\BuildISO.ps1 -IncludeCommonDrivers -IncludeDellDrivers -SkipBootPrompt
.INPUTS
    -IncludeCommonDrivers: Download and stage common generic hardware drivers for inclusion in the built images.

    -IncludeDellDrivers: Download and stage the Dell Windows PE 10+ and Windows PE 11+ client driver packs for
                         inclusion in the built images.

    -IncludeHPDrivers: Download and stage the HP Windows PE client driver pack for inclusion in the built images.

    -IncludeSurfaceDrivers: Download and stage targeted drivers for x86-64 (Intel and AMD) Surface Pro 8/9/10
                            and Surface Laptop 4/5/6 devices for inclusion in the built images.

    -IncludeVMwareDrivers: Download and stage the VMware PVSCSI driver for inclusion in the built images.

    -SkipBootPrompt: Disable the "press any key to boot from [media]" prompt when the system boots from one
                     of the built images.

    -SkipThirdPartyDriverDownloads: By default all drivers are downloaded. This flag will globally disable all
                                    driver downloads.

.OUTPUTS
    CSPERecovery_x64.iso: Automated recovery image. BitLocker-encrypted systems will require recovery keys.

    CSSafeBoot_x64.iso: Tool which will boot systems into Safe Mode without a BitLocker key. Note that a
                        local administrator account will be required to log in to the system, remediate it,
                        and boot back into Windows. A script to carry out this second stage is left at the
                        root of the CD/USB drive to automate this process, too.
.NOTES
    Version:        v1.3.2
    Author:         CrowdStrike, Inc.
    Creation Date:  2 August 2024
#>
#Requires -RunAsAdministrator
Param(
    [switch]$IncludeCommonDrivers,
    [switch]$IncludeDellDrivers,
    [switch]$IncludeHPDrivers,
    [switch]$IncludeSurfaceDrivers,
    [switch]$IncludeVMwareDrivers,
    [switch]$SkipBootPrompt,
    [switch]$SkipThirdPartyDriverDownloads
)

# Constant Paths
$ADKInstallLocation = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10")
$ADKWinPELocation = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\en-us\winpe.wim")

$DandISetEnvPath = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat")
$CopyPEPath = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\copype.cmd")
$MakeWinPEMediaPath = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\MakeWinPEMedia.cmd")

$OSCDIMGPath = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg")

$DownloadsDir = "$PSScriptRoot\Downloads"
$DriversDir = "$PSScriptRoot\Drivers"
$ScriptsDir = "$PSScriptRoot\Scripts"

# Package Download Repository
# This is stored within the PowerShell file rather than in a separate repository file so that it can also be digitally signed
# By storing everything here, we can cache downloads
$PackageRepository = [ordered]@{
    ADKInstaller = @{
        Name = "Assessment and Deployment Kit (ADK)";
        URL = "https://go.microsoft.com/fwlink/?linkid=2271337";
        DownloadHash = "3DBB9BF40E9CF5FACD9D770BE8EBA8F9509E77FC20A6051C0D9BAA1173F98E4B";
        FileName = "adksetup.exe";
    };
    ADKWinPEInstaller = @{
        Name = "Assessment and Deployment Kit (ADK) Windows PE Addon";
        URL = "https://go.microsoft.com/fwlink/?linkid=2271338";
        DownloadHash = "91AC010247B65244E5CD84C5F342D91B16501DBB08E422DE7DE06850CEF5680B";
        FileName = "adkwinpesetup.exe";
    };
    AMDSATADrivers = @{
        Name = "AMD SATA Drivers";
        URL = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2018/07/wt64a_0a03c9fb3d4947ed73acb807e1572e6c71ab757f.cab";
        DownloadHash = "0503ED0C754C273C9ED368D8E7CD20252E5C8F845262A29B554C944B7ECB8544";
        FileName = "amd_sata.cab";
    };
    DellWinPE10Pack = @{
        Name = "Dell Windows PE Driver Pack (Win10+)";
        URL = "https://downloads.dell.com/FOLDER11211606M/1/WinPE10.0-Drivers-A33-CCKD7.cab";
        DownloadHash = "7D2A85674B0BBED95C2905A30F6C9B30E7F3723911E56351DAD33D82549F4EE3";
        FileName = "WinPE10.0-Drivers-A33-CCKD7.cab";
    };
    DellWinPE11Pack = @{
        Name = "Dell Windows PE Driver Pack (Win11+)";
        URL = "https://downloads.dell.com/FOLDER11559429M/1/WinPE11.0-Drivers-A03-V81GV.cab";
        DownloadHash = "23E3D5D921525246B6A0D55797392B7DFA08D293D4B16073B1E1B41F8FB4B3AF";
        FileName = "WinPE11.0-Drivers-A03-V81GV.cab";
    };
    HPClientDriverPack = @{
        Name = "HP Windows PE Client Drivers";
        URL = "https://ftp.ext.hp.com/pub/softpaq/sp151001-151500/sp151478.exe";
        DownloadHash = "A1825CA0248B3121695D8EA78BFBF43046C4B842C4BF83D6AF6E3B6DFBDD89BE";
        FileName = "sp151478.exe";
    };
    IntelLSIMegaSASDrivers = @{
        Name = "Intel / LSI MegaSAS RAID Drivers";
        URL = "https://downloadmirror.intel.com/29537/eng/intel_windows_drv_mr_6.714.18.00_pv.zip";
        DownloadHash = "18C2764692D39399F0F2706DC604D1872158603080A2D65BCC7D1FA36C4C28C1";
        FileName = "intel_windows_drv_mr_6.714.18.00_pv.zip";
    }
    SurfacePro8 = @{
        Name = "Surface Pro 8";
        URL = "https://download.microsoft.com/download/9/1/3/9133dbd3-799a-4766-bb9e-f67697159c02/SurfacePro8_Win11_22621_24.063.29016.0.msi";
        DownloadHash = "88B52CC8853F320AB2F8874B97E578D4E48C354EF6F71A48DAB61995DB4F9601";
        FileName = "SurfacePro8_Win11_22621_24.063.29016.0.msi";
        FolderName = "SurfacePro8";
    };
    SurfacePro9Intel = @{
        Name = "Surface Pro 9 with Intel Processor";
        URL = "https://download.microsoft.com/download/e/9/a/e9a35d1b-7b4c-48d4-8619-5301d4c09f65/SurfacePro9_Win11_22621_24.062.27401.0.msi";
        DownloadHash = "576288C74DDE8D2F7A86A88B2A91BF3A213659E1AF308F57E86990F4AB577880";
        FileName = "SurfacePro9_Win11_22621_24.062.27401.0.msi";
        FolderName = "SurfacePro9Intel";
    };
    SurfacePro10 = @{
        Name = "Surface Pro 10";
        URL = "https://download.microsoft.com/download/d/c/c/dcc1042a-1a67-4b20-b0cd-5322f1604154/SurfacePro10forBusiness_Win11_22631_24.062.18480.0.msi";
        DownloadHash = "7021A0BCDFF69F17931652E2CAD33A6DAC962B211E328DE66CE74663380708F4";
        FileName = "SurfacePro10forBusiness_Win11_22631_24.062.18480.0.msi";
        FolderName = "SurfacePro10";
    };
    SurfaceLaptop4AMD = @{
        Name = "Surface Laptop 4 with AMD Processor";
        URL = "https://download.microsoft.com/download/c/2/8/c2840704-6c0e-4457-82ca-68502b1803b5/SurfaceLaptop4_AMD_Win11_22621_24.064.39167.0.msi";
        DownloadHash = "5D400B10DEA79FC06FC62CA0A3B569F66AD7B55D28E537F16F73984500802CE2";
        FileName = "SurfaceLaptop4_AMD_Win11_22621_24.064.39167.0.msi";
        FolderName = "SurfaceLaptop4AMD";
    };
    SurfaceLaptop4Intel = @{
        Name = "Surface Laptop 4 with Intel Processor";
        URL = "https://download.microsoft.com/download/f/7/0/f70b3d0a-59b1-4842-9130-0c152bb738ba/SurfaceLaptop4_Intel_Win11_22621_24.072.27345.0.msi";
        DownloadHash = "B78949C575190D45A822810E3827E175AD437F21E10F9F9F06C8AEF2DF9DB349";
        FileName = "SurfaceLaptop4_Intel_Win11_22621_24.072.27345.0.msi";
        FolderName = "SurfaceLaptop4Intel";
    };
    SurfaceLaptop5 = @{
        Name = "Surface Laptop 5";
        URL = "https://download.microsoft.com/download/d/2/6/d26c7d69-ec2f-4dd6-95ab-7e1d2b5ee7ae/SurfaceLaptop5_Win11_22621_24.072.21679.0.msi";
        DownloadHash = "8A67A828359366B82BCC4EE3E4DEE98D07602DEBAB7EEA33C8CBF5BD8C28B6D5";
        FileName = "SurfaceLaptop5_Win11_22621_24.072.21679.0.msi";
        FolderName = "SurfaceLaptop5";
    };
    SurfaceLaptop6 = @{
        Name = "Surface Laptop 6";
        URL = "https://download.microsoft.com/download/0/5/0/0508e86f-59f7-4b47-8c1a-fa9c13b03b08/SurfaceLaptop6forBusiness_Win11_22631_24.061.14582.0.msi";
        DownloadHash = "0BB9BFBA109FD260C0FB8C1245081AB93FA02CD1F428D4D5495096EFFE4A0B0F";
        FileName = "SurfaceLaptop6forBusiness_Win11_22631_24.061.14582.0.msi";
        FolderName = "SurfaceLaptop6";
    };
    VMwareToolsISO = @{
        Name = "VMware Tools";
        URL = "https://packages.vmware.com/tools/releases/latest/windows/VMware-tools-windows-12.4.5-23787635.iso";
        DownloadHash = "A16C79DFA7DEA79410D7E1B4221A52CF945138767A2EC0D4DCDAFA2594B7CAEC";
        FileName = "VMware-tools-windows-12.4.5-23787635.iso";
    };
}

$CSPERecoveryISO = "CSPERecovery_x64.iso"
$CSSafeBootISO = "CSSafeBoot_x64.iso"

function Get-CSVFile {
    Param(
        [Parameter(Mandatory = $true)]
        $FilePath
    )
    if (-Not (Test-Path -Path "$FilePath")) {
        Write-Host "[+] No BitLockerKeys.csv - skipping"
        return $false
    }

    Write-Host "[+] Found a BitLocker key database CSV"
    $KeyDatabase = Import-Csv -Path $FilePath
    
    foreach ($KeyEntry in $KeyDatabase) {
        $IsRecoveryIDValid = ($KeyEntry.KeyID -match '^\w{8}-(\w{4}-){3}\w{12}$' -and $KeyEntry.KeyID.Length -eq 36)
        if (-Not $IsRecoveryIDValid)
        {
            Write-Host "[-] Found invalid recovery ID $($KeyEntry.KeyID), aborting CSV import" -ForegroundColor Red
            Write-Host "[-] ERROR: invalid format in BitLockerKeys.csv" -ForegroundColor Red
            Exit
        } 
        $IsRecoveryKeyValid = ($KeyEntry.RecoveryKey -match '^(\d{6}-){7}\d{6}$' -and $KeyEntry.RecoveryKey.Length -eq 55)
        if (-Not $IsRecoveryKeyValid)
        {
            Write-Host "[-] Found invalid recovery key $($KeyEntry.RecoveryKey), aborting CSV import" -ForegroundColor Red
            Write-Host "[-] ERROR: invalid format in BitLockerKeys.csv" -ForegroundColor Red
            Exit
        } 
    }

    Write-Host "[+] Successfully validated BitLocker recovery keys and ID's"
    return $true
}

function Get-CachedDownload {
    Param(
        [Parameter(Mandatory = $true)]
        $Package
    )
    if (-not(Test-Path -Path "$DownloadsDir")) {
        mkdir -Path "$DownloadsDir"
    }

    $DownloadRequired = $true
    $DownloadPath = "$DownloadsDir\$($Package.FileName)"

    if (Test-Path -Path "$DownloadPath") {
        Write-Host "[+] Download for the $($Package.Name) package was found in the cache. Checking its integrity."
        if ((Get-FileHash -Path "$DownloadPath").Hash -eq $Package.DownloadHash) {
            Write-Host "[+] Cached download verified" -ForegroundColor Green
            $DownloadRequired = $false
        }
        else {
            Write-Host "[-] Hash verification failed. Package will redownload." -ForegroundColor Yellow
            Remove-Item -Path "$DownloadPath" -Force -Confirm:$false
        }
    }

    if (!$DownloadRequired) {
        return
    }

    Write-Host "[+] Downloading the $($Package.Name) package..."
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $Package.URL -OutFile "$DownloadPath" -ErrorAction Stop
    $ProgressPreference = "Continue"

    Write-Host "[+] Verifying the $($Package.Name) package"
    if ((Get-FileHash -Path "$DownloadPath").Hash -ne $Package.DownloadHash) {
        Write-Host "[-] ERROR: Failed to verify the hash of the $($Package.Name) package" -ForegroundColor Red
        exit
    }
}


function Get-CSVFile {
    Param(
        [Parameter(Mandatory = $true)]
        $FilePath
    )
    if (-Not (Test-Path -Path "$FilePath")) {
        Write-Host "[+] No BitLockerKeys.csv - skipping"
        return $false
    }

    Write-Host "[+] Found a BitLocker key database CSV"
    $KeyDatabase = Import-Csv -Path $FilePath
    
    foreach ($KeyEntry in $KeyDatabase) {
        $IsRecoveryIDValid = ($KeyEntry.KeyID -match '^\w{8}-(\w{4}-){3}\w{12}$' -and $KeyEntry.KeyID.Length -eq 36)
        if (-Not $IsRecoveryIDValid)
        {
            Write-Host "[-] Found invalid recovery ID $($KeyEntry.KeyID), aborting CSV import" -ForegroundColor Red
            Write-Host "[-] ERROR: invalid format in BitLockerKeys.csv" -ForegroundColor Red
            Exit
        } 
        $IsRecoveryKeyValid = ($KeyEntry.RecoveryKey -match '^(\d{6}-){7}\d{6}$' -and $KeyEntry.RecoveryKey.Length -eq 55)
        if (-Not $IsRecoveryKeyValid)
        {
            Write-Host "[-] Found invalid recovery key $($KeyEntry.RecoveryKey), aborting CSV import" -ForegroundColor Red
            Write-Host "[-] ERROR: invalid format in BitLockerKeys.csv" -ForegroundColor Red
            Exit
        } 
    }

    Write-Host "[+] Successfully validated BitLocker recovery keys and IDs"
    return $true
}

function Remove-MOTW {
    Param(
        [Parameter(Mandatory = $true)]
        $FilePath
    )
    # Remove mark of the web (MOTW) to avoid PowerShell prompts
    Remove-Item -Path "$FilePath" -Stream "Zone.Identifier" -Force -Confirm:$false -ErrorAction SilentlyContinue
}

function Install-ADK {
    Write-Host "[+] Checking if ADK is installed..."

    $ADKInstalled = Test-Path -Path "$ADKInstallLocation\Assessment and Deployment Kit\Deployment Tools\AMD64"
    if ($ADKInstalled)
    {
        Write-Host "[+] An installation of ADK was found on device. Skipping ADK installation." -ForegroundColor Yellow
    }
    else
    {
        Write-Host "[+] An installation of ADK was not found on the device. This tool will now download and install the Windows ADK."
        Get-CachedDownload -Package $PackageRepository.ADKInstaller

        Write-Host "[+] Please wait while the ADK is downloaded and installed. Please note that this may take a while." -ForegroundColor Blue
        Start-Process -FilePath "$DownloadsDir\$($PackageRepository.ADKInstaller.FileName)" -ArgumentList "/features", "OptionId.DeploymentTools", "/q", "/ceip", "off", "/installpath", """$ADKInstallLocation""", "/norestart" -Wait
        Write-Host "[+] Successfully installed Windows ADK." -ForegroundColor Green
    }

    #
    # Check if the ADK WinPE Addon is installed
    #
    Write-Host "[+] Checking if ADK WinPE addon is installed..."
    $ADKWinPEInstalled = Test-Path -Path "$ADKWinPELocation"
    if ($ADKWinPEInstalled)
    {
        Write-Host "[+] An installation of Windows ADK WinPE add-on was found on this device. Skipping installation." -ForegroundColor Yellow
    }
    else
    {
        Write-Host "[+] An installation for Windows ADK WinPE add-on was not found on this device. This tool will now download and install the Windows ADK WinPE add-on."
        Get-CachedDownload -Package $PackageRepository.ADKWinPEInstaller

        Write-Host "[+] Please wait while the Windows PE ADK addon is downloaded and installed. Please note that this may take a while." -ForegroundColor Blue
        Start-Process -FilePath "$DownloadsDir\$($PackageRepository.ADKWinPEInstaller.FileName)" -ArgumentList "/features", "OptionId.WindowsPreinstallationEnvironment", "/q", "/ceip", "off", "/installpath", """$ADKInstallLocation""", "/norestart" -Wait
        Write-Host "[+] Successfully installed the Windows ADK WinPE add-on." -ForegroundColor Green
    }
}

function Get-CommonDrivers {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    Write-Host "[+] Downloading common drivers for multiple vendors" -ForegroundColor Cyan
    # Intel MegaSAS driver pack
    # Supports: RMS3AC160, RMS3CC080, RMS3CC040, RMS3HC080, RS3YC, RS3LC, RS3SC008, RS3MC044, RS3DC080,
    # RS3DC040, RS3WC080, RCS25ZB040, RCS25ZB040LX, RMS25PB080, RMS25PB040, RMT3PB080, RMS25CB080,
    # RMS25CB040, RMT3CB080, RMS25CB080N, RMS25PB080N, RS25AB080, RS25SB008, RS25DB080, RS25NB008,
    # RS2VB080, RS2VB040, RT3WB080, RS2WC040, RS2WC080, RS2SG244, RS2WG160, RMS2MH080, RMS2AF080,
    # RMS2AF040, RS2MB044, RS2BL080, RS2BL080DE, RS2BL040, RS2PI008DE, RS2PI008
    Get-CachedDownload -Package $PackageRepository.IntelLSIMegaSASDrivers

    Write-Host "[+] Extracting Intel / LSI MegaSAS RAID driver package"
    Expand-Archive -Path "$DownloadsDir\$($PackageRepository.IntelLSIMegaSASDrivers.FileName)" -DestinationPath "$WorkDir"

    Write-Host "[+] Staging driver files"
    Move-Item -Path "$WorkDir\intel_windows_drv_mr_6.714.18.00_pv\win10_x64" -Destination "$WorkDir\Drivers\intel_windows_drv_mr_6.714.18.00_pv_Win10_x64"
    Remove-Item -Path "$WorkDir\intel_windows_drv_mr_6.714.18.00_pv" -Force -Recurse -Confirm:$false

    Write-Host "[+] Intel / LSI MegaSAS RAID drivers successfuly staged" -ForegroundColor Green

    Get-CachedDownload -Package $PackageRepository.AMDSATADrivers
    $AMDSATADir = "$WorkDir\Drivers\amd_sata"
    mkdir "$AMDSATADir"
    Push-Location "$AMDSATADir"
    Write-Host "[+] Extracting the AMD SATA cab file"
    Start-Process cmd.exe -ArgumentList "/c", "C:\Windows\System32\expand.exe", "-F:*", """$DownloadsDir\$($PackageRepository.AMDSATADrivers.FileName)""", "." -NoNewWindow -Wait
    Pop-Location

    Write-Host "[+] AMD SATA drivers successfully staged" -ForegroundColor Green
}

function Get-VMwareDrivers {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    Get-CachedDownload -Package $PackageRepository.VMwareToolsISO

    Write-Host "[+] Mounting VMware Tools ISO"
    $mount = Mount-DiskImage -ImagePath "$DownloadsDir\$($PackageRepository.VMwareToolsISO.FileName)" -StorageType ISO
    $vol = Get-Volume | Where-Object {$_.FileSystemLabel -eq "VMware Tools"}
    $vol = $vol[0]

    Write-Host "[+] Copying the VMware PVSCSI driver into the working directory"
    $VMwareDriveLetter = $vol.DriveLetter
    $PVSCSIDir = "$WorkDir\Drivers\VMwarePVSCSI"
    mkdir "$PVSCSIDir"
    Copy-Item -Path "$VMwareDriveLetter`:\Program Files\VMware\VMware Tools\Drivers\pvscsi\Win10\amd64\*" -Destination "$PVSCSIDir" -Recurse

    Write-Host "[+] Unmounting VMware Tools ISO"
    Dismount-DiskImage -DevicePath $mount.DevicePath
    Write-Host "[+] VMware PVSCSI driver successfully staged" -ForegroundColor Green
}

function Get-HPClientDrivers {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    Get-CachedDownload -Package $PackageRepository.HPClientDriverPack

    Write-Host "[+] Executing the HP Driver Pack driver package to extract the Windows PE drivers..."
    Start-Process "$DownloadsDir\$($PackageRepository.HPClientDriverPack.FileName)" -ArgumentList "/s", "/e", "/f", """$WorkDir\Drivers\HP""" -NoNewWindow -Wait

    Write-Host "[+] Curating HP client drivers"
    Remove-Item -Path "$WorkDir\Drivers\HP\WinPE10_2.70\x64_winpe10\network" -Recurse -Force -Confirm:$false

    Write-Host "[+] HP drivers successfully staged" -ForegroundColor Green
}

function Get-DellDrivers-WinPE10 {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    Get-CachedDownload -Package $PackageRepository.DellWinPE10Pack

    $DellDir = "$WorkDir\Drivers\DellWinPE10"
    mkdir $DellDir
    Push-Location $DellDir

    Write-Host "[+] Extracting the Dell Windows PE Driver Pack (Win10+) cab file"
    Start-Process cmd.exe -ArgumentList "/c", "C:\Windows\System32\expand.exe", "-F:*", """$DownloadsDir\$($PackageRepository.DellWinPE10Pack.FileName)""", "." -NoNewWindow -Wait
    Pop-Location

    Write-Host "[+] Curating Dell Win10+ drivers"
    Remove-Item -Path "$WorkDir\Drivers\DellWinPE10\winpe\x86" -Recurse
    Remove-Item -Path "$WorkDir\Drivers\DellWinPE10\winpe\x64\network" -Recurse

    Write-Host "[+] Dell Windows PE drivers (Win10+) successfully staged" -ForegroundColor Green
}


function Get-DellDrivers-WinPE11 {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    Get-CachedDownload -Package $PackageRepository.DellWinPE11Pack

    $DellDir = "$WorkDir\Drivers\DellWinPE11"
    mkdir $DellDir
    Push-Location $DellDir

    Write-Host "[+] Extracting the Dell Windows PE Driver Pack (Win11+) cab file"
    Start-Process cmd.exe -ArgumentList "/c", "C:\Windows\System32\expand.exe", "-F:*", """$DownloadsDir\$($PackageRepository.DellWinPE11Pack.FileName)""", "." -NoNewWindow -Wait
    Pop-Location

    Write-Host "[+] Curating Dell Win11+ drivers"
    Remove-Item -Path "$WorkDir\Drivers\DellWinPE11\winpe\x64\network" -Recurse

    Write-Host "[+] Dell Windows PE drivers (Win11+) successfully staged" -ForegroundColor Green
}

function Get-SurfaceDrivers {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    $SurfaceDriversDir = "$WorkDir\Drivers\Surface"
    $SurfaceTempDriversDir = "$WorkDir\SurfaceTemp"
    # This function will download and stage drivers for common Surface devices
    # In-scope drivers: keyboard, trackpad, touch screen, storage, chipset
    # Out of scope drivers: network, brightness control, button control, sleep, etc.
    # For other Surface devices, please download and extract the drivers separately, and place the required
    # drivers into the Drivers folder next to this build script.
    $ProgressPreference = "SilentlyContinue"

    # Commented drivers are recommended by Microsoft for Windows PE, but are likely not required for this use case
    $SurfaceDriverTypes = @(
        "ialpss2gpio2mtl",
        "ialpss2i2cmtl",
        "ialpss2spimtl",
        "ialpss2uart2mtl",
        "intcpmt",
        "intelquickspi",
        "msu53cx22x64sta",
        "msu56cx22x64sta",
        "surfaceacpiplatformextension",
        # "surfacebattery",
        # "surfacebutton",
        "surfacehidminidriverwinre",
        # "surfacehotplug",
        "surfaceintegrationdriver",
        "surfacepanel",
        # "surfacepen217integration",
        # "surfacepenblelcaddradaptationdriver",
        "surfaceserialhub",
        # "surfaceservicenulldriver",
        "surfacesptclient",
        # "surfacetimealarmacpifilter",
        # "surfacetouchpenprocessor0c88update"
        # "surfacetouchpenprocessor0c89update",
        "surfaceucmucsihidclient",
        # 'tbtslimhostcontroller',
        "acpiplatformextension",
        # "Battery",
        # "DockIntegration",
        "HidMini",
        # "HotPlug",
        # "Integration",
        "IntelQuickSPI",
        # "msu53cx22x64sta",
        # "msu56cx22x64sta",
        # "penwirelesschargerhotkey",
        # "SarManager",
        "SerialHub",
        # "Service",
        # "SMFClient",
        # "smfdisplayclient",
        # "timealarmacpifilter",
        "UcmUcsiHidClient",
        "adlserial",
        "alderlakepchpsystem",
        "alderlakesystem",
        "gna",
        "intelprecisetouch",
        # "managementengine",
        # "msump64x64sta",
        # "surfacedockintegration",
        "surfacehidmini",
        # "surfacesarmanager",
        "surfaceserialhubdriver",
        "intelthcbase",
        # "SurfaceCoverClick",
        # "SurfaceEthernetAdapter",
        "surfacetypecoverv7fprude",
        # "surfacevirtualfunctionenum",
        "TglChipset",
        "TglSerial",
        "SurfaceTconDriver",
        # "U0361415",
        # "AMDfendr",
        "AMDGpio2",
        "AMDI2c",
        # "AMDLpcFilterDriver",
        # "AMDMicroPEP",
        # "AMDPsp",
        "AMDSmf",
        "AMDSpi",
        "AMDUart",
        "SMBUS",
        "SurfaceDigitizerHidSpiExtnPackage",
        "SurfaceHIDFriendlyNames",
        "SurfaceOemPanel"
        # "SurfacePowerMeter",
        # "SurfacePowerTrackerCore",
        # "SurfaceSmfDisplayClient",
        # "SurfaceSystemManagementFramework",
        # "SurfaceThermalPolicy",
    )
    $SurfacePackages = @(
        $PackageRepository.SurfacePro8,
        $PackageRepository.SurfacePro9Intel,
        $PackageRepository.SurfacePro10,
        $PackageRepository.SurfaceLaptop4AMD,
        $PackageRepository.SurfaceLaptop4Intel,
        $PackageRepository.SurfaceLaptop5,
        $PackageRepository.SurfaceLaptop6
    )

    Write-Host "[+] Downloading drivers for $($SurfacePackages.Count) Microsoft Surface devices..."
    Write-Host "[+] Please note that Surface driver packages are around 700MB each, so downloads might take a while" -ForegroundColor Blue
    mkdir $SurfaceDriversDir

    Foreach ($SurfacePackage in $SurfacePackages) {
        Get-CachedDownload -Package $SurfacePackage

        Write-Host "[+] Extracting $($SurfacePackage.Name) driver package"

        # WinPE drivers will be placed in WorkDir\SurfaceTemp
        # The driver packages contain much more than is actually required here, so we extract first to a temporary
        # directory, copy over what we need for WinPE to WorkDir\Drivers\Surface, then clean up the rest.
        $ThisDriverDir = "$SurfaceDriversDir\$($SurfacePackage.FolderName)"
        mkdir $ThisDriverDir
        $ThisDriverTempDir = "$SurfaceTempDriversDir\$($SurfacePackage.FolderName)"
        mkdir $ThisDriverTempDir
        Start-Process msiexec.exe -ArgumentList "/a", """$DownloadsDir\$($SurfacePackage.FileName)""", "targetdir=""$ThisDriverTempDir""", "/qn" -NoNewWindow -Wait

        Write-Host "[+] Gathering necessary Surface drivers for Windows PE"
        Foreach ($SurfaceDriverType in $SurfaceDriverTypes) {
            $SourceDriverFolder = "$ThisDriverTempDir\SurfaceUpdate\$SurfaceDriverType"
            if (Test-Path -Path "$SourceDriverFolder") {
                Write-Host "[+] Gathering $SurfaceDriverType driver for $($SurfacePackage.Name)"
                Move-Item -Path "$SourceDriverFolder" -Destination "$ThisDriverDir"
            }
        }

        Write-Host "[+] Cleaning up $($SurfacePackage.Name) driver package"
        Remove-Item -Path "$ThisDriverTempDir" -Recurse -Confirm:$false -Force
    }

    Write-Host "[+] Surface drivers successfully staged" -ForegroundColor Green
    $ProgressPreference = "Continue"
}

function New-Directory {
    Param(
        [Parameter(Mandatory = $true)]
        $Dir
    )

    if (Test-Path -Path $Dir) {
        if (Test-Path -Path "$Dir\Drivers") {
            Remove-Item -Path "$Dir\Drivers" -Force -Recurse -Confirm:$false
        }
        Remove-Item -Path "$Dir" -Force -Recurse -Confirm:$false
        Write-Host "[+] Cleaned up the old working directory $Dir"
    }

    mkdir "$Dir"
    mkdir "$Dir\Drivers"
}

function New-BootDisks {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir,
        [Parameter(Mandatory = $false)]
        $BitLockerCSV
    )
    Write-Host "[+] Loading ADK environment variables"
    # Load the environment variables set by an ADK script run with no parameters into this PowerShell session
    $envVars = cmd.exe /c """$DandISetEnvPath"" && set" | Out-String
    $envVars -split "`r`n" | ForEach-Object {
        if ($_ -match "^(.*?)=(.*)$")
        {
            # Update the current execution environment
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], [System.EnvironmentVariableTarget]::Process)
        }
    }

    Write-Host "[+] Creating a working copy of Windows PE"
    $WinPEPath = "$WorkDir\WinPE"
    Start-Process -FilePath "$CopyPEPath" -ArgumentList "amd64", """$WinPEPath""" -NoNewWindow -Wait

    Write-Host "[+] Adding libvirt licence"
    Copy-Item -Path "$DriversDir\libvirt\readme-license.rtf" -Destination "$WinPEPath\media\readme-license.rtf"

    $WinPEMountLocation = "$WinPEPath\mount"

    Write-Host "[+] Mounting Windows PE Image"
    Mount-WindowsImage -ImagePath "$WinPEPath\media\sources\boot.wim" -Path "$WinPEMountLocation" -Index 1

    Write-Host "[+] Setting Locale to en-US"
    Start-Process dism -ArgumentList "/Set-AllIntl:en-US", "/Image:""$WinPEMountLocation""" -NoNewWindow -Wait

    Write-Host "[+] Setting Time Zone to UTC"
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Set-TimeZone:""GMT Standard Time""" -NoNewWindow -Wait

    Write-Host "[+] Installing required WinPE packages"
    $WinPEPackagePath = "$ADKInstallLocation\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs"

    # WinPE WMI
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-WMI.cab""" -NoNewWindow -Wait
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\en-us\WinPE-WMI_en-us.cab""" -NoNewWindow -Wait

    # WinPE StorageWMI
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-StorageWMI.cab""" -NoNewWindow -Wait
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\en-us\WinPE-StorageWMI_en-us.cab""" -NoNewWindow -Wait

    # WinPE Scripting
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-Scripting.cab""" -NoNewWindow -Wait
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\en-us\WinPE-Scripting_en-us.cab""" -NoNewWindow -Wait

    # WinPE .Net Framework
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-NetFx.cab""" -NoNewWindow -Wait
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\en-us\WinPE-NetFx_en-us.cab""" -NoNewWindow -Wait

    # WinPE PowerShell
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-PowerShell.cab""" -NoNewWindow -Wait
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\en-us\WinPE-PowerShell_en-us.cab""" -NoNewWindow -Wait

    # WinPE DISM
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-DismCmdlets.cab""" -NoNewWindow -Wait
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\en-us\WinPE-DismCmdlets_en-us.cab""" -NoNewWindow -Wait

    # WinPE FMAPI
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-FMAPI.cab""" -NoNewWindow -Wait

    # WinPE Secure Boot Cmdlets
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-SecureBootCmdlets.cab""" -NoNewWindow -Wait

    # WinPE Enhanced Storage
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-EnhancedStorage.cab""" -NoNewWindow -Wait
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\en-us\WinPE-EnhancedStorage_en-us.cab""" -NoNewWindow -Wait

    # WinPE Secure Startup
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-SecureStartup.cab""" -NoNewWindow -Wait
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\en-us\WinPE-SecureStartup_en-us.cab""" -NoNewWindow -Wait

    # WinPE Dot3Svc (for certutil.exe)
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\WinPE-Dot3Svc.cab""" -NoNewWindow -Wait
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Package", "/PackagePath:""$WinPEPackagePath\en-us\WinPE-Dot3Svc_en-us.cab""" -NoNewWindow -Wait

    Write-Host "[+] Installing packaged and user-provided third party drivers"
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Driver", "/Recurse", "/Driver:""$PSScriptRoot\Drivers""" -NoNewWindow -Wait
    
    Write-Host "[+] Installing downloaded third party drivers"
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Driver", "/Recurse", "/Driver:""$WorkDir\Drivers""" -NoNewWindow -Wait

    Write-Host "[+] Installing CrowdStrike recovery scripts"
    Remove-MOTW -FilePath "$ScriptsDir\CSPERecovery_startnet.cmd"
    Copy-Item -Force -Path "$ScriptsDir\CSPERecovery_startnet.cmd" -Destination "$WinPEMountLocation\Windows\System32\startnet.cmd"

    Remove-MOTW -FilePath "$ScriptsDir\CSPERecovery.ps1"
    Copy-Item -Force -Path "$ScriptsDir\CSPERecovery.ps1" -Destination "$WinPEMountLocation\Windows\System32\CSPERecovery.ps1"

    Remove-MOTW -FilePath "$ScriptsDir\CSAuthenticodePublicKey.pem"
    Copy-Item -Force -Path "$ScriptsDir\CSAuthenticodePublicKey.pem" -Destination "$WinPEMountLocation\Windows\System32\CSAuthenticodePublicKey.pem"

    if ($BitlockerCSV) {
        Write-Host "[+] Adding BitLockerKeys.csv to recovery iso"
        Copy-Item -Force -Path "$PSScriptRoot\BitLockerKeys.csv" -Destination "$WinPEMountLocation\BitLockerKeys.csv"
    }

    Write-Host "[+] Dismounting and committing Windows PE Image"
    Dismount-WindowsImage -Path "$WinPEMountLocation" -Save

    Write-Host "[+] CS WinPE Recovery boot.wim built" -ForegroundColor Green

    if ($SkipBootPrompt) {
        Write-Host "[+] -SkipBootPrompt flag provided. Removing requirement to ""press any key"" to boot Windows PE." -ForegroundColor Yellow
        $NoPromptFWFile = "$OSCDIMGPath\efisys_noprompt.bin"
        $WorkingFWFile = "$WinPEPath\fwfiles\efisys.bin"
        Copy-Item -Force -Path $NoPromptFWFile -Destination $WorkingFWFile
    }

    Write-Host "[+] Creating CS WinPE Recovery bootable ISO"

    Push-Location $WorkDir
    Start-Process $MakeWinPEMediaPath -ArgumentList "/ISO", "WinPE", "..\$CSPERecoveryISO" -NoNewWindow -Wait
    Pop-Location

    Write-Host "[+] CS WinPE Recovery ISO build completed successfully" -ForegroundColor Green

    Write-Host "[+] Building Safe Mode Boot ISO"
    Write-Host "[+] Mounting Windows PE Image"
    Mount-WindowsImage -ImagePath "$WinPEPath\media\sources\boot.wim" -Path "$WinPEMountLocation" -Index 1

    Write-Host "[+] Installing Safe Mode Script"
    Remove-Item -Force -Path "$WinPEMountLocation\Windows\System32\CSPERecovery.ps1"

    Remove-MOTW -FilePath "$ScriptsDir\SafeBoot_startnet.cmd"
    Copy-Item -Force -Path "$ScriptsDir\SafeBoot_startnet.cmd" -Destination "$WinPEMountLocation\Windows\System32\startnet.cmd"
    
    if ($BitlockerCSV) {Remove-Item -Force -Path "$WinPEMountLocation\BitLockerKeys.csv"}

    Write-Host "[+] Installing Safe Boot recovery batch script"
    Remove-MOTW -FilePath "$ScriptsDir\SafeBoot_CSRecovery.cmd"
    Copy-Item -Force -Path "$ScriptsDir\SafeBoot_CSRecovery.cmd" -Destination "$WinPEPath\media\CSRecovery.cmd"

    Write-Host "[+] Dismounting and committing Windows PE Image"
    Dismount-WindowsImage -Path "$WinPEMountLocation" -Save

    Write-Host "[+] Windows PE Safe Boot boot.wim built" -ForegroundColor Green
    Write-Host "[+] Creating bootable ISO"

    Push-Location $WorkDir
    Start-Process $MakeWinPEMediaPath -ArgumentList "/ISO", "WinPE", "..\$CSSafeBootISO" -NoNewWindow -Wait
    Pop-Location

    Write-Host "[+] Safe Boot ISO built" -ForegroundColor Green
}

Write-Host "[+] Checking if the Drivers directory exists"
if (Test-Path -Path "$DriversDir" -PathType Container) {
    Write-Host "[+] Drivers directory exists"
} else {
    Write-Host "[-] ERROR: The Drivers directory does not exist. Please review the documentation and re-run this tool." -ForegroundColor Red
    Exit
}

Write-Host "[+] Checking if the Scripts directory exists"
if (Test-Path -Path "$ScriptsDir" -PathType Container) {
    Write-Host "[+] Scripts directory exists"
} else {
    Write-Host "[-] ERROR: The Scripts directory does not exist. Please review the documentation and re-run this tool." -ForegroundColor Red
    Exit
}

Write-Host "[+] Checking for BitLockerKeys.csv"
$BitlockerCSV = Get-CSVFile -FilePath "$PSScriptRoot\BitLockerKeys.csv"

Write-Host "CrowdStrike WinPE Recovery and Safe Boot ISO Generation Tool"
Write-Host "Execution of this tool constitutes acceptance of the licence agreements for the following components:"
Write-Host "- Microsoft Assessment and Deployment Toolkit (ADK)"
Write-Host "- Microsoft ADK Windows Preinstallation Environment Addon"
Write-Host "- Any device drivers you include in the final bootable image"
Write-Host "If you do not accept any of these terms, cancel execution of this script immediately. Execution will continue automatically in ten seconds." -ForegroundColor Yellow

if ($true -eq $SkipThirdPartyDriverDownloads) {
    Write-Host "[+] NOTE: Skipping download of third party drivers from Dell, HP, and VMware" -ForegroundColor Yellow
}
Write-Host "[+] Including: All drivers in the Drivers directory next to this script" -ForegroundColor Green

$DriverPacks = [ordered]@{
    Common = @{
        Enabled = $IncludeCommonDrivers
        Name = "Common driver pack (multi-vendor)"
    };
    Dell = @{
        Enabled = $IncludeDellDrivers
        Name = "Dell Win10+ and Win11+ Windows PE driver packs"
    };
    HP = @{
        Enabled = $IncludeHPDrivers
        Name = "HP Windows PE driver pack"
    };
    Surface = @{
        Enabled = $IncludeSurfaceDrivers
        Name = "Surface drivers (Surface Laptop 4, 5, 6, and Surface Pro 8, 9, 10)"
    };
    VMware = @{
        Enabled = $IncludeVMwareDrivers
        Name = "VMware PVSCSI driver"
    };
}

$GlobalInclude = !$SkipThirdPartyDriverDownloads
if ($IncludeCommonDrivers -or $IncludeDellDrivers -or $IncludeHPDrivers -or $IncludeSurfaceDrivers -or $IncludeVMwareDrivers) {
    $GlobalInclude = $false
}

foreach ($DriverPack in $DriverPacks.Values) {
    if (($true -eq $DriverPack.Enabled -or $true -eq $GlobalInclude) -and $false -eq $SkipThirdPartyDriverDownloads) {
        Write-Host "[+] Including: $($DriverPack.Name)" -ForegroundColor Green
        $DriverPack.Enabled = $true
    }
    else {
        Write-Host "[X] Skipping:  $($DriverPack.Name)" -ForegroundColor Yellow
        $DriverPack.Enabled = $false
    }
}

if ($SkipBootPrompt) {
    Write-Host "`r`n[+] NOTE: -SkipBootPrompt was chosen, so the ISOs will boot automatically without prompting for a key press." -ForegroundColor Cyan
    Write-host "[+] Remember to remove the CD/unplug the flash drive/dismount the ISO from a target system if it is configured to boot from external storage by default." -ForegroundColor Cyan
}

Start-Sleep -Seconds 10

Write-Host "[+] Downloading and Staging Drivers"

# Setting up the work directory
$LocalWorkDir = Get-Location
$LocalWorkDir = "$LocalWorkDir\WorkDir"
New-Directory -Dir $LocalWorkDir

# Install the Windows ADK
Install-ADK

# Download vendor-specific drivers for Windows PE
if ($true -eq $DriverPacks["Common"].Enabled) {
    Get-CommonDrivers -WorkDir $LocalWorkDir
}

if ($true -eq $DriverPacks["Dell"].Enabled) {
    Get-DellDrivers-WinPE10 -WorkDir $LocalWorkDir
    Get-DellDrivers-WinPE11 -WorkDir $LocalWorkDir
}

if ($true -eq $DriverPacks["HP"].Enabled) {
    Get-HPClientDrivers -WorkDir $LocalWorkDir
}

if ($true -eq $DriverPacks["Surface"].Enabled) {
    Get-SurfaceDrivers -WorkDir $LocalWorkDir
}

if ($true -eq $DriverPacks["VMware"].Enabled) {
    Get-VMwareDrivers -WorkDir $LocalWorkDir
}

Write-Host "[+] Building Boot Disks"
New-BootDisks -WorkDir $LocalWorkDir -BitlockerCSV $BitlockerCSV

Write-Host "[+] Complete!" -ForegroundColor Green
Write-Host "CrowdStrike WinPE Recovery ISO: $CSPERecoveryISO"
Write-Host "CrowdStrike Safe Boot ISO: $CSSafeBootISO"

# SIG # Begin signature block
# MIIuwwYJKoZIhvcNAQcCoIIutDCCLrACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDVgb1MmpdVdMWa
# oHIAeht+oqNu//8bTTCn/6kC5Sa7LaCCE68wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggawMIIEmKADAgECAhAOTWf2QxbJKjt6F8xGl2qPMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMTA3MjgwMDAwMDBaFw0zNjA3MjcyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCuLgx90+9o
# 44QI+psMTfM2D+ex8zQyg0ZUYl/qiBWxymjHTRxk86IBdnAYvI+b8eZLGY0IPEpS
# oVYTUshVPMJhw22SoK/4w0JmgfEhjWYRF2xT6xhh8AMMMemLXSinRuvRKuusS5/r
# 665dHGGlnvGCim1P9aEMbe+peNpsk+woINwSycSW63o2bxccdX4JydmlvCV7g4Jy
# euAt6sEQe76IgSOAK2zTWf7VvVpuasVfMndoL+Jc//ocipizux0BRTwLtZwt+Veb
# fHN5zrKW2rIoTLFy+B0ExNqmqbDumQWubyXnolily0Ucm13IWyugvqWiMLzJLePn
# PTn5KBoCNIwjxB9qXlYDLYmKL8S+c9l/VrOBS/NiR8qBgTLmQDlz7eP1m4qJ9vsQ
# +nim+RcdknorMmFpu5GBeqM5s71i1GTkudmC/AcnvhP+8VNg7juHbA6q/8lpl3wr
# n8gCJKin8lOOUcGy2Ql+cBvqIfVRQoqAyGk0KlKQz2zbHNBCZnjhEYhEOz4AebmU
# RHhnY6iFD6cw/+BSO+ei5nZdm4j7KfYQFu1EOQGv1hGu7bxumwo0IAuAWY3OjFHu
# uzoVpAHMSyAOPzS7oXThiUUhDCn1TyJZOWNZYxf6nw4ntDUtcA9CX9pJmaV/5Ytd
# ByvzHSpT6/teLVNVIFmm9ExrSz3jUYTRaQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQUvGsiZZ2MaObmHgXx2HIl1LjgSMAwHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATANBgkq
# hkiG9w0BAQsFAAOCAgEASfK8p3nzB1leZwD5fvPqhgNtUe8hR9nTqPtx4fy5UG1g
# gNkeTmhUcbNW6LjDHcP3t91YKqwUv4Hn1n2NlxM92siWay0iIuTKy1U6uTINGw6i
# Ij/o7+e6/E5L6JKj70wsyJT+tQH1ivMsv5RLAV4iK3AvgJGF1/5m5qv81izLWpTx
# wdXTikYh2J7aY8p8trlOpGEDUESVtg9xqQChYrH/87UHTgFiJUBtT10Svaf6ki0H
# b9DONoib201tyvJ5dbyySONUynwA/q3/L3HRdyFnmlVtMAF/+pVPd9/GzLODIvsf
# JaAL99VHutuBWhf0HD8aYfD/GJ1tl1hYFx5OEenWZHYwm1sDrCveX1z4WC44wXnW
# /1BXjn+eEYJAktyc6B0zbBvPXdju51GgXWlsF8N0GrKjWb1m2Xw0PJScanz66M9S
# 756AiA/LdnyFII9sspA1IyyBFJ1ytf4p3447NkqkO8fYQnDM1GqLMksv6W47gAp/
# w0oiVNccVsYZpeGY1cHo9JQvZehuTAeYD1ktXoBDkbdLWAExicsFtuMSa4xjNalP
# /hZbJ1e8ZkaQKDAyocpUeQ6nhHHLfXDwkkFXKnY1O92vklc2WtvVTR0lTUh7Rs2R
# fG/Dm9W+/SOGBIt3Zwymh2bp0yU1TlNa3ZC0utQq1829wsp4XrAbZrKKLoI6xegw
# ggdmMIIFTqADAgECAhANSP/Z4mauPlHcXAYTU4vzMA0GCSqGSIb3DQEBCwUAMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyMSBDQTEwHhcNMjMxMjE4MDAwMDAwWhcNMjYxMjE5MjM1OTU5WjBuMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxl
# MRowGAYDVQQKExFDcm93ZFN0cmlrZSwgSW5jLjEaMBgGA1UEAxMRQ3Jvd2RTdHJp
# a2UsIEluYy4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjWRQhxJ3t
# fVMVHGldhEzO1eO8XKNxtHanRYrMfoZGRKNtNerivsWLR6kkPKxWjM5yfJPEFlwo
# YQJ52ngi1402/rMaEZy+6jhzeE4zSc0zWnRWrXyFDWg/1jNX3MMkrtKjq0F0PVN/
# 1hdfChYjuZyEaXwKIoaUH33GtyLgx8oAX8/5cBXrv9DrZ5n1vjJi3IdicAWhqThK
# F990x+KuYiLdJFlMrFaHBuUoOkH66LLuqu05oIABcDjwvwv5k6erIzfO8JfHouga
# QlW/l51jYIG9nCcbYGDt13JRU5qSW1URJzgVatIU46XuxNGdV1I3/yq99o1MR9Ig
# RmF3DyhIJNUBMjfr4OHvF8VwXsBJvQgy4zYeF7UtvNGUmWxz55dTnSRJwBKDdU/B
# U0XGRuT2mxIqk3saynt2yD3LE6+MPUICnxfyljqMheiqcgI2gzP1kDqfYO/WxlIB
# hF+FFy8iMt2ot2PmNtlC2exYb0YerXdZyANXmF27iuzaMFNII+4PmESLzcDh4M4q
# jV6PG5tz/Ga/XWaBo5H6i0nByTHjCsyw+GihIR8np/ZVIiQAFp5zqDxDUTNUdl8j
# RXjAf5kRbByyMBRRCS3zrWHvFnaiHI6LKOpoJbH2oOEsTwCuMO/mK1F05YHaba4T
# wDf67TWkVZNkMbxjAiWbNQcjRauMi0HBxwIDAQABo4ICAzCCAf8wHwYDVR0jBBgw
# FoAUvGsiZZ2MaObmHgXx2HIl1LjgSMAwHQYDVR0OBBYEFAVzMxoRwTxtGJQjZY9y
# 2dvzL5rkMD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6
# Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww
# CgYIKwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hB
# MjU2MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTI1NjIwMjFDQTEu
# Y3JsMIGUBggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEyNTYy
# MDIxQ0ExLmNydDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQCYJpIKCcY6
# sOCBq+xmlDiy6cgtOk1E6Cy7DBfOXkfYrKiZDx5w1I+nymQFBjfsWMnS5qTmdYGh
# qvVB9LSaIwomVOujNcV41y0HJOVP5w7t4eKzQGTsV+iskMi3HxQxfRAZAxel41Re
# NOKpFHyPpTkF2lvoe2fgY8YLWpxcZQx/P/+xaU4aek5HK+lNueuQ8l8ZNyOGZ3c9
# FcctpYy0IAaqsMnY9mt5ZJAoBWXkKw4JBaL6mWso77KPzDC4O/ugRrBli+HxogM6
# vtVgX4ZbGG7f9zfJOntCPVTqNlU1gxv/2caWNgVNwrp49ndmHVQQGiibgzktTiwt
# Bq4AUQQUGQSBEssDu4CJZX9tKwna30Q0CgIwcF2h3pMprUkKWTMKFp1WdhYIRWh2
# i88MtPd3yAyzAf6hwb/nrMbDimUyqQmpDObXZPsU/oWZAzW28FUbqKnJnayD/3G+
# Ota4j6vATEXIzn1/RZH/1vhYW2B433uF4IxCu9x2VrIrkb/j3wIKtk4rDUohQrCV
# aR6BlEWeiZoBh0W6d1hU8EQzMxjHaqowOXRzcrDh3w15/amuIr0ivGmkhy4Nh0M3
# AZ1EzJNwBMVHsGhgpjJHF3HYoPHOmEIMFLY5/PdDXNQD0NUVSKl/LEcxK2bkhreQ
# wCxXKaDLYxjnLaTcco3jYJER7yfpfPlPVjGCGmowghpmAgEBMH0waTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTI1NiAyMDIxIENB
# MQIQDUj/2eJmrj5R3FwGE1OL8zANBglghkgBZQMEAgEFAKB8MBAGCisGAQQBgjcC
# AQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCt0e8lNvGlE+exWnZxTdf5
# sTYd+NRs/503KuoGYvIFFzANBgkqhkiG9w0BAQEFAASCAgB82Jzb0H0Uqv6TD3iD
# Ryo8df51zYQG889XofcNR+rtF446yOS/DtoBdYimXkyuQsZECVlqPzKfxOkiTMLQ
# qrb8PMfsOp2fXXwN+1UOqF8/2/9AUXtd2Pd/sJQxtF4XTRv0uwCA0glHwSmBh3HC
# d4WI24FBpB/jkaq73AnpWAhs7csB9g5VArOdf7HNhC8CnyvTewixoyGU1Ekv5zxA
# xiszYpX00AowFwpxw6Mx1kx3f/0pEHj+cqgnCbyBVFEyAqJ+42/oYIvZf6BEb7FO
# 90aUAiHoZRoOm2dBWgwN2ax0VzdeM9s7A8QVpeL92fEQ4NnnC5hxlP9XodOYyfua
# DxmRARACCXVImsYqNfBavUM3ldk9oUSUhuhoekCpauRuOsGIuCnf8tOuxIhsRIgt
# PsM3iG9+daeeQwcgfjedv7kQkrFUf2grMN5u86wMBEwZbPrNEDfiQePYxJpn5cXV
# tRCiJ8B4S69VrCPv862tj8h0Zv3D6k2HqG9711NChkgDvDPxNrBIcLgZ8OPZASva
# FxaJsEaXaQnXHufaegGguEKr0PqmcAKjhZyoxhJZDoPUc4AePvTKySoVWXZIEpOT
# 0QV1M5Mth0aD7fLApdIgm9tBDRetcaKmlPzVuwCZoWuTFzUy/CDfx0Wb4DI9Nc2R
# QEYj59nYg+frA5agc6QAw+Hz66GCF0Awghc8BgorBgEEAYI3AwMBMYIXLDCCFygG
# CSqGSIb3DQEHAqCCFxkwghcVAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcN
# AQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCBR6D+j
# yGdachuY8JJ2VxMTH6oQhki7hOEq1z8tmGr8qAIRAKd5hxoc53xPE2o+1Bj8vv8Y
# DzIwMjQwODA1MTUyNDUxWqCCEwkwggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f
# 5WEWMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEz
# MjM1OTU5WjBIMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# IDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIzMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAo1NFhx2DjlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6
# OyqcZ9xiFVjBqZMRp82qsmrdECmKHmJjadNYnDVxvzqX65RQjxwg6seaOy+WZuNp
# 52n+W8PWKyAcwZeUtKVQgfLPywemMGjKg0La/H8JJJSkghraarrYO8pd3hkYhftF
# 6g1hbJ3+cV7EBpo88MUueQ8bZlLjyNY+X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G4
# 5lKVtUfXeCk5a+B4WZfjRCtK1ZXO7wgX6oJkTf8j48qG7rSkIWRw69XloNpjsy7p
# Be6q9iT1HbybHLK3X9/w7nZ9MZllR1WdSiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAs
# NJvj3m5kGQc3AZEPHLVRzapMZoOIaGK7vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU
# 6mIIE9NpHnxkTZ0P387RXoyqq1AVybPKvNfEO2hEo6U7Qv1zfe7dCv95NBB+plwK
# WEwAPoVpdceDZNZ1zY8SdlalJPrXxGshuugfNJgvOuprAbD3+yqG7HtSOKmYCaFx
# smxxrz64b5bV4RAT/mFHCoz+8LbH1cfebCTwv0KCyqBxPZySkwS0aXAnDU+3tTbR
# yV8IpHCj7ArxES5k4MsiK8rxKBMhSVF+BmbTO77665E42FEHypS34lCh8zrTioPL
# QHsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4E
# FgQUpbbvE+fvzdBkodVWqWUxo97V40kwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1
# NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNI
# QTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCp
# tZgXvHCNT4o8aJzYJf/LLOTN6l0ikuyMIgKpuM+AqNnn48XtJoKKcS8Y3U623mzX
# 4WCcK+3tPUiOuGu6fF29wmE3aEl3o+uQqhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoF
# eoQpmLZXeY/bJlYrsPOnvTcM2Jh2T1a5UsK2nTipgedtQVyMadG5K8TGe8+c+nji
# kxp2oml101DkRBK+IA2eqUTQ+OVJdwhaIcW0z5iVGlS6ubzBaRm6zxbygzc0brBB
# Jt3eWpdPM43UjXd9dUWhpVgmagNF3tlQtVCMr1a9TMXhRsUo063nQwBw3syYnhmJ
# A+rUkTfvTVLzyWAhxFZH7doRS4wyw4jmWOK22z75X7BC1o/jF5HRqsBV44a/rCcs
# QdCaM0qoNtS5cpZ+l3k4SF/Kwtw9Mt911jZnWon49qfH5U81PAC9vpwqbHkB3NpE
# 5jreODsHXjlY9HxzMVWggBHLFAx+rrz+pOt5Zapo1iLKO+uagjVXKBbLafIymrLS
# 2Dq4sUaGa7oX/cR3bBVsrquvczroSUa31X/MtjjA2Owc9bahuEMs305MfR5ocMB3
# CtQC4Fxguyj/OOVSWtasFyIjTvTs0xf7UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUb
# c7aZ+WssBkbvQR7w8F/g29mtkIBEr4AQQYowggauMIIElqADAgECAhAHNje3JFR8
# 2Ees/ShmKl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0z
# NzAzMjIyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1
# NiBUaW1lU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDGhjUGSbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI
# 82j6ffOciQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9
# xBd/qxkrPkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ
# 3HxqV3rwN3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5Emfv
# DqVjbOSmxR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDET
# qVcplicu9Yemj052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHe
# IhTZgirHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jo
# n7ZGs506o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ
# 9FHzNklNiyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/T
# Xkt2ElGTyYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJg
# o1gJASgADoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkw
# EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+e
# yG8wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQD
# AgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# dDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglg
# hkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGw
# GC4QTRPPMFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0
# MWfNthKWb8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1D
# X+1gtqpPkWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw
# 1YpxdmXazPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY
# +/umnXKvxMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0I
# SQ+UzTl63f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr
# 5Dhzq6YBT70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7y
# Rp11LB4nLCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDop
# hrCYoCvtlUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/
# AAvkdgIm2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMO
# Hds3OBqhK/bt1nz8MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkq
# hkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBB
# c3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5
# WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJv
# b3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1K
# PDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2r
# snnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C
# 8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBf
# sXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGY
# QJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8
# rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaY
# dj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+
# wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw
# ++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+N
# P8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7F
# wI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUw
# AwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAU
# Reuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEB
# BG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsG
# AQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAow
# CDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/
# Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLe
# JLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE
# 1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9Hda
# XFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbO
# byMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYID
# djCCA3ICAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYg
# VGltZVN0YW1waW5nIENBAhAFRK/zlJ0IOaa/2z9f5WEWMA0GCWCGSAFlAwQCAQUA
# oIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcN
# MjQwODA1MTUyNDUxWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBRm8CsywsLJD4Jd
# zqqKycZPGZzPQDAvBgkqhkiG9w0BCQQxIgQgXzN2VBGgRmzHrkbL6bgzJ7tIEpBA
# mkraaFvqsUXwJjIwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQg0vbkbe10IszR1EBX
# aEE2b4KK2lWarjMWr00amtQMeCgwDQYJKoZIhvcNAQEBBQAEggIAQ/spVIxCQ3fh
# WbvXJsZQT62aqf3JS4w3YpXCGguZzfvS55tIVlO3xQRRwrTicn8D1hQQIQXtHgsd
# Boe6JFqby/XWa424pE47RfqbZnVL/MgRHW7uoY8lEgNjYTRXv6kM1HoXsWiGpR10
# yvynNw5L5ZV0cVKuUnUyl/gZUR3o5FIH/GnR4AEN5QRf3vvagbG/eNF3BWGcY1MY
# SDRviecUHAtFa3ZLiXvHzGy9HRYHJBCnL5/YjqCQ4Y+YWWeyv27aI1h0uCv4mFLN
# 9BF2LRV0puB6ABoUu/0X79cW/HIKCakKs/DPKCt0llybIp63Mfv/dQ1U6wasgvY2
# v2zfTkxg8A2ht0D4PEyON1dC9ikI5Bf75GxANUgJ81K9wZVZKA4sGFw2R79JOcsN
# zkriVtxrpLi5p8Zw5rjRDw1XZJAq3kO4GOYjarTA1/d3aWYHrKH98z9rAqlXeoSG
# fEgRnnCij9uOZ8yH/1iNEvLdUKMnCDf4iujlouWPFVQOKX6PN4b3OFVG/LZFguL9
# ivSXfes46cnv+FVXVQ0NpxhOwHzWKQweEnvP9Yl+qv1W0autRU0om9Bc2jeVGRSg
# Wmmay+RwRRtp3lRiD6gKqMiQvxwlnYOWjF+nYY35wBjP4EjVLRJW7mWRwcXxud8T
# Nl9f4Cuh95Z59vAiSxXJnijL5bktf+U=
# SIG # End signature block
