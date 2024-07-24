<# CrowdStrike Preinstallation Environment Recovery ISO Builder
v1.2.0
#>
#Requires -RunAsAdministrator
Param(
    [switch]$SkipThirdPartyDriverDownloads,
    [switch]$IncludeDellDrivers,
    [switch]$IncludeHPDrivers,
    [switch]$IncludeSurfaceDrivers,
    [switch]$IncludeVMwareDrivers
)

# Constant Paths
$ADKInstallLocation = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10")
$ADKInstaller = [System.Environment]::ExpandEnvironmentVariables("%TEMP%\ADKSetup.exe")

$ADKWinPELocation = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\en-us\winpe.wim")
$ADKWinPEAddOnInstaller = [System.Environment]::ExpandEnvironmentVariables("%TEMP%\adkwinpesetup.exe")

$DandISetEnvPath = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat")
$CopyPEPath = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\copype.cmd")
$MakeWinPEMediaPath = [System.Environment]::ExpandEnvironmentVariables("%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\MakeWinPEMedia.cmd")

$DriversDir = "$PSScriptRoot\Drivers"
$ScriptsDir = "$PSScriptRoot\Scripts"

Write-Host "[+] Checking if drivers directory exists..."
if (Test-Path -Path "$DriversDir" -PathType Container) {
    Write-Host "[+] Drivers directory exists"
} else {
    Write-Host "[-] ERROR: The drivers does not exist, please review the documentation and re-run this tool." -ForegroundColor Red
    Exit
}

Write-Host "[+] Checking if scripts directory exists..."
if (Test-Path -Path "$ScriptsDir" -PathType Container) {
    Write-Host "[+] Scripts directory exists"
} else {
    Write-Host "[-] ERROR: The scripts does not exist, please review the documentation and re-run this tool." -ForegroundColor Red
    Exit
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

function Install-ADK-MS {
    Write-Host "[+] Checking if ADK is installed..."

    $ADKInstalled = Test-Path -Path "$ADKInstallLocation\Assessment and Deployment Kit\Deployment Tools\AMD64"
    if ($ADKInstalled)
    {
        Write-Host "[+] An installation of ADK was found on device. Skipping ADK installation." -ForegroundColor Yellow
    }
    else
    {
        Write-Host "[+] An installation of ADK was not found on the device. This tool will now download and install the Windows ADK."

        # Download the ADK Installer
        Write-Host "[+] Downloading ADK installer..."

        # Remove existing installation file
        if (Test-Path $ADKInstaller)
        {
            Remove-Item $ADKInstaller -Verbose
        }

        # Download
        Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2271337" -OutFile $ADKInstaller -ErrorAction Stop

        # Verify hash
        if ((Get-FileHash $ADKInstaller).Hash -ne "3DBB9BF40E9CF5FACD9D770BE8EBA8F9509E77FC20A6051C0D9BAA1173F98E4B")
        {
            Write-Host "[-] ERROR: Failed to verify ADK installer hash" -ForegroundColor Red
            Exit
        }
        Write-Host "[+] Please wait while the ADK is downloaded and installed. Please note that this may take a while." -ForegroundColor Blue
        Start-Process -FilePath "$ADKInstaller" -ArgumentList "/features", "OptionId.DeploymentTools", "/q", "/ceip", "off", "/installpath", """$ADKInstallLocation""", "/norestart" -Wait
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

        # Download the Windows ADK WinPE add-on installer
        Write-Host "[+] Downloading Windows ADK WinPE add-on installer..."

        # Remove existing installation file
        if (Test-Path $ADKWinPEAddOnInstaller)
        {
            Remove-Item $ADKWinPEAddOnInstaller -verbose
        }

        # Download
        Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2271338" -OutFile $ADKWinPEAddOnInstaller -ErrorAction Stop

        # Verify hash
        if ((Get-FileHash $ADKWinPEAddOnInstaller).Hash -ne "91AC010247B65244E5CD84C5F342D91B16501DBB08E422DE7DE06850CEF5680B")
        {
            Write-Host "[-] ERROR: Failed to verify ADK WinPE add-on hash" -ForegroundColor Red
            Exit
        }

        Write-Host "[+] Please wait while the Windows PE ADK addon is downloaded and installed. Please note that this may take a while." -ForegroundColor Blue
        Start-Process -FilePath "$ADKWinPEAddOnInstaller" -ArgumentList "/features", "OptionId.WindowsPreinstallationEnvironment", "/q", "/ceip", "off", "/installpath", """$ADKInstallLocation""", "/norestart" -Wait
        Write-Host "[+] Successfully installed the Windows ADK WinPE add-on." -ForegroundColor Green
    }
}

function Get-VMwareDrivers {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    Write-Host "[+] Downloading VMware Tools package..."
    $URL = "https://packages.vmware.com/tools/releases/latest/windows/VMware-tools-windows-12.4.5-23787635.iso"
    $OutputPath = "$WorkDir\VMware-tools-windows-12.4.5-23787635.iso"

    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $URL -OutFile "$OutputPath" -ErrorAction Stop
    $ProgressPreference = "Continue"

    Write-Host "[+] Verifying the integrity of the VMware Tools package"
    if ((Get-FileHash $OutputPath).Hash -ne "A16C79DFA7DEA79410D7E1B4221A52CF945138767A2EC0D4DCDAFA2594B7CAEC")
    {
        Write-Host "[-] ERROR: Failed to verify VMware Tools download hash" -ForegroundColor Red
        Exit
    }

    Write-Host "[+] Mounting VMware Tools ISO"
    $mount = Mount-DiskImage -ImagePath "$OutputPath" -StorageType ISO
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
    Write-Host "[+] Downloading HP Windows PE Client Driver Pack..."
    $URL = "https://ftp.ext.hp.com/pub/softpaq/sp151001-151500/sp151478.exe"
    $OutputPath = "$WorkDir\sp151478.exe"
    mkdir "$WorkDir\Drivers\HP"

    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $URL -OutFile "$OutputPath" -ErrorAction Stop
    $ProgressPreference = "Continue"

    Write-Host "[+] Verifying the integrity of the HP Client Driver Pack"
    if ((Get-FileHash "$OutputPath").Hash -ne "A1825CA0248B3121695D8EA78BFBF43046C4B842C4BF83D6AF6E3B6DFBDD89BE")
    {
        Write-Host "[-] ERROR: Failed to verify HP Windows PE Client Driver Pack hash" -ForegroundColor Red
        Exit
    }

    Write-Host "[+] Executing the HP Driver Pack driver package to extract the Windows PE drivers..."
    Start-Process "$OutputPath" -ArgumentList "/s", "/e", "/f", """$WorkDir\Drivers\HP""" -NoNewWindow -Wait

    Write-Host "[+] Curating HP drivers"
    Remove-Item -Path "$WorkDir\Drivers\HP\WinPE10_2.70\x64_winpe10\network" -Recurse -Confirm:$false

    Write-Host "[+] HP drivers successfully staged" -ForegroundColor Green
}

function Get-DellDrivers-WinPE10 {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    Write-Host "[+] Downloading Dell Windows PE Driver Pack (Win10+)..."
    $URL = "https://downloads.dell.com/FOLDER11211606M/1/WinPE10.0-Drivers-A33-CCKD7.cab"
    $OutputPath = "$WorkDir\WinPE10.0-Drivers-A33-CCKD7.cab"

    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $URL -OutFile "$OutputPath" -ErrorAction Stop
    $ProgressPreference = "Continue"

    Write-Host "[+] Verifying the integrity of the Dell Windows PE Driver Pack (Win10+)"
    if ((Get-FileHash "$OutputPath").Hash -ne "7D2A85674B0BBED95C2905A30F6C9B30E7F3723911E56351DAD33D82549F4EE3")
    {
        Write-Host "[-] ERROR: Failed to verify Dell Windows PE Driver Pack (Win10+) hash" -ForegroundColor Red
        Exit
    }

    $DellDir = "$WorkDir\Drivers\DellWinPE10"
    mkdir $DellDir
    Push-Location $DellDir

    Write-Host "[+] Extracting the Dell Windows PE Driver Pack (Win10+) cab file"
    Start-Process cmd.exe -ArgumentList "/c", "C:\Windows\System32\expand.exe", "-F:*", """$OutputPath""", "." -NoNewWindow -Wait
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
    Write-Host "[+] Downloading Dell Windows PE Driver Pack (Win11+)..."
    $URL = "https://downloads.dell.com/FOLDER11559429M/1/WinPE11.0-Drivers-A03-V81GV.cab"
    $OutputPath = "$WorkDir\WinPE11.0-Drivers-A03-V81GV.cab"

    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $URL -OutFile "$OutputPath" -ErrorAction Stop
    $ProgressPreference = "Continue"

    Write-Host "[+] Verifying the integrity of the Dell Windows PE Driver Pack (Win11+)"
    if ((Get-FileHash "$OutputPath").Hash -ne "23E3D5D921525246B6A0D55797392B7DFA08D293D4B16073B1E1B41F8FB4B3AF")
    {
        Write-Host "[-] ERROR: Failed to verify Dell Windows PE Driver Pack (Win11+) hash" -ForegroundColor Red
        Exit
    }

    $DellDir = "$WorkDir\Drivers\DellWinPE11"
    mkdir $DellDir
    Push-Location $DellDir

    Write-Host "[+] Extracting the Dell Windows PE Driver Pack (Win10+) cab file"
    Start-Process cmd.exe -ArgumentList "/c", "C:\Windows\System32\expand.exe", "-F:*", """$OutputPath""", "." -NoNewWindow -Wait
    Pop-Location

    Write-Host "[+] Curating Dell Win11+ drivers"
    Remove-Item -Path "$WorkDir\Drivers\DellWinPE11\winpe\x64\network" -Recurse

    Write-Host "[+] Dell Windows PE drivers (Win11+) successfully staged" -ForegroundColor Green
}

function Get-Packaged-Drivers {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    Write-Host "[+] Staging drivers packaged with this script"
    Copy-Item -Recurse -Path "$DriversDir" -Destination "$WorkDir\Drivers"
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
    $SurfacePackages = [ordered]@{
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
        SufacePro10 = @{
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
            URL = "https://download.microsoft.com/download/f/7/0/f70b3d0a-59b1-4842-9130-0c152bb738ba/SurfaceLaptop4_Intel_Win11_22621_24.052.21627.0.msi";
            DownloadHash = "9618E1954D8F62EB21C90BAC7F3452DB97A92D8504085B4505C79C9E6320AC61";
            FileName = "SurfaceLaptop4_Intel_Win11_22621_24.052.21627.0.msi";
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
    }

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

    Write-Host "[+] Downloading drivers for $($SurfacePackages.Count) Microsoft Surface devices..."
    Write-Host "[+] Please note that Surface driver packages are around 700MB each, so downloads might take a while" -ForegroundColor Blue
    mkdir $SurfaceDriversDir

    Foreach ($SurfacePackage in $SurfacePackages.values) {
        Write-Host "[+] Downloading driver package for $($SurfacePackage.Name)..."
        $DownloadPath = "$WorkDir\$($SurfacePackage.FileName)"
        Invoke-WebRequest -Uri $SurfacePackage.URL -OutFile "$DownloadPath"

        Write-Host "[+] Verifying the driver package for $($SurfacePackage.Name)"
        if ((Get-FileHash "$DownloadPath").Hash -ne $SurfacePackage.DownloadHash) {
            Write-Host "[-] ERROR: Failed to verify $($SurfacePackage.Name) driver package hash" -ForegroundColor Red
            Exit
        }

        Write-Host "[+] Extracting $($SurfacePackage.Name) driver package"

        # WinPE drivers will be placed in WorkDir\SurfaceTemp
        # The driver packages contain much more than is actually required here, so we extract first to a temporary
        # directory, copy over what we need for WinPE to WorkDir\Drivers\Surface, then clean up the rest.
        $ThisDriverDir = "$SurfaceDriversDir\$($SurfacePackage.FolderName)"
        mkdir $ThisDriverDir
        $ThisDriverTempDir = "$SurfaceTempDriversDir\$($SurfacePackage.FolderName)"
        mkdir $ThisDriverTempDir
        Start-Process msiexec.exe -ArgumentList "/a", """$DownloadPath""", "targetdir=""$ThisDriverTempDir""", "/qn" -NoNewWindow -Wait

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
        Remove-Item -Path "$DownloadPath" -Confirm:$false -Force
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
            Remove-Item -Path "$Dir\Drivers" -Force
        }
        Remove-Item -Path "$Dir" -Force
        Write-Host "[+] Cleaned up the old working directory $Dir"
    }

    mkdir "$Dir"
    mkdir "$Dir\Drivers"
}

function New-BootDisks {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
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

    Write-Host "[+] Installing Drivers"
    Start-Process dism -ArgumentList "/Image:""$WinPEMountLocation""", "/Add-Driver", "/Recurse", "/Driver:""$WorkDir\Drivers""" -NoNewWindow -Wait

    Write-Host "[+] Installing CrowdStrike Recovery iso"
    Copy-Item -Force -Path "$ScriptsDir\CSPERecovery_startnet.cmd" -Destination "$WinPEMountLocation\Windows\System32\startnet.cmd"
    Copy-Item -Force -Path "$ScriptsDir\CSPERecovery.ps1" -Destination "$WinPEMountLocation\Windows\System32\CSPERecovery.ps1"

    if ($BitlockerCSV) {
        Write-Host "[+] Adding BitLockerKeys.csv to recovery iso"
        Copy-Item -Force -Path "$PSScriptRoot\BitLockerKeys.csv" -Destination "$WinPEMountLocation\BitLockerKeys.csv"
    }

    Write-Host "[+] Dismounting and committing Windows PE Image"
    Dismount-WindowsImage -Path "$WinPEMountLocation" -Save

    Write-Host "[+] CS WinPE Recovery boot.wim built" -ForegroundColor Green

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
    Copy-Item -Force -Path "$ScriptsDir\SafeBoot_startnet.cmd" -Destination "$WinPEMountLocation\Windows\System32\startnet.cmd"
    
    if ($BitlockerCSV) {Remove-Item -Force -Path "$WinPEMountLocation\BitLockerKeys.csv"}

    Write-Host "[+] Installing Safe Boot recovery batch script"
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


Write-Host "CrowdStrike WinPE Recovery and Safe Boot ISO Generation Tool"
Write-Host "Execution of this tool constitutes acceptance of the licence agreements for the following components:"
Write-Host "- Microsoft Assessment and Deployment Toolkit (ADK)"
Write-Host "- Microsoft ADK Windows Preinstallation Environment Addon"
Write-Host "- Any device drivers you include in the final bootable image"
Write-Host "If you do not accept any of these terms, cancel execution of this script immediately. Execution will continue automatically in ten seconds." -ForegroundColor Yellow

Write-Host "[+] Checking for BitLockerKeys.csv..."
$BitlockerCSV = Get-CSVFile -FilePath "$PSScriptRoot\BitLockerKeys.csv"

if ($true -eq $SkipThirdPartyDriverDownloads) {
    Write-Host "[+] NOTE: Skipping download of third party drivers from Dell, HP, and VMware" -ForegroundColor Yellow
}
Write-Host "[+] Including: All drivers in the Drivers directory next to this script" -ForegroundColor Green

$DriverPacks = [ordered]@{
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
if ($IncludeDellDrivers -or $IncludeHPDrivers -or $IncludeSurfaceDrivers -or $IncludeVMwareDrivers) {
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

Start-Sleep -Seconds 10

Write-Host "[+] Downloading and Staging Drivers"

# Setting up the work directory
$LocalWorkDir = Get-Location
$LocalWorkDir = "$LocalWorkDir\WorkDir"
New-Directory -Dir $LocalWorkDir

# Install the Windows ADK
Install-ADK-MS

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

Get-Packaged-Drivers -WorkDir $LocalWorkDir

Write-Host "[+] Building Boot Disks"
New-BootDisks -WorkDir $LocalWorkDir

Write-Host "[+] Complete!" -ForegroundColor Green
Write-Host "CrowdStrike WinPE Recovery ISO: $CSPERecoveryISO"
Write-Host "CrowdStrike Safe Boot ISO: $CSSafeBootISO"

# SIG # Begin signature block
# MIIpMQYJKoZIhvcNAQcCoIIpIjCCKR4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAtcSLDBKnVXx7v
# n94uyTQBucJpNO9hM2xqB2NBni7G+KCCDh4wggawMIIEmKADAgECAhAOTWf2QxbJ
# Kjt6F8xGl2qPMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA3MjgwMDAwMDBaFw0z
# NjA3MjcyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQCuLgx90+9o44QI+psMTfM2D+ex8zQyg0ZUYl/qiBWxymjHTRxk86IB
# dnAYvI+b8eZLGY0IPEpSoVYTUshVPMJhw22SoK/4w0JmgfEhjWYRF2xT6xhh8AMM
# MemLXSinRuvRKuusS5/r665dHGGlnvGCim1P9aEMbe+peNpsk+woINwSycSW63o2
# bxccdX4JydmlvCV7g4JyeuAt6sEQe76IgSOAK2zTWf7VvVpuasVfMndoL+Jc//oc
# ipizux0BRTwLtZwt+VebfHN5zrKW2rIoTLFy+B0ExNqmqbDumQWubyXnolily0Uc
# m13IWyugvqWiMLzJLePnPTn5KBoCNIwjxB9qXlYDLYmKL8S+c9l/VrOBS/NiR8qB
# gTLmQDlz7eP1m4qJ9vsQ+nim+RcdknorMmFpu5GBeqM5s71i1GTkudmC/AcnvhP+
# 8VNg7juHbA6q/8lpl3wrn8gCJKin8lOOUcGy2Ql+cBvqIfVRQoqAyGk0KlKQz2zb
# HNBCZnjhEYhEOz4AebmURHhnY6iFD6cw/+BSO+ei5nZdm4j7KfYQFu1EOQGv1hGu
# 7bxumwo0IAuAWY3OjFHuuzoVpAHMSyAOPzS7oXThiUUhDCn1TyJZOWNZYxf6nw4n
# tDUtcA9CX9pJmaV/5YtdByvzHSpT6/teLVNVIFmm9ExrSz3jUYTRaQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUvGsiZZ2MaObmHgXx
# 2HIl1LjgSMAwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQsFAAOCAgEASfK8p3nzB1leZwD5fvPqhgNt
# Ue8hR9nTqPtx4fy5UG1ggNkeTmhUcbNW6LjDHcP3t91YKqwUv4Hn1n2NlxM92siW
# ay0iIuTKy1U6uTINGw6iIj/o7+e6/E5L6JKj70wsyJT+tQH1ivMsv5RLAV4iK3Av
# gJGF1/5m5qv81izLWpTxwdXTikYh2J7aY8p8trlOpGEDUESVtg9xqQChYrH/87UH
# TgFiJUBtT10Svaf6ki0Hb9DONoib201tyvJ5dbyySONUynwA/q3/L3HRdyFnmlVt
# MAF/+pVPd9/GzLODIvsfJaAL99VHutuBWhf0HD8aYfD/GJ1tl1hYFx5OEenWZHYw
# m1sDrCveX1z4WC44wXnW/1BXjn+eEYJAktyc6B0zbBvPXdju51GgXWlsF8N0GrKj
# Wb1m2Xw0PJScanz66M9S756AiA/LdnyFII9sspA1IyyBFJ1ytf4p3447NkqkO8fY
# QnDM1GqLMksv6W47gAp/w0oiVNccVsYZpeGY1cHo9JQvZehuTAeYD1ktXoBDkbdL
# WAExicsFtuMSa4xjNalP/hZbJ1e8ZkaQKDAyocpUeQ6nhHHLfXDwkkFXKnY1O92v
# klc2WtvVTR0lTUh7Rs2RfG/Dm9W+/SOGBIt3Zwymh2bp0yU1TlNa3ZC0utQq1829
# wsp4XrAbZrKKLoI6xegwggdmMIIFTqADAgECAhANSP/Z4mauPlHcXAYTU4vzMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyMSBDQTEwHhcNMjMxMjE4MDAwMDAwWhcNMjYxMjE5
# MjM1OTU5WjBuMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAG
# A1UEBxMJU3Vubnl2YWxlMRowGAYDVQQKExFDcm93ZFN0cmlrZSwgSW5jLjEaMBgG
# A1UEAxMRQ3Jvd2RTdHJpa2UsIEluYy4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQCjWRQhxJ3tfVMVHGldhEzO1eO8XKNxtHanRYrMfoZGRKNtNerivsWL
# R6kkPKxWjM5yfJPEFlwoYQJ52ngi1402/rMaEZy+6jhzeE4zSc0zWnRWrXyFDWg/
# 1jNX3MMkrtKjq0F0PVN/1hdfChYjuZyEaXwKIoaUH33GtyLgx8oAX8/5cBXrv9Dr
# Z5n1vjJi3IdicAWhqThKF990x+KuYiLdJFlMrFaHBuUoOkH66LLuqu05oIABcDjw
# vwv5k6erIzfO8JfHougaQlW/l51jYIG9nCcbYGDt13JRU5qSW1URJzgVatIU46Xu
# xNGdV1I3/yq99o1MR9IgRmF3DyhIJNUBMjfr4OHvF8VwXsBJvQgy4zYeF7UtvNGU
# mWxz55dTnSRJwBKDdU/BU0XGRuT2mxIqk3saynt2yD3LE6+MPUICnxfyljqMheiq
# cgI2gzP1kDqfYO/WxlIBhF+FFy8iMt2ot2PmNtlC2exYb0YerXdZyANXmF27iuza
# MFNII+4PmESLzcDh4M4qjV6PG5tz/Ga/XWaBo5H6i0nByTHjCsyw+GihIR8np/ZV
# IiQAFp5zqDxDUTNUdl8jRXjAf5kRbByyMBRRCS3zrWHvFnaiHI6LKOpoJbH2oOEs
# TwCuMO/mK1F05YHaba4TwDf67TWkVZNkMbxjAiWbNQcjRauMi0HBxwIDAQABo4IC
# AzCCAf8wHwYDVR0jBBgwFoAUvGsiZZ2MaObmHgXx2HIl1LjgSMAwHQYDVR0OBBYE
# FAVzMxoRwTxtGJQjZY9y2dvzL5rkMD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYI
# KwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZN
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNp
# Z25pbmdSU0E0MDk2U0hBMjU2MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5
# NlNIQTI1NjIwMjFDQTEuY3JsMIGUBggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmlu
# Z1JTQTQwOTZTSEEyNTYyMDIxQ0ExLmNydDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEB
# CwUAA4ICAQCYJpIKCcY6sOCBq+xmlDiy6cgtOk1E6Cy7DBfOXkfYrKiZDx5w1I+n
# ymQFBjfsWMnS5qTmdYGhqvVB9LSaIwomVOujNcV41y0HJOVP5w7t4eKzQGTsV+is
# kMi3HxQxfRAZAxel41ReNOKpFHyPpTkF2lvoe2fgY8YLWpxcZQx/P/+xaU4aek5H
# K+lNueuQ8l8ZNyOGZ3c9FcctpYy0IAaqsMnY9mt5ZJAoBWXkKw4JBaL6mWso77KP
# zDC4O/ugRrBli+HxogM6vtVgX4ZbGG7f9zfJOntCPVTqNlU1gxv/2caWNgVNwrp4
# 9ndmHVQQGiibgzktTiwtBq4AUQQUGQSBEssDu4CJZX9tKwna30Q0CgIwcF2h3pMp
# rUkKWTMKFp1WdhYIRWh2i88MtPd3yAyzAf6hwb/nrMbDimUyqQmpDObXZPsU/oWZ
# AzW28FUbqKnJnayD/3G+Ota4j6vATEXIzn1/RZH/1vhYW2B433uF4IxCu9x2VrIr
# kb/j3wIKtk4rDUohQrCVaR6BlEWeiZoBh0W6d1hU8EQzMxjHaqowOXRzcrDh3w15
# /amuIr0ivGmkhy4Nh0M3AZ1EzJNwBMVHsGhgpjJHF3HYoPHOmEIMFLY5/PdDXNQD
# 0NUVSKl/LEcxK2bkhreQwCxXKaDLYxjnLaTcco3jYJER7yfpfPlPVjGCGmkwghpl
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2
# IFNIQTI1NiAyMDIxIENBMQIQDUj/2eJmrj5R3FwGE1OL8zANBglghkgBZQMEAgEF
# AKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDl
# g9XNQ5baYM1kfjd5ArUCm1OShezOMDy+hdHfj5mTaDANBgkqhkiG9w0BAQEFAASC
# AgAmvtlUz/tyaxsfEyFrib5bUI/yCoZscic/l+rc6lC0etKBlSghuvtNZQT8snT+
# Q+BTXyUOo2Op7UhMhNsaojtYZ5IMMBEgiTCLOycmkDyL0cY/uWwRn4nuqwjABASK
# rhewWakOkbRARhL0FjfVQVKor9ViQqYAGu09f1wUxMFw6zQb0/miVC4iOI1dNheS
# X1llzQw1aET33SL3Zz5HuNnj17ToS6SSV58ade7OOiyO3h6U8KDJr5yovzNLWwZg
# YfkuTEaoMPAZxe9IymGtUyvULicO0V/2QyTDNakcdrshGRv/TesylDaRFGeHVHv8
# 8a4OUPtWeqOhq2KbV9NTrdv8awN/xma3hNDjCwzA4riLvGJf98zMFg9RY2l0oDqU
# UL7gmM2XqmreLdK4Ed3lXzgFnb8yUFGaEFd2sgwXYnyZ8PTRgMkb4LAdngBiZRD3
# tr/3Bxaxw4u0rPPqIMZUy7rFQKchhHwYfkXl5Ie6yAAU/UDPp9pxp0XdCsetWofF
# qDZPDqj2PRK5ScXlbVoBaz5RsU18ebdADK6e4Zo9tzX2pswqQ+XNQDp6fISF4GqO
# /P5EFru1aEJ+b83PR9aRYudn+vtAxfZvmEu6+vL7HceONAABq5OeAiJ9eKg+NAAZ
# A4RH6uBVZfDms5WVBR0wYDpRcUYz4C6EaRudB8DqLBN6CaGCFz8wghc7BgorBgEE
# AYI3AwMBMYIXKzCCFycGCSqGSIb3DQEHAqCCFxgwghcUAgEDMQ8wDQYJYIZIAWUD
# BAIBBQAwdwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCG
# SAFlAwQCAQUABCCpNPljfvuQLASY8n1FLjwKFc0Ds+ACBk8yE/GJEf9QMQIQOh6f
# eNXPgFQVtEbKXt/nXhgPMjAyNDA3MjQwMzE5NTJaoIITCTCCBsIwggSqoAMCAQIC
# EAVEr/OUnQg5pr/bP1/lYRYwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3MTQw
# MDAwMDBaFw0zNDEwMTMyMzU5NTlaMEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjMw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f
# 1+XS512hDgncL0ijl3o7Kpxn3GIVWMGpkxGnzaqyat0QKYoeYmNp01icNXG/Opfr
# lFCPHCDqx5o7L5Zm42nnaf5bw9YrIBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkklKSC
# Gtpqutg7yl3eGRiF+0XqDWFsnf5xXsQGmjzwxS55DxtmUuPI1j5f2kPThPXQx/ZI
# LV5FdZZ1/t0QoRuDwbjmUpW1R9d4KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobu
# tKQhZHDr1eWg2mOzLukF7qr2JPUdvJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9
# e3M+Mu5SNPvUu+vUoCw0m+PebmQZBzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/g
# WEH72LEs4VGvtK0VBhTqYggT02kefGRNnQ/fztFejKqrUBXJs8q818Q7aESjpTtC
# /XN97t0K/3k0EH6mXApYTAA+hWl1x4Nk1nXNjxJ2VqUk+tfEayG66B80mC866msB
# sPf7Kobse1I4qZgJoXGybHGvPrhvltXhEBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9
# nJKTBLRpcCcNT7e1NtHJXwikcKPsCvERLmTgyyIryvEoEyFJUX4GZtM7vvrrkTjY
# UQfKlLfiUKHzOtOKg8tAewIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WM
# aiCPnshvMB0GA1UdDgQWBBSltu8T5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBR
# ME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSB
# gzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsG
# AQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCBGtbeoKm1mBe8cI1PijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co2efj
# xe0mgopxLxjdTrbebNfhYJwr7e09SI64a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLa
# wkA4n13IoC4leCWdKgV6hCmYtld5j9smViuw86e9NwzYmHZPVrlSwradOKmB521B
# XIxp0bkrxMZ7z5z6eOKTGnaiaXXTUOREEr4gDZ6pRND45Ul3CFohxbTPmJUaVLq5
# vMFpGbrPFvKDNzRusEEm3d5al08zjdSNd311RaGlWCZqA0Xe2VC1UIyvVr1MxeFG
# xSjTredDAHDezJieGYkD6tSRN+9NUvPJYCHEVkft2hFLjDLDiOZY4rbbPvlfsELW
# j+MXkdGqwFXjhr+sJyxB0JozSqg21Llyln6XeThIX8rC3D0y33XWNmdaifj2p8fl
# TzU8AL2+nCpseQHc2kTmOt44OwdeOVj0fHMxVaCAEcsUDH6uvP6k63llqmjWIso7
# 65qCNVcoFstp8jKastLYOrixRoZruhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1
# tqG4QyzfTkx9HmhwwHcK1ALgXGC7KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RB
# ybhG02wyfFgvZ0dl5Rtztpn5aywGRu9BHvDwX+Db2a2QgESvgBBBijCCBq4wggSW
# oAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIy
# MDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0
# IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2g
# sMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHx
# c7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT
# 2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjch
# u0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7X
# j3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQ
# mDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87f
# SqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq
# +nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjCl
# TNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72
# wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2x
# AgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6Ftlt
# TYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUH
# AQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYI
# KwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2
# b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5g
# yNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7
# cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1
# T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZ
# gaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFy
# nOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN
# 3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9
# HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAW
# Tyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC
# 3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA
# 8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQxggN2MIIDcgIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBS
# U0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYw
# DQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwG
# CSqGSIb3DQEJBTEPFw0yNDA3MjQwMzE5NTJaMCsGCyqGSIb3DQEJEAIMMRwwGjAY
# MBYEFGbwKzLCwskPgl3OqorJxk8ZnM9AMC8GCSqGSIb3DQEJBDEiBCA9Tps/ZYaW
# c2WdN0vUEUHazgRQ1oRS3tBcFlYoGuTWZDA3BgsqhkiG9w0BCRACLzEoMCYwJDAi
# BCDS9uRt7XQizNHUQFdoQTZvgoraVZquMxavTRqa1Ax4KDANBgkqhkiG9w0BAQEF
# AASCAgCifGlqh9IIMJFnWd+r4W/QI8NOpqEP7IshXmrgnpLgdMUeLNUx02MC8Xkk
# KQ58AtzVE/OJ1lIa0AI78aEDLiwsreu/kTvmbGygnfxU/lxDP9zL5h6TlG2CWgax
# z88wM7lcgtUOGXQqqcoBXmR6fagVU3618uGvudTRguQv6SjZw2N2hKa2bFcljLtU
# k/nL7lKan2E9fcwMW7Jhah2jRPcUMM5Ox8WX3PnMDL6TlkbgYbDDPCpy43wRmSAS
# JXd4JKHSHm57F5uHJK8LKwEi6w/iElMPKX5KaMYPSwAOhugdPSAKVM4q0TeFT1m0
# 8A5eOHvD5BQ/oQE3YY2jNI/mV2tGr0eAo8cRHV57/61VHO4aSXiL5gdS3CPsFNPf
# ZgbqCmmq4xmKVUmXyXrmo+DXro6WIIL4itblz5Ncmut7mU37hnzw4k2TB8eVkb5T
# DeXCgQwwm2+Bj0BGhZ565QcXt33sBGDf2d4XYpmjC4SHLkB8CQmuYXkL5AAg0KNp
# 9sXMAIt6z3FPm7uBWbjhhnA6PPNYaXx0OhBynV0zzxp5l6Tx+xHhSSzbP47YlAGn
# BcmKzXQMSIzsPghVserQvAhO0Yo72Bt2D7BsEyBwftUyiBhbGtbr/pxNkc4nc6f2
# jKIGxYhGHEiCoqY5mXPMMPEUy9zCVzdv6x/Re7MOU0QCPYie1g==
# SIG # End signature block
