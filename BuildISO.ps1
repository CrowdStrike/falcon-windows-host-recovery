<# CrowdStrike Preinstallation Environment Recovery ISO Builder
v1.1.0
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

$CSPERecoveryISO = "CSPERecovery_x64.iso"
$CSSafeBootISO = "CSSafeBoot_x64.iso"

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
        Start-Process -FilePath $ADKInstaller -ArgumentList "/features", "OptionId.DeploymentTools", "/q", "/ceip", "off", "/installpath", """$ADKInstallLocation""", "/norestart" -Wait
        Write-Host "[+] Successfully installed Windows ADK." -ForegroundColor Green
    }

    #
    # Check if the ADK WinPE Addon is installed
    #
    Write-Host "[+] Checking if ADK WinPE addon is installed..."
    $ADKWinPEInstalled = Test-Path -Path $ADKWinPELocation
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
        Start-Process -FilePath $ADKWinPEAddOnInstaller -ArgumentList "/features", "OptionId.WindowsPreinstallationEnvironment", "/q", "/ceip", "off", "/installpath", """$ADKInstallLocation""", "/norestart" -Wait
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
    Invoke-WebRequest -Uri $URL -OutFile $OutputPath -ErrorAction Stop
    $ProgressPreference = "Continue"

    Write-Host "[+] Verifying the integrity of the VMware Tools package"
    if ((Get-FileHash $OutputPath).Hash -ne "A16C79DFA7DEA79410D7E1B4221A52CF945138767A2EC0D4DCDAFA2594B7CAEC")
    {
        Write-Host "[-] ERROR: Failed to verify VMware Tools download hash" -ForegroundColor Red
        Exit
    }

    Write-Host "[+] Mounting VMware Tools ISO"
    $mount = Mount-DiskImage -ImagePath $OutputPath -StorageType ISO
    $vol = Get-Volume | Where-Object {$_.FileSystemLabel -eq "VMware Tools"}
    $vol = $vol[0]

    Write-Host "[+] Copying the VMware PVSCSI driver into the working directory"
    $VMwareDriveLetter = $vol.DriveLetter
    $PVSCSIDir = "$WorkDir\Drivers\VMwarePVSCSI"
    mkdir $PVSCSIDir
    Copy-Item -Path "$VMwareDriveLetter`:\Program Files\VMware\VMware Tools\Drivers\pvscsi\Win10\amd64\*" -Destination $PVSCSIDir -Recurse

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
    Invoke-WebRequest -Uri $URL -OutFile $OutputPath -ErrorAction Stop
    $ProgressPreference = "Continue"

    Write-Host "[+] Verifying the integrity of the HP Client Driver Pack"
    if ((Get-FileHash $OutputPath).Hash -ne "A1825CA0248B3121695D8EA78BFBF43046C4B842C4BF83D6AF6E3B6DFBDD89BE")
    {
        Write-Host "[-] ERROR: Failed to verify HP Windows PE Client Driver Pack hash" -ForegroundColor Red
        Exit
    }

    Write-Host "[+] Executing the HP Driver Pack driver package to extract the Windows PE drivers..."
    Start-Process $OutputPath -ArgumentList "/s", "/e", "/f", """$WorkDir\Drivers\HP""" -NoNewWindow -Wait

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
    Invoke-WebRequest -Uri $URL -OutFile $OutputPath -ErrorAction Stop
    $ProgressPreference = "Continue"

    Write-Host "[+] Verifying the integrity of the Dell Windows PE Driver Pack (Win10+)"
    if ((Get-FileHash $OutputPath).Hash -ne "7D2A85674B0BBED95C2905A30F6C9B30E7F3723911E56351DAD33D82549F4EE3")
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
    Invoke-WebRequest -Uri $URL -OutFile $OutputPath -ErrorAction Stop
    $ProgressPreference = "Continue"

    Write-Host "[+] Verifying the integrity of the Dell Windows PE Driver Pack (Win11+)"
    if ((Get-FileHash $OutputPath).Hash -ne "23E3D5D921525246B6A0D55797392B7DFA08D293D4B16073B1E1B41F8FB4B3AF")
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
    Copy-Item -Recurse -Path $DriversDir -Destination "$WorkDir\Drivers"
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
        Invoke-WebRequest -Uri $SurfacePackage.URL -OutFile $DownloadPath

        Write-Host "[+] Verifying the driver package for $($SurfacePackage.Name)"
        if ((Get-FileHash $DownloadPath).Hash -ne $SurfacePackage.DownloadHash) {
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
            if (Test-Path -Path $SourceDriverFolder) {
                Write-Host "[+] Gathering $SurfaceDriverType driver for $($SurfacePackage.Name)"
                Move-Item -Path $SourceDriverFolder -Destination $ThisDriverDir
            }
        }

        Write-Host "[+] Cleaning up $($SurfacePackage.Name) driver package"
        Remove-Item -Path $ThisDriverTempDir -Recurse -Confirm:$false -Force
        Remove-Item -Path $DownloadPath -Confirm:$false -Force
    }

    Write-Host "[+] Surface drivers successfully staged" -ForegroundColor Green
    $ProgressPreference = "Continue"
}

function Make-WorkDir {
    Param(
        [Parameter(Mandatory = $true)]
        $WorkDir
    )
    mkdir $WorkDir
    mkdir $WorkDir\Drivers
}

function Make-BootDisks {
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
    Start-Process -FilePath $CopyPEPath -ArgumentList "amd64", """$WinPEPath""" -NoNewWindow -Wait

    Write-Host "[+] Adding libvirt licence"
    Copy-Item -Path "$DriversDir\libvirt\readme-license.rtf" -Destination "$WinPEPath\media\readme-license.rtf"

    $WinPEMountLocation = "$WinPEPath\mount"

    Write-Host "[+] Mounting Windows PE Image"
    Mount-WindowsImage -ImagePath "$WinPEPath\media\sources\boot.wim" -Path $WinPEMountLocation -Index 1

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

    Write-Host "[+] Installing CrowdStrike Recovery Scripts"
    Copy-Item -Force -Path "$ScriptsDir\CSPERecovery_startnet.cmd" -Destination "$WinPEMountLocation\Windows\System32\startnet.cmd"
    Copy-Item -Force -Path "$ScriptsDir\CSPERecovery.ps1" -Destination "$WinPEMountLocation\Windows\System32\CSPERecovery.ps1"

    Write-Host "[+] Dismounting and committing Windows PE Image"
    Dismount-WindowsImage -Path $WinPEMountLocation -Save

    Write-Host "[+] CS WinPE Recovery boot.wim built" -ForegroundColor Green

    Write-Host "[+] Creating CS WinPE Recovery bootable ISO"
    Start-Process $MakeWinPEMediaPath -ArgumentList "/ISO", """$WinPEPath""", $CSPERecoveryISO -NoNewWindow -Wait
    Write-Host "[+] CS WinPE Recovery ISO build completed successfully" -ForegroundColor Green

    Write-Host "[+] Building Safe Mode Boot ISO"
    Write-Host "[+] Mounting Windows PE Image"
    Mount-WindowsImage -ImagePath "$WinPEPath\media\sources\boot.wim" -Path $WinPEMountLocation -Index 1

    Write-Host "[+] Installing Safe Mode Script"
    Remove-Item -Force -Path "$WinPEMountLocation\Windows\System32\CSPERecovery.ps1"
    Copy-Item -Force -Path "$ScriptsDir\SafeBoot_startnet.cmd" -Destination "$WinPEMountLocation\Windows\System32\startnet.cmd"

    Write-Host "[+] Installing Safe Boot recovery batch script"
    Copy-Item -Force -Path "$ScriptsDir\SafeBoot_CSRecovery.cmd" -Destination "$WinPEPath\media\CSRecovery.cmd"

    Write-Host "[+] Dismounting and committing Windows PE Image"
    Dismount-WindowsImage -Path $WinPEMountLocation -Save

    Write-Host "[+] Windows PE Safe Boot boot.wim built" -ForegroundColor Green
    Write-Host "[+] Creating bootable ISO"
    Start-Process $MakeWinPEMediaPath -ArgumentList "/ISO", """$WinPEPath""", $CSSafeBootISO -NoNewWindow -Wait
    Write-Host "[+] Safe Boot ISO built" -ForegroundColor Green
}


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
Make-WorkDir -WorkDir $LocalWorkDir

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
Make-BootDisks -WorkDir $LocalWorkDir

Write-Host "[+] Complete!" -ForegroundColor Green
Write-Host "CrowdStrike WinPE Recovery ISO: $CSPERecoveryISO"
Write-Host "CrowdStrike Safe Boot ISO: $CSSafeBootISO"

# SIG # Begin signature block
# MIIpMgYJKoZIhvcNAQcCoIIpIzCCKR8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAcsUpsWNKvOphF
# ihWJsadQZHW5uKLRJgAhpISv1Yc136CCDh4wggawMIIEmKADAgECAhAOTWf2QxbJ
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
# 0NUVSKl/LEcxK2bkhreQwCxXKaDLYxjnLaTcco3jYJER7yfpfPlPVjGCGmowghpm
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2
# IFNIQTI1NiAyMDIxIENBMQIQDUj/2eJmrj5R3FwGE1OL8zANBglghkgBZQMEAgEF
# AKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDs
# J2iW9U78SeRp57yc9r8Eb1RVmPc/6FHgqaM5UBEGWzANBgkqhkiG9w0BAQEFAASC
# AgCeKtzOL1MkNbrTh/9TOm9E59/U1VurM6Qmm4x0D4E6s7DPaaOutWFjhqxeh0tb
# WznH6UGm2wp/K++Y44v7X33vHlusPh5BETDIJM6bfXgD8l2cfzMNfESyQYEPp05k
# 2KKJuhJ7A22cYDb7FtapQcwKjg9wE6F4+xGZzT23E4eTMggR3ZKkez2XEl3xFdQp
# KzxY/QCmEJwllJY4fALINCDULdZ7Un3nf9hPjhfGy//+W8dLS9m/ltjeIQZnca9x
# j9zHRHknXlYlH/tcwtdbz5askt9A6TwGognnbeNYUGDM09t7NXeJx9U9SPM+rD7h
# i26ZM0SHILG0ZTQa4ccz3h/EzCPsp9Jy8f6VARvdp9G5drYh4Ev0mQoMvHUnx1z2
# rG6sI4r6M7z0JT7EoYnSdibeejzKbputq7ButXrT66NgFK8M5ACRKPmIKLAbmTIK
# yG1GLJGg5yI0pyW7yJ0N8qRHD0ioKc+QbHME+yxUphleEqgOSer1mBExT3+Ydijq
# OV5OSFrBiP3aZFghKMl8GJ0Y0yVMzu3OTQpRxFC1fLy0r10xWtOggDmNwLQFx2st
# 5BiKEU+/CjsKWgvIBt5K3n6f67yM6Zq1KvON2m84V9/No3kUHruw4hDSGfnht6IM
# HCYVZT+xOGxb0pEYyibtYAMOi2ciJxYVDZJC6vX/ut7yS6GCF0Awghc8BgorBgEE
# AYI3AwMBMYIXLDCCFygGCSqGSIb3DQEHAqCCFxkwghcVAgEDMQ8wDQYJYIZIAWUD
# BAIBBQAweAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCG
# SAFlAwQCAQUABCDLf3Jeo056d87xPAIelxxcVRj3DIg0I4w7xFlIsOTXIAIRAKqk
# xdSml+srwCmFKUrgXgQYDzIwMjQwNzIzMDQxMDQwWqCCEwkwggbCMIIEqqADAgEC
# AhAFRK/zlJ0IOaa/2z9f5WEWMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjMwNzE0
# MDAwMDAwWhcNMzQxMDEzMjM1OTU5WjBIMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xIDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIz
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAo1NFhx2DjlusPlSzI+DP
# n9fl0uddoQ4J3C9Io5d6OyqcZ9xiFVjBqZMRp82qsmrdECmKHmJjadNYnDVxvzqX
# 65RQjxwg6seaOy+WZuNp52n+W8PWKyAcwZeUtKVQgfLPywemMGjKg0La/H8JJJSk
# ghraarrYO8pd3hkYhftF6g1hbJ3+cV7EBpo88MUueQ8bZlLjyNY+X9pD04T10Mf2
# SC1eRXWWdf7dEKEbg8G45lKVtUfXeCk5a+B4WZfjRCtK1ZXO7wgX6oJkTf8j48qG
# 7rSkIWRw69XloNpjsy7pBe6q9iT1HbybHLK3X9/w7nZ9MZllR1WdSiQvrCuXvp/k
# /XtzPjLuUjT71Lvr1KAsNJvj3m5kGQc3AZEPHLVRzapMZoOIaGK7vEEbeBlt5NkP
# 4FhB+9ixLOFRr7StFQYU6mIIE9NpHnxkTZ0P387RXoyqq1AVybPKvNfEO2hEo6U7
# Qv1zfe7dCv95NBB+plwKWEwAPoVpdceDZNZ1zY8SdlalJPrXxGshuugfNJgvOupr
# AbD3+yqG7HtSOKmYCaFxsmxxrz64b5bV4RAT/mFHCoz+8LbH1cfebCTwv0KCyqBx
# PZySkwS0aXAnDU+3tTbRyV8IpHCj7ArxES5k4MsiK8rxKBMhSVF+BmbTO77665E4
# 2FEHypS34lCh8zrTioPLQHsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91
# jGogj57IbzAdBgNVHQ4EFgQUpbbvE+fvzdBkodVWqWUxo97V40kwWgYDVR0fBFMw
# UTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEE
# gYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggr
# BgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAgRrW3qCptZgXvHCNT4o8aJzYJf/LLOTN6l0ikuyMIgKpuM+AqNnn
# 48XtJoKKcS8Y3U623mzX4WCcK+3tPUiOuGu6fF29wmE3aEl3o+uQqhLXJ4Xzjh6S
# 2sJAOJ9dyKAuJXglnSoFeoQpmLZXeY/bJlYrsPOnvTcM2Jh2T1a5UsK2nTipgedt
# QVyMadG5K8TGe8+c+njikxp2oml101DkRBK+IA2eqUTQ+OVJdwhaIcW0z5iVGlS6
# ubzBaRm6zxbygzc0brBBJt3eWpdPM43UjXd9dUWhpVgmagNF3tlQtVCMr1a9TMXh
# RsUo063nQwBw3syYnhmJA+rUkTfvTVLzyWAhxFZH7doRS4wyw4jmWOK22z75X7BC
# 1o/jF5HRqsBV44a/rCcsQdCaM0qoNtS5cpZ+l3k4SF/Kwtw9Mt911jZnWon49qfH
# 5U81PAC9vpwqbHkB3NpE5jreODsHXjlY9HxzMVWggBHLFAx+rrz+pOt5Zapo1iLK
# O+uagjVXKBbLafIymrLS2Dq4sUaGa7oX/cR3bBVsrquvczroSUa31X/MtjjA2Owc
# 9bahuEMs305MfR5ocMB3CtQC4Fxguyj/OOVSWtasFyIjTvTs0xf7UGv/B3cfcZdE
# Qcm4RtNsMnxYL2dHZeUbc7aZ+WssBkbvQR7w8F/g29mtkIBEr4AQQYowggauMIIE
# lqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0y
# MjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBH
# NCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJt
# oLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR
# 8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp
# 09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43
# IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+
# 149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUmcJgmf6AaRyBD40NjgHt1bicl
# kJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO
# 30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+Drhk
# Kvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIw
# pUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+
# 9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TN
# sQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZ
# bU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCT
# tm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+
# YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3
# +3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8
# dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5
# mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHx
# cpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMk
# zdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j
# /R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8g
# Fk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6
# gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6
# wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIFjTCCBHWgAwIBAgIQDpsYjvnQ
# Lefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYD
# VQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAw
# WhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdp
# Q2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QN
# xDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DC
# srp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTr
# BcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17l
# Necxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WC
# QTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1
# EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KS
# Op493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAs
# QWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUO
# UlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtv
# sauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCC
# ATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQD
# AgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaG
# NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9D
# XFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6
# Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuW
# cqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLih
# Vo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBj
# xZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02f
# c7cBqZ9Xql4o4rmUMYIDdjCCA3ICAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAFRK/zlJ0IOaa/2z9f5WEW
# MA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAc
# BgkqhkiG9w0BCQUxDxcNMjQwNzIzMDQxMDQwWjArBgsqhkiG9w0BCRACDDEcMBow
# GDAWBBRm8CsywsLJD4JdzqqKycZPGZzPQDAvBgkqhkiG9w0BCQQxIgQgkIvDVhve
# fLHmV6oLpu1uRn2Ja+QZcHyBxUc3Sc2Mx8wwNwYLKoZIhvcNAQkQAi8xKDAmMCQw
# IgQg0vbkbe10IszR1EBXaEE2b4KK2lWarjMWr00amtQMeCgwDQYJKoZIhvcNAQEB
# BQAEggIAP99djwp2XRi4GTfIEvbS7FBLGL3DgFkXpl/zLTy+7NyohRySMphtZoCo
# bLJofB77X9mQVPN6jyYLgSh0gvpTWYQvZnRB2Qftqdo+QL5VwNsmXMm5tP54SP6E
# Golup3kROzVHWG4EbS0xNqk+mxoEXTJDnH4XEni3/sLqE990uFmeoWtftusvJBcY
# ODe2egN1TOU+1q8l6wfpmU3hzeJ1oqgyqvNCyDiF+JgnaCxIg0xffm8OhU33j3BN
# ZJw/tX2hqKBFM5ygHswBqtvvxSzaAP9ayfyBgbqLjE00ZsUg3ODOnL3lFn50bgbw
# aXZzkIxVWmKG/1yoi43asU7YGQMBed6YHyMHtxzYav+3uvTR52vqYzGA+E9XNWte
# osnweERSkJW/Y8ExB3Ov1hsOmu8AlZ56vITgsO1vxCd2g8Rp9DsAyXWIm2E/wpM+
# 7GlrE+au0oF2YtwGNdSxTxcSQmHbMj7IjSmx1pEZ3BDETaT+ViC+vtJn1rT7zO1B
# YpDuXL9vV25EyO9kJ8Iev8TuC2u+e1nHF8jUBnkeYl/BGNXODClgj2RwpHLZhlm5
# GqZqTmL83d7WbVP+54c7Y/shjKZ3MKq3a4TZa/7LoLRWnPLZQ3GCCfiDQbd6Ljz/
# iD7fXhhJnZURMGWy/E45fBI5BC8xgevwKasy2ztr38p7ond2drc=
# SIG # End signature block
