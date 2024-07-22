<# CrowdStrike Preinstallation Environment Recovery ISO Builder
Version 1.0
#>
Param(
    [switch]$SkipThirdPartyDriverDownloads
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
    Invoke-WebRequest -Uri $URL -OutFile $OutputPath -ErrorAction Stop

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
    Invoke-WebRequest -Uri $URL -OutFile $OutputPath -ErrorAction Stop

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
    Invoke-WebRequest -Uri $URL -OutFile $OutputPath -ErrorAction Stop

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
    Invoke-WebRequest -Uri $URL -OutFile $OutputPath -ErrorAction Stop

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
Write-Host "- Microsoft ADK Windows Preinstallation Envrionment Addon"
Write-Host "- Any device drivers you include in the final bootable image"
Write-Host "If you do not accept any of these terms, cancel execution of this script immediately. Execution will continue automatically in ten seconds." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Install-ADK-MS

$LocalWorkDir = Get-Location
$LocalWorkDir = "$LocalWorkDir\WorkDir"
Make-WorkDir -WorkDir $LocalWorkDir

Write-Host "[+] Downloading and Staging Drivers"

if ($true -eq $SkipThirdPartyDriverDownloads) {
    Write-Host "[+] Skipping download of third party drivers from Dell, HP, and VMware" -ForegroundColor Yellow
}
else {
    Get-DellDrivers-WinPE10 -WorkDir $LocalWorkDir
    Get-DellDrivers-WinPE11 -WorkDir $LocalWorkDir  
    Get-HPClientDrivers -WorkDir $LocalWorkDir
    Get-VMwareDrivers -WorkDir $LocalWorkDir
}

Get-Packaged-Drivers -WorkDir $LocalWorkDir

Write-Host "[+] Building Boot Disks"
Make-BootDisks -WorkDir $LocalWorkDir

Write-Host "[+] Complete!" -ForegroundColor Green
Write-Host "CrowdStrike WinPE Recovery ISO: $CSPERecoveryISO"
Write-Host "CrowdStrike Safe Boot ISO: $CSSafeBootISO"
