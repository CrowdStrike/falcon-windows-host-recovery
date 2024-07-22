<# CrowdStrike Preinstallation Environment Recovery
Version 1.0

DESCRIPTION: Remove failing CrowdStrike Falcon channel file via Windows PE
#>
function Get-Drives {
    Write-Host "[+] Loading drives and checking encryption status."
    # Build up a list of potential drives, and add placeholder values for their encryption statuses
    $drives = Get-Volume | Where-Object { $null -ne $_.DriveLetter -and $_.DriveType -ne "CD-ROM" -and ($_.FileSystemType -eq "NTFS" -or $_.FileSystemType -eq "Unknown") } | Select-Object DriveLetter, FileSystemType, DriveType, HealthStatus, OperationalStatus, @{n = "Size / GB"; e = { [math]::Truncate($_.Size / 1GB) } }
    $drives | Add-Member -MemberType NoteProperty -Name Encrypted -Value "False"
    $drives | Add-Member -MemberType NoteProperty -Name ProtectorStatus -Value "None"
    $drives | Add-Member -MemberType NoteProperty -Name EncryptionMethod -Value "None"
    $drives | Add-Member -MemberType NoteProperty -Name RecoveryKeyID -Value "None"
    
    $BitLockerDrives = Get-WmiObject -Namespace "Root\cimv2\Security\MicrosoftVolumeEncryption" -Class Win32_EncryptableVolume
    $KeyProtectorType = 3  # Recovery Password type
    $BitLockerDrives | ForEach-Object {
        # Temporary storage variables
        $DriveLetter      = $_.DriveLetter
        $Encrypted        = $_.IsVolumeInitializedForProtection
        $ProtectorStatus  = $_.ProtectionStatus
        $EncryptionMethod = $_.EncryptionMethod
       
        # Type of protector status. 
        switch ($ProtectorStatus) {
            ("0")   { $ProtectorStatus = "Off" }
            ("1")   { $ProtectorStatus = "On (UnLocked)" }
            ("2")   { $ProtectorStatus = "On (Locked)" }
            Default { $ProtectorStatus = "Unknown" }
        }
    
        # Type of encryption Methods. 
        switch ($EncryptionMethod) {
            ("0")   { $EncryptionMethod = "None" }
            ("1")   { $EncryptionMethod = "AES 128 WITH DIFFUSER"}
            ("2")   { $EncryptionMethod = "AES 256 WITH DIFFUSER"}
            ("3")   { $EncryptionMethod = "AES 128" }
            ("4")   { $EncryptionMethod = "AES 256" }
            ("5")   { $EncryptionMethod = "Hardware Encryption"}
            ("6")   { $EncryptionMethod = "XTS-AES 128" }
            ("7")   { $EncryptionMethod = "XTS-AES 256" }
            Default { $EncryptionMethod = "Unknown" }
        }

        # Get recovery key ID (which will map to a password)
        $RecoveryKeyID = $_.GetKeyProtectors($KeyProtectorType).volumekeyprotectorID
   
        $drives | ForEach-Object {

            if ($DriveLetter -match $_.DriveLetter) {
                if ($_."Size / GB" -eq "0") { $_."Size / GB" = "Unknown" }
                $_.Encrypted = $Encrypted
                $_.ProtectorStatus = $ProtectorStatus
                $_.EncryptionMethod = $EncryptionMethod
                $_.RecoveryKeyID = $RecoveryKeyID
            }
        }

        # Clear Temporary variable values
        Clear-Variable  -Name DriveLetter, Encrypted, ProtectorStatus, EncryptionMethod, RecoveryKeyID
    }
   
    return $drives
}

function Unlock-Drive{
    Param(
        [Parameter(Mandatory = $true)]
        $Drive
    )

    # Select drive and prompt user for BitLocker recovery key
    $DriveLetter = "$($Drive.DriveLetter):"
    Write-Host "`r`n[+] Chosen Drive: $DriveLetter" -ForegroundColor Yellow
    Write-Host "[+] Recovery key password ID: " -ForegroundColor Yellow -NoNewline
    Write-Host $Drive.RecoveryKeyID -ForegroundColor Green
    Write-Host "[+] Enter the recovery password in the below format:" -ForegroundColor Yellow
    Write-Host "Recovery Key: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX" -BackgroundColor Yellow -ForegroundColor Black
    $RecoveryKey = (Read-Host "Recovery Key").Trim()

    # Validate recovery key format
    $IsRecoveryKeyValid = ($RecoveryKey -match '^(\d{6}-){7}\d{6}$' -and $RecoveryKey.Length -eq 55) 

    # Unlock BitLocker encrypted drive using recovery key
    if ($true  -eq $IsRecoveryKeyValid) {
        manage-bde -Unlock $DriveLetter -RecoveryPassword $RecoveryKey | Out-String -OutVariable ManageBDEOutput | Out-Null
        if ($ManageBDEOutput -match "successfully unlocked") {
            Write-Host "`r`n[+] The recovery password successfully unlocked this disk: $DriveLetter`r`n" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "`n"$ManageBDEOutput -ForegroundColor Red
            return $false
        }
    }
    else {
        Write-Host "`r`n[-] The recovery password was not of the correct length. It must comprise eight groups of six numbers, separated by hyphens." -ForegroundColor Red
        return $false
    }

    # Remove variable containing recovery key
    Remove-Variable $RecoveryKey
}

function Select-Drive {
    # Get list of all drives
    $drives = Get-Drives
    Write-Host "`r`n[+] List of detected drives:" -ForegroundColor Yellow
    $drives | Format-List -GroupBy Encrypted | Out-Host

    $DriveCount = @($drives).Length

    # If there is only one volume, skip user prompt to select drive. Else, prompt user for drive.
    if ($DriveCount -eq 1) {
        $CDrive = $drives[0]
        if (($CDrive.Encrypted -eq "True" -or $CDrive.Encrypted -eq $true) -and $CDrive.ProtectorStatus -eq "On (Locked)") {
            $unlocked = $false
            while ($false -eq $unlocked) {
               $unlocked = Unlock-Drive -Drive $CDrive
            }
        }
        else {
            Write-Host "[+] Drive is not encrypted. Skipping BitLocker stage."
        }
        return $CDrive
    }
    else {
        $LoopCount = 10
        $EnterDriveLetter = $false
        while ($false -eq $EnterDriveLetter -and $LoopCount -gt 0) {
            $EnterDriveLetter = Get-DriveLetterInput $drives
            $LoopCount = $LoopCount-1
        }

        if ($false -eq $EnterDriveLetter -and $LoopCount -eq 0) {
            Write-Host "[-] Invalid drive letter choice. Please review drive list and try again."
            return
        }

        $SelectedDrive = $drives | Where-Object {$_.DriveLetter -like $EnterDriveLetter}
        if (($SelectedDrive.Encrypted -eq "True" -or $SelectedDrive.Encrypted -eq $true) -and $SelectedDrive.ProtectorStatus -eq "On (Locked)") {
            $unlocked = $false
            while ($false -eq $unlocked) {
                $unlocked = Unlock-Drive -Drive $SelectedDrive
            }
        }
        else {
            Write-Host "[+] Drive is not encrypted. Skipping BitLocker stage."
        }
        return $SelectedDrive
    }
}

function Get-DriveLetterInput {
Param(
    [Parameter(Mandatory = $true)]
    $drives
)
    Write-Host "[+] Enter the letter of the drive to repair:" -ForegroundColor Black -BackgroundColor Yellow -NoNewline
    $EnterDriveLetter = (Read-Host).Trim().ToUpper()

    # select from valid drives ONLY
    if ($EnterDriveLetter -notin $drives.DriveLetter) {
        Write-Host "[-] Selected drive not in list of drives. Please re-enter a valid drive." -ForegroundColor Red
        return $false
    } else {
        return $EnterDriveLetter
    }
}

function Repair-Falcon {
    Write-Host "[+] Loading drive selection."
    $drive = Select-Drive
    $DriveLetter = $drive.DriveLetter
    Write-Host "[+] Will remediate Drive $DriveLetter`:"

    $ImpactedFiles = Get-ChildItem -Path "$DriveLetter`:\Windows\System32\drivers\CrowdStrike\*" -Include C-00000291*.sys
    if ($ImpactedFiles.Count -eq 0) { 
        Write-Host "[+] No potentially problematic channel files found on this drive. Script will reboot in 20 seconds. If you are still encountering a system error please contact CrowdStrike support." -ForegroundColor Yellow 
        Start-Sleep -Seconds 20
        wpeutil reboot
    }

    $KnownHeader=@('170','170','170','170','1','0','35','1')
    $DeleteFailed = $false

    Write-Host "[+] Deleting potentially problematic channel file(s)."
    foreach ($ImpactedFile in $ImpactedFiles) {
        $ImpactedFileHeader = Get-Content -Path $ImpactedFile.FullName -Encoding Byte -TotalCount 8
        $CompareResult = Compare-Object -ReferenceObject $ImpactedFileHeader -DifferenceObject $KnownHeader -PassThru
        if ($null -eq $CompareResult) {
            Remove-Item $ImpactedFile -Confirm:$false
            if (Test-Path $ImpactedFile) {
                Write-Host "[-] Unable to delete $ImpactedFile." -ForegroundColor Red
                $DeleteFailed = $true
            }
            else {
                Write-Host "[+] Successfully deleted $ImpactedFile."
            }
        }
        else {
            Write-Host "[-] Invalid file header, $Impactedfile is not a channel file." -ForegroundColor Red
            $DeleteFailed = $true
        }
    }

    if ($DeleteFailed) {
        Write-Host "[-] One or more channel files were invalid or could not be deleted. If any files were deleted, it is possible system issues are resolved." -ForegroundColor Red
        Write-Host "[-] System will reboot in 20 seconds. If no files were deleted, or system issues do not resolve, please contact CrowdStrike support." -ForegroundColor Red
        Start-Sleep 20
        wpeutil reboot
    }
    else {
        Write-Host "[+] Success! Rebooting in five seconds..." -ForegroundColor Green
        Start-Sleep -Seconds 5
        wpeutil reboot
    }
}

Repair-Falcon
exit
