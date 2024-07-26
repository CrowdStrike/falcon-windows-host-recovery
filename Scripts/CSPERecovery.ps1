<# CrowdStrike Preinstallation Environment Recovery
.SYNOPSIS
    Remove potentially problematic CrowdStrike Falcon channel file via Windows PE
.NOTES
    Version:        v1.3.1
    Author:         CrowdStrike, Inc.
    Creation Date:  26 July 2024
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
            ("1")   { $ProtectorStatus = "On (Unlocked)" }
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

function Unlock-DriveWithRecoveryKey {
    Param(
        [Parameter(Mandatory = $true)]
        $Drive,
        [Parameter(Mandatory = $true)]
        [string]$RecoveryKey
    )
    Write-Host "[+] Attempting to unlock the drive"

    # Validate recovery key format
    $IsRecoveryKeyValid = ($RecoveryKey -match '^(\d{6}-){7}\d{6}$' -and $RecoveryKey.Length -eq 55) 

    # Unlock BitLocker encrypted drive using recovery key
    if ($true -eq $IsRecoveryKeyValid) {
        manage-bde -Unlock "$($Drive.DriveLetter):" -RecoveryPassword $RecoveryKey | Out-String -OutVariable ManageBDEOutput | Out-Null
        if ($ManageBDEOutput -match "successfully unlocked") {
            Write-Host "`r`n[+] The recovery password successfully unlocked this disk: $($Drive.DriveLetter)`r`n" -ForegroundColor Green
            $Drive.ProtectorStatus = "On (Unlocked)"
            return $true
        }
        else {
            Write-Host "`n"$ManageBDEOutput -ForegroundColor Red
            return $false
        }
    }
    else {
        Write-Host "`r`n[-] The recovery password was not of the correct length or format. It must comprise eight groups of six numbers, separated by hyphens." -ForegroundColor Red
        return $false
    }
}

function Unlock-DriveWithDatabase {
    Param(
        [Parameter(Mandatory = $true)]
        $Drive
    )
    # Get the drive letter that this script is running from (likely X)
    $PSScriptRootDriveLetter = $(${PSScriptRoot}.Split("\")[0])
    $BitLockerKeysCSVPath = "$PSScriptRootDriveLetter\BitLockerKeys.csv"
    if (-not (Test-Path $BitLockerKeysCSVPath -PathType Leaf)) {
        # CSV file does not exist on boot disk, so bail out
        return $false
    }
    
    Write-Host "[+] Found a BitLocker key database CSV"
    $KeyDatabase = Import-Csv -Path $BitLockerKeysCSVPath
    # Remove the curly braces from the recovery key ID
    $ValueToFind = $Drive.RecoveryKeyID.Trim('{}').ToUpper()
    foreach ($KeyEntry in $KeyDatabase) {
        if ($KeyEntry.KeyID.ToUpper() -eq $ValueToFind) {
            Write-Host "[+] Found a potential recovery key matching Key ID: $($KeyEntry.KeyID)"
            $UnlockResult = Unlock-DriveWithRecoveryKey -Drive $Drive -RecoveryKey $KeyEntry.RecoveryKey
            if ($true -eq $UnlockResult) {
                return $true
            }
        }
    }
    return $false
}

function Unlock-DriveWithUserInput {
    Param(
        [Parameter(Mandatory = $true)]
        $Drive
    )
    # Select drive and prompt user for BitLocker recovery key
    Write-Host "`r`n[+] Chosen Drive: $($Drive.DriveLetter)" -ForegroundColor Yellow
    Write-Host "[+] Recovery key ID: " -ForegroundColor Yellow -NoNewline
    Write-Host $Drive.RecoveryKeyID -ForegroundColor Green

    if ($true -eq $AutomatedUnlock) {
        return $true
    } else {
        Write-Host "[+] Enter the recovery key in the below format:" -ForegroundColor Yellow
        Write-Host "Recovery Key: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX" -BackgroundColor Yellow -ForegroundColor Black
        $RecoveryKey = (Read-Host "Recovery Key").Trim()

        $UnlockResult = Unlock-DriveWithRecoveryKey -Drive $Drive -RecoveryKey $RecoveryKey
        return $UnlockResult
    }
}

function Get-DriveLetterInput {
    Param(
        [Parameter(Mandatory = $true)]
        $Drives
    )
    Write-Host "[+] Enter the letter of the drive to repair:" -ForegroundColor Black -BackgroundColor Yellow -NoNewline
    $EnterDriveLetter = (Read-Host).Trim().ToUpper()

    # Select from valid drives ONLY
    if ($EnterDriveLetter -notin $Drives.DriveLetter) {
        Write-Host "[-] Selected drive not in list of drives. Please re-enter a valid drive." -ForegroundColor Red
        return $false
    } else {
        return $EnterDriveLetter
    }
}

function Remove-PotentiallyProblematicChannelFiles {
    Param(
        [Parameter(Mandatory = $true)]
        $Drive
    )

    $CrowdStrikeDir = "$($Drive.DriveLetter):\Windows\System32\drivers\CrowdStrike"
    if (-not (Test-Path "$CrowdStrikeDir" -PathType Container)) {
        Write-Host "[-] The directory $CrowdStrikeDir does not exist, so the Falcon sensor is not installed on Drive $($Drive.DriveLetter):" -ForegroundColor Yellow
        return $false
    }

    $ImpactedFiles = Get-ChildItem -Path "$CrowdStrikeDir\*" -Include C-00000291*.sys
    if ($ImpactedFiles.Count -eq 0) { 
        Write-Host "[-] No potentially problematic channel files were found on Drive $($Drive.DriveLetter):" -ForegroundColor Yellow
        return $false
    }

    $KnownHeader=@('170','170','170','170','1','0','35','1')
    $Success = $false

    Write-Host "[+] Deleting potentially problematic channel file(s)."
    foreach ($ImpactedFile in $ImpactedFiles) {
        $ImpactedFileHeader = Get-Content -Path $ImpactedFile.FullName -Encoding Byte -TotalCount 8
        $CompareResult = Compare-Object -ReferenceObject $ImpactedFileHeader -DifferenceObject $KnownHeader -PassThru
        if ($null -eq $CompareResult) {
            Remove-Item $ImpactedFile -Confirm:$false
            if (Test-Path $ImpactedFile) {
                Write-Host "[-] Unable to delete $ImpactedFile." -ForegroundColor Red
            }
            else {
                Write-Host "[+] Successfully deleted $ImpactedFile."
                $Success = $true
            }
        }
        else {
            Write-Host "[-] Invalid file header, $Impactedfile is not a channel file." -ForegroundColor Red
        }
    }

    return $Success
}

function Repair-SingleDrive {
    Param(
        [Parameter(Mandatory = $true)]
        $Drive
    )
    Write-Host "[+] Attempting to remediate Falcon on drive $($Drive.DriveLetter):"

    if (("True" -eq $Drive.Encrypted -or $true -eq $Drive.Encrypted) -and "On (Locked)" -eq $Drive.ProtectorStatus) {
        $unlocked = Unlock-DriveWithDatabase -Drive $Drive
        while ($false -eq $unlocked) {
           $unlocked = Unlock-DriveWithUserInput -Drive $Drive
        }
    }
    else {
        Write-Host "[+] Drive is not encrypted. Skipping BitLocker stage."
    }
    $result = Remove-PotentiallyProblematicChannelFiles -Drive $Drive
    return $result
}

function Repair-MultipleDrives {
    Param(
        [Parameter(Mandatory = $true)]
        $Drives
    )

    # We try automated remediation first
    $RemediatedADrive = $false
    foreach ($Drive in $Drives) {
        if (("True" -eq $Drive.Encrypted -or $true -eq $Drive.Encrypted) -and "On (Locked)" -eq $Drive.ProtectorStatus) {
            $AutoUnlocked = Unlock-DriveWithDatabase -Drive $Drive
            if ($true -eq $AutoUnlocked) {
                $result = Remove-PotentiallyProblematicChannelFiles -Drive $Drive
            }
            else {
                $result = $false
            }
        }
        else {
            $result = Remove-PotentiallyProblematicChannelFiles -Drive $Drive
        }

        if ($true -eq $result) {
            $RemediatedADrive = $true
        }
    }

    # If we successfully remediated based on the key database, we immediately return back.
    # This technically could impact users with dual boot systems, but we assessed the potential
    # impact to be very small.
    if ($true -eq $RemediatedADrive) {
        return $true
    }

    # If we can't remediate a drive automatically, we ask the user which drive to remediate
    # and accept a drive letter as input. We will then ask the user for the BitLocker key.
    # Auto-unlocked and non-encrypted drives would already have been through the remediation
    # routine, so we're therefore only concerned with drives that are still locked.
    $EncryptedDrives = $Drives | Where-Object { ("True" -eq $_.Encrypted -or $true -eq $_.Encrypted) -and "On (Locked)" -eq $_.ProtectorStatus }
    if ($null -eq $EncryptedDrives -or 0 -eq $EncryptedDrives.Count) {
        return $false
    }
    elseif ($EncryptedDrives.Count -eq 1) {
        $unlocked = $false
        while ($false -eq $unlocked) {
            $unlocked = Unlock-DriveWithUserInput -Drive $EncryptedDrives[0]
        }
        $result = Remove-PotentiallyProblematicChannelFiles -Drive $EncryptedDrives[0]
        return $result
    }
    else {
        $EncryptedDrives | Format-List -GroupBy Encrypted | Out-Host
        $LoopCount = 10
        $EnterDriveLetter = $false
        while ($false -eq $EnterDriveLetter -and $LoopCount -gt 0) {
            $EnterDriveLetter = Get-DriveLetterInput $drives
            $LoopCount = $LoopCount-1
        }

        if ($false -eq $EnterDriveLetter -and $LoopCount -eq 0) {
            Write-Host "[-] Invalid drive letter choice. Please review drive list and try again."
            return $false
        }

        $Drive = ($EncryptedDrives | Where-Object {$_.DriveLetter -eq $EnterDriveLetter })[0]
        $unlocked = $false
        while ($false -eq $unlocked) {
            $unlocked = Unlock-DriveWithUserInput -Drive $Drive
        }
        $result = Remove-PotentiallyProblematicChannelFiles -Drive $Drive
        return $result
    }
}

function Remove-SafeBoot {
    Write-Host "[+] Ensuring system will not boot into Safe Mode"
    # Capture all the output from the process upon execution
    # Answer based on: https://stackoverflow.com/a/8762068
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "bcdedit.exe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = "/deletevalue", "{default}", "safeboot"
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $pinfo
    $process.Start() | Out-Null
    $process.WaitForExit()
    $ExitCode = $process.ExitCode

    if (0 -eq $ExitCode) {
        Write-Host "[+] The system will now boot into Windows normally" -ForegroundColor Green
    }
    else {
        Write-Host "[+] The system was not configured to boot into safe mode, so no changes were made."
    }
}

function Repair-BootLoop {
    Write-Host "[+] Loading drive selection."
    $Drives = Get-Drives
    Write-Host "`r`n[+] List of detected drives:" -ForegroundColor Yellow
    $Drives | Format-List -GroupBy Encrypted | Out-Host

    $DriveCount = @($Drives).Length
    if ($null -eq $Drives -or $DriveCount -eq 0) {
        Write-Host "[-] No NTFS or BitLocker encrypted drives were found on the system. It is likely that necessary drivers for your system are not included with this tool. Please speak to your IT department for further assistance."
        Write-Host "[-] The system will reboot in 20 seconds."
        Start-Sleep -Seconds 20
        wpeutil reboot
        exit
    }
    elseif ($DriveCount -eq 1) {
        $success = Repair-SingleDrive -Drive $Drives[0]
        if ($true -eq $success) {
            Remove-SafeBoot
            Write-Host "[+] Success! Rebooting in five seconds..." -ForegroundColor Green
            Start-Sleep -Seconds 5
            wpeutil reboot
            exit
        }
        else {
            Write-Host "[-] One or more channel files were invalid or could not be deleted. If any files were deleted, it is possible system issues are resolved." -ForegroundColor Red
            Write-Host "[-] System will reboot in 20 seconds. If no files were deleted, or system issues do not resolve, please contact CrowdStrike support." -ForegroundColor Red
            Start-Sleep 20
            wpeutil reboot
            exit
        }
    }
    else {
        $success = Repair-MultipleDrives -Drives $Drives
        # Handle this situation since multiple things could have gone wrong here
        if ($true -eq $success) {
            Remove-SafeBoot
            Write-Host "[+] Success! Rebooting in five seconds..." -ForegroundColor Green
            Start-Sleep -Seconds 5
            wpeutil reboot
            exit
        }
        else {
            Write-Host "[-] This tool detected multiple drives, but none of them could be remediated." -ForegroundColor Red
            Write-Host "[-] System will reboot in 20 seconds. If no files were deleted, or system issues do not resolve, please contact CrowdStrike support." -ForegroundColor Red
            Start-Sleep -Seconds 20
            wpeutil reboot
            exit
        }
    }
}

Repair-BootLoop
exit

# SIG # Begin signature block
# MIIuwgYJKoZIhvcNAQcCoIIuszCCLq8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDWSnWJ3gnZC97p
# RL2i1FowRQv6yD19D7bsLKSOjCZfnaCCE68wggWNMIIEdaADAgECAhAOmxiO+dAt
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
# wCxXKaDLYxjnLaTcco3jYJER7yfpfPlPVjGCGmkwghplAgEBMH0waTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTI1NiAyMDIxIENB
# MQIQDUj/2eJmrj5R3FwGE1OL8zANBglghkgBZQMEAgEFAKB8MBAGCisGAQQBgjcC
# AQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC/H27rq51impjQFPdGC/J3
# +0SeVOkpnlrq5iV0fmjbLDANBgkqhkiG9w0BAQEFAASCAgB8GmZ6zuE0ds/R6qxI
# xO06NhnW4/vqjkTA6cnblmrdG5mNG0IxYmOkJHY90lXRZomeLOc1Cy9bIg6oCurh
# LktpPzxCSOc2jK9jb7nHuXN0EkLZax+7fR0HFvQEz689RtcLA+qz71cH5DMiwkbn
# TyGP9ryvk9btFqUXU5GUjVTh7YzxL1CtT98Hta9HRT5Xu6NShERIhMAm+9fpJd87
# iEHNG8p7eE2DPpGT+Q5a6T7O3tgurOFe6/CFKuzd8NrRBv96CIMCArBnjzAeo2U2
# Go6PnSxd2p5XTtmne08w0dhbKkTNX2jNdsEKFiDws2teAkdq9R5fu+NbKTf8Mzys
# zhX+2vF9/BLmHd7I0mOrXHgNTnrNameOy0jQ4w2qfof/DNOKaie8pz2OOTGujFfw
# iAd/ImNONGM7x8nsiyQBzLJSMRQIZFwsJ/S/BgwDzwknlgD3ZvsDqXfy4pePZ5CQ
# IxuBxB4diX+/BSiQEDxEjtsF4KPwtLE9ihSJp8c5pHSb0S6wiOBhP9U3+fp2mUDX
# y+wNlLbgG7LHV9MA5Yq0pjKS7TXyfSqGVeKPpsqFlajHMje39t7lLsM6GgXwsN8C
# 0UaLzgnYaGbO0U+ha+nGGmQawITzfbcz537W4NrWVNfc/IyyKTpLTPS4spePGZJ/
# sL8rWHWEnNjAe9sLPnb9Feh4R6GCFz8wghc7BgorBgEEAYI3AwMBMYIXKzCCFycG
# CSqGSIb3DQEHAqCCFxgwghcUAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcN
# AQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCC2Iwsl
# OOiDqw4vcGBDLSfdyFPqK/j6dw5xUfmskTXNKAIQMcrbO/x0Xe2SqQ0qNvo59hgP
# MjAyNDA3MjYxOTUyNTBaoIITCTCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/l
# YRYwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYg
# U0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMy
# MzU5NTlaMEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEg
# MB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7
# Kpxn3GIVWMGpkxGnzaqyat0QKYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nn
# af5bw9YrIBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0Xq
# DWFsnf5xXsQGmjzwxS55DxtmUuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjm
# UpW1R9d4KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF
# 7qr2JPUdvJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0
# m+PebmQZBzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTq
# YggT02kefGRNnQ/fztFejKqrUBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApY
# TAA+hWl1x4Nk1nXNjxJ2VqUk+tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGy
# bHGvPrhvltXhEBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJ
# XwikcKPsCvERLmTgyyIryvEoEyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tA
# ewIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQW
# BBSltu8T5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2
# VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hB
# MjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1
# mBe8cI1PijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfh
# YJwr7e09SI64a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6
# hCmYtld5j9smViuw86e9NwzYmHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKT
# GnaiaXXTUOREEr4gDZ6pRND45Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm
# 3d5al08zjdSNd311RaGlWCZqA0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD
# 6tSRN+9NUvPJYCHEVkft2hFLjDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB
# 0JozSqg21Llyln6XeThIX8rC3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTm
# Ot44OwdeOVj0fHMxVaCAEcsUDH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLY
# OrixRoZruhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK
# 1ALgXGC7KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtz
# tpn5aywGRu9BHvDwX+Db2a2QgESvgBBBijCCBq4wggSWoAMCAQICEAc2N7ckVHzY
# R6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3
# MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjz
# aPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3E
# F3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYnc
# fGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8O
# pWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROp
# VymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4i
# FNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmif
# tkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0
# UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9Ne
# S3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCj
# WAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57I
# bzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0
# MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAY
# LhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQx
# Z822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf
# 7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDV
# inF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7
# +6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJ
# D5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvk
# OHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJG
# nXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimG
# sJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38A
# C+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d
# 2zc4GqEr9u3WfPwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqG
# SIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFz
# c3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTla
# MGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9v
# dCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8
# MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauy
# efLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34Lz
# B4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+x
# embud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhA
# kHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1Lyu
# GwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2
# PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37A
# lLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD7
# 6GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/
# ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXA
# j6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTAD
# AQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF
# 66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEE
# bTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYB
# BQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
# ZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979X
# B72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4k
# vFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU
# 53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pc
# VIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5v
# Iy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2
# MIIDcgIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBU
# aW1lU3RhbXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCg
# gdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0y
# NDA3MjYxOTUyNTBaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFGbwKzLCwskPgl3O
# qorJxk8ZnM9AMC8GCSqGSIb3DQEJBDEiBCCtQ0afngTKlovXtW3wt0BkCllfnxSd
# SW4mAPTy58+8oDA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCDS9uRt7XQizNHUQFdo
# QTZvgoraVZquMxavTRqa1Ax4KDANBgkqhkiG9w0BAQEFAASCAgAcZJVxn5BN/SRw
# f/JdmG9UsRihmXA/kCGRxUoscmXI9GLRWK6ABEOGF4bQ7/h2oqLw2LrxOXCdhssS
# gQxhqVwMIMPLGQdOQ5j8sJiDWNkA5E6XplTM3HtRMoiE/rc1f4TNr/i5IlNM1Vsq
# Rx/PFUHSq+hd6aZ20L8OBZbYZrCLQA/Wu6DxwN4fE3fzvdAWrIgm98O336xqHQKt
# tAG1RG7L8twB+ML75klSEgX+rElUECQB1KfBqeYKwWQWeN+TqWM9FSLT3A97dv7f
# /HhGtCwd4ybMY8abpB52VXSFac/q4SQHIWFlcjj4l6PKZpFz8gEY9f3tcom5+fe1
# yb5C9GmA0/uyzJyFA/c9xQhlm/ZXxtRBBjKcxZyRA3MgVjfYEKD9eXUsF67c/d8S
# fWna8flnEPwxqQxwcDFX0Gss8k92hIiicWb6BimIzGOFaAkhFIIs0aKPXQlCaBva
# jamCfqXaFxxBtF85JJl5fzQgQ0e6hALtSg66bOSHbg1IIX6t3xx6NXQlKh35Y32y
# 7dYztf2n0aAt902/17cd92LzTf2Q4IF9Sf3MqIkQ1jku1Wh5JnDO36vJ4KJ1MsBJ
# Addlxxkw93wJCy2of9EhMi0XKR3E80XxDZaPg8Ic4+wsGEEhoU4cfWeikKBaH+fx
# DGExi1Ntn1BxpmzJ1ZLcEXz7gvzukQ==
# SIG # End signature block
