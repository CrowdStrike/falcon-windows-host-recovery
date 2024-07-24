<# CrowdStrike Preinstallation Environment Recovery
v1.2.0
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
    $ImpactedFiles = Get-ChildItem -Path "$($Drive.DriveLetter):\Windows\System32\drivers\CrowdStrike\*" -Include C-00000291*.sys
    if ($ImpactedFiles.Count -eq 0) { 
        Write-Host "[+] No potentially problematic channel files found on this drive. Script will reboot in 20 seconds. If you are still encountering a system error please contact CrowdStrike support." -ForegroundColor Yellow 
        Start-Sleep -Seconds 20
        wpeutil reboot
    }

    $KnownHeader=@('170','170','170','170','1','0','35','1')
    $Success = $true

    Write-Host "[+] Deleting potentially problematic channel file(s)."
    foreach ($ImpactedFile in $ImpactedFiles) {
        $ImpactedFileHeader = Get-Content -Path $ImpactedFile.FullName -Encoding Byte -TotalCount 8
        $CompareResult = Compare-Object -ReferenceObject $ImpactedFileHeader -DifferenceObject $KnownHeader -PassThru
        if ($null -eq $CompareResult) {
            Remove-Item $ImpactedFile -Confirm:$false
            if (Test-Path $ImpactedFile) {
                Write-Host "[-] Unable to delete $ImpactedFile." -ForegroundColor Red
                $Success = $false
            }
            else {
                Write-Host "[+] Successfully deleted $ImpactedFile."
            }
        }
        else {
            Write-Host "[-] Invalid file header, $Impactedfile is not a channel file." -ForegroundColor Red
            $Success = $false
        }
    }

    return $Success
}

function Repair-SingleDrive {
    Param(
        [Parameter(Mandatory = $true)]
        $Drive
    )
    Write-Host "[+] Attempting to remediate Falcon on drive $($Drive.DriverLetter):"

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
# MIIpMQYJKoZIhvcNAQcCoIIpIjCCKR4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDzm61Ce6Vl1yI2
# tq80/xgsHrQkXYOzwzaTV/dRJIJVqKCCDh4wggawMIIEmKADAgECAhAOTWf2QxbJ
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDi
# Mlkn+WWpMOOmuAaEmPrsnHHSyK/HhQ9bS+PqYeDH1jANBgkqhkiG9w0BAQEFAASC
# AgAUPjwUEBcHPgNFPCB3I8rncoJrnrcWslyxQz8/ZtnGWQnMpY/o/wUei9jU/CbZ
# jzWdANguJjKnV8VPyAkz7iwpsl8dlh1XUYIJrElRvVCBjCxtD3aeBFJR1OtEmysX
# XuzECogRaNydBWxxhVCeOb+dx1y3Ys9P0Ut6vPLpXgA3rd+3M5FZiUGGdoPaR0s/
# dDqZX3+e9HeGiM/MmgtsVYkUgrl9/NnDHb7sWX6xaBbuBl6TaTa5u1HxsnzJPodH
# +j/VrGQFk88KRt0BxTG8il9O5GXZnFbnqsIqXlDQeE6JLWNgrYuEkttLVsv5mFha
# +r3afpFXSxJayTcDM3kvWx9Bn2T50jZ6b9/aX8xZoar6VxhFuN3xqh7C8Pe3pihC
# sq+kVmZrLYxrd4h5NZUnk2h2Mr9mYrmgv5aRK4USGMuEGrSSa/1mfcpWTZzibUqo
# 4VQbAm3SyIjsu4ls8ni0D8tK4uE5xyHikrVEfk5z0oOwetk5WbeK4hc2MxlAhzDn
# C+ix0KupEcloGHhAG3iD7JQ+ogMSLbMo1lsWB9o3V4UQf9iK4LwLjI/cTp5EJF0y
# JUCnWPlnQgzhwnDnHzSuUN/LHjkoPWXZNBFTU6MEA0cImoidabpix76cqKQaTy1C
# L2oInXbFVabt75bGFZe5FXU+nyKzGwQtfNS6rVgHGOLeeaGCFz8wghc7BgorBgEE
# AYI3AwMBMYIXKzCCFycGCSqGSIb3DQEHAqCCFxgwghcUAgEDMQ8wDQYJYIZIAWUD
# BAIBBQAwdwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCG
# SAFlAwQCAQUABCDyroKWxsOhZ3OBRmqcoKyo1qzcvkv5DvIVb8Bt35/+wQIQGY5v
# Z02zvHLtiNamut2emxgPMjAyNDA3MjQwMzE5NTRaoIITCTCCBsIwggSqoAMCAQIC
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
# CSqGSIb3DQEJBTEPFw0yNDA3MjQwMzE5NTRaMCsGCyqGSIb3DQEJEAIMMRwwGjAY
# MBYEFGbwKzLCwskPgl3OqorJxk8ZnM9AMC8GCSqGSIb3DQEJBDEiBCDz2iwAOels
# FBhTY9D0x9D+RguGAQcvR3tMcyhBRVzJ4jA3BgsqhkiG9w0BCRACLzEoMCYwJDAi
# BCDS9uRt7XQizNHUQFdoQTZvgoraVZquMxavTRqa1Ax4KDANBgkqhkiG9w0BAQEF
# AASCAgCizgMwpTawgkxFkMfsmzpfVeYYTnf47QenXmfEfjL+XNX22gFsjjpFk1jE
# XjLHJ+AfALIJu2aFRtbSDxHoC0O5DwHGLQUsoIqvpX3PPAn4jGLEQABcVBZX/AD5
# Vz3c0xvRM10sHWJmp+wS4Sn2qbPTNcWq69bQoQrZEb8jQJ4xw/jyAaqEjnE49IY2
# dORgWQ+ga+KsLcWEFr5CFH5LwxdbKJluF3Z2PaIJHvEDsU/zFzIvaQbW64rgPw1A
# Rw0o202aMdCqlUgCt2AN5SrA+4RIx2KMIsXHqR8DTDRfzEBEfWqn/rGykjRAiAbU
# vfXNFnlTrrIuQmStgySz7/U0Uhf7I1STPr2JSybRKeHVFwvoVa4fw6SjmFsDVUMI
# DsexIQFsWdeGYzs6f1q8q4QVrO37nVI7dH7vt5oSPNy04O46RvPnjxzpYcipZB5k
# IRtEoQDMBh5wQEQe7e+yt8YogXic9CRFfwQjX0q/NkhU6NUd9aRvEw2oC9OiCRku
# jsRqJNk+befSh49xEOcU4VR/d7qiUY4RLhTnfp7KjbNAxRBFjHCEU3OwdlU990ng
# yozf8qRNv/xbghkL1PjeZJkjbw8N8SAqLVFOXi7Mz88qU6YswywzXXC/QJ3nMFBB
# zDN4VpWuyyOUNxwO1m/jj/WWsR8Ci4y5kmBrlJSQ5IuIbyVmyw==
# SIG # End signature block
