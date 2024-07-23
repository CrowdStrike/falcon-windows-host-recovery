<# CrowdStrike Preinstallation Environment Recovery
v1.1.0
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

# SIG # Begin signature block
# MIIpMgYJKoZIhvcNAQcCoIIpIzCCKR8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBR0IAaJ+Gjc9wh
# fpiTiVxARKUx3yY09X3awFuP8DxIg6CCDh4wggawMIIEmKADAgECAhAOTWf2QxbJ
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBc
# ljopkhlF+YPnUGxdTLn0JB5mMXnsfuXUEp9Z5Z2eTTANBgkqhkiG9w0BAQEFAASC
# AgBUmt2X0EtkCQufXQlXB0PNZ/jFkHP0ss7+nzI+5UgUBgx3E0mmYL81dLRV5NOe
# Rph5IdkMUEqLEkEYE3Ai1ePbADOYGc/eH1heDcnFEkkdJ0IrF7/YgB5SNdrHwkVj
# J6hM2Qih15cuEyft9n2YP5vPSn+l8kHcq5hRt9WisG2sTkzWvMaSpoT3lok+63gr
# eBFVfRWFItwz8srBoYIQivtBhfocO/0uEdNPUzXUFvhCS5dscug09J4hq0tiWgZo
# 8NZhi8O184E5rWAf6wCaLw4Fw/c+WbSNAyFxIvrXWW8T5TsTgCyH5Y5VtIuoVSgw
# El+pKmHur4dKapCueKmlOJJ/iMfJ/dyPIdEmDUbT4eWgPXcfW/3eNrVdAkPEZ6B5
# y+YjdT9u0AGiYb3c1w03smy1vfDr703WJSE5QmwB5f8SowUNAXV0aroTxx9mgJnp
# 1EDDDFwCCCCRENJItxfXUKa90ly7p3xc8X10DiwafSHV3oxvjC8K5OohJlt0GSVZ
# b9ffPzsCIHzt4lvVxQEnpsigZ101GyTGGwG9R6Nt7IJSFPfRVg/+04d4tsCB+6tT
# r0kJi7VK1SBHXN3aMThQtYUfUK1uDwugzJ4UpiP3korp/SKHPer+OcguHdzAkGwe
# u9hSnRityKFHxicB/uF1CDs7bJ41dT712QuCINUO1BgzF6GCF0Awghc8BgorBgEE
# AYI3AwMBMYIXLDCCFygGCSqGSIb3DQEHAqCCFxkwghcVAgEDMQ8wDQYJYIZIAWUD
# BAIBBQAweAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCG
# SAFlAwQCAQUABCB89HVA58cGbcMBoO79BF79f/lgUcZ5pGLglraT39x/kAIRAI0D
# nVF862NdLWBpHo0IsBUYDzIwMjQwNzIzMDQxMDQxWqCCEwkwggbCMIIEqqADAgEC
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
# BgkqhkiG9w0BCQUxDxcNMjQwNzIzMDQxMDQxWjArBgsqhkiG9w0BCRACDDEcMBow
# GDAWBBRm8CsywsLJD4JdzqqKycZPGZzPQDAvBgkqhkiG9w0BCQQxIgQgX6KchSkg
# jJUhehNCUeTFjttuRWd7upCJt9iuxpla+OIwNwYLKoZIhvcNAQkQAi8xKDAmMCQw
# IgQg0vbkbe10IszR1EBXaEE2b4KK2lWarjMWr00amtQMeCgwDQYJKoZIhvcNAQEB
# BQAEggIAes+Uv0DshaT6Ew1stYpFXYQw70ISRGAreE/Q9wI57uIm5Plg/Hbh0rMv
# sQ20Eg5zkVNoVRnr8H4Yjk3RY5gdtfe2rmYrWkvjEFvIsiDSvZfaynDiK4mrwF1E
# uYktvogI/Rj65EIPNpeqAJ/ZBNPihQiBnjdFSUgxyajOl/nxK02OzbscesIduaUk
# VO6gL9V/eFBoR9EGs2l3bgQA4vqRC8yCLYg8YKJQWog+uZkDHwYH58IW9U2Cn8VA
# zYhCS3ILqJWYERU5NIFhY3CD68tM5ihRLNG/tpKvVb3q/DWb6QtO9Yy3XTkwDr7C
# SsWZ9A8YhJ1h6OpPuI5KUmWSfViot70d9ZLNBDIRIUJh6EISaR5e3XH8YV5d+xLX
# i4zklko4E55WN2ILdKoJh4c3DtNUPXRngHLAOnXFbq5oMYC7QdGGPHspOMHlDJN5
# AYXmZbYNNqtjzZPtHuj1m31jyxeXbG1WM04uQ1i0R2a1vVggmQmK0s1D2RAr5BgG
# zhXP2cDU1M3V/Ec/mUuukWqbcgDss9PwZU0NWC3oSDDvj4qTE1x5l3JHTGMj3qua
# p9iMFeujjJxcJxbXKWoTw3DMZgRYvWxgxVWWq7zANr9yWDjeI7gYCA6LFECqhn96
# nq+jzrzMG4hTjbW5+9w3P16nUe0123uYmqfnbvWgqF4CcPfuoyo=
# SIG # End signature block
