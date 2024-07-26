<# CrowdStrike BitLocker Password Export Tool
v1.3.0
DESCRIPTION: Export all BitLocker recovery keys from Active Directory and Entra ID
#>
#Requires -RunAsAdministrator
#Requires -Version 7

Param(
    [switch] $EntraID,
    [switch] $ActiveDirectory,
    [string] $OU
)

function Install-MicrosoftGraphCmdlets {
    $Modules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Identity.SignIns"
    )

    foreach ($Module in $Modules) {
        Write-Host "[+] Checking for $Module"
        if (Get-Module -ListAvailable -Name $Module) {
            Write-Host "[+] $Module looks available" -ForegroundColor Green
        }
        else {
            Write-Host "[+] $Module not found. Installing into the CurrentUser scope." -ForegroundColor Yellow
            Install-Module -Name $Module -Scope CurrentUser -Force
        }
    }
}

function Install-MicrosoftADTools {
    Param(
        [Parameter(Mandatory = $true)]
        $ProductType
    )
    Write-Host "[+] Checking for Active Directory PowerShell tools"
    if ($ProductType -eq "2") {
        Write-Host "[+] Script is running on a domain controller, so Active Directory PowerShell tools are available by default"
        return
    }
    $installed = Get-WindowsFeature -Name RSAT-AD-PowerShell | Where-Object {$_. installstate -eq "installed"}
    if (!$installed) {
        Write-Host "`n[+] Active Directory RSAT (PowerShell) not installed" -ForeGroundcolor Yellow
        Write-Host "[+] Installing Active Directory RSAT (PowerShell)"
        Install-WindowsFeature -Name "RSAT-AD-PowerShell"
    }
}

function Get-EntraIDBitLockerKeys {
    Param(
        [Parameter(Mandatory = $true)]
        $BitLockerKeys
    )
    Write-Host "[+] Connecting to the Microsoft Graph API"
    $Scopes = @(
        "BitLockerKey.ReadBasic.All",
        "BitLockerKey.Read.All",
        "Device.Read.All"
    )
    Write-Host "[+] Requesting these scopes:"
    foreach ($Scope in $Scopes) {
        Write-Host "    - $Scope"
    }
    Connect-MgGraph -Scopes ($Scopes -join " ") -NoWelcome

    Write-Host "[+] Searching for all BitLocker enabled devices in Entra ID" -ForegroundColor Cyan

    # Retrieve a list of objects which map recovery key IDs (key protector GUIDs) to devices
    $ProtectorMapping = Get-MgInformationProtectionBitLockerRecoveryKey

    if (!$ProtectorMapping) {
        Write-Host "[-] Unable to get any BitLocker enabled devices in EntraID. See errors above." -ForegroundColor Red
        return
    }

    # Precache the list of devices in the Entra ID tenant to reduce required API calls
    $Devices = Get-MgDevice -Select DeviceId, DisplayName -All | Select-Object -Property DeviceId, DisplayName
    Write-Host "[+] Fetched a list of $($Devices.Count) devices"

    $ProtectorMapping | Foreach-Object -ThrottleLimit 5 -Parallel {
        $Key = $_
        Write-Host "[+] Obtaining BitLocker Recovery key for Key ID {$($Key.Id)} (Device ID: $($Key.DeviceId))" -ForegroundColor Cyan

        $RecoveryKey = Get-MgInformationProtectionBitLockerRecoveryKey -BitLockerRecoveryKeyId $Key.Id -Property "key" | Select-Object -ExpandProperty key
        $DeviceName = $using:Devices | Where-Object {$_.DeviceId -eq $Key.DeviceId} | Select-Object -ExpandProperty DisplayName

        if ($RecoveryKey) {
            Write-Host "[+] Successfully obtained BitLocker recovery key for $DeviceName (key ID: {$($Key.Id)})" -ForegroundColor Green
            $DeviceData = @{
                Hostname = $DeviceName
                KeyID = $Key.Id
                RecoveryKey = $RecoveryKey
                Directory = "Entra"
            }
            ($using:BitLockerKeys).Add($DeviceData)
        }
    }
    $EntraBitLockerKeys | Format-Table | Out-Host
}

function Get-ADBitLockerKeys {
    Param(
        [Parameter(Mandatory = $true)]
        $BitLockerKeys,
        [Parameter(Mandatory = $false)]
        $OU
    )

    if (!$OU) {
        Write-Host "[+] Getting a list of all computers in Active Directory" -ForegroundColor Cyan
        $computers = Get-ADComputer -Filter * -Properties DistinguishedName
    }
    else {
        Write-Host "[+] Searching for all computers in Active Directory within the OU: $OU"
        $computers = Get-ADComputer -Filter * -Properties DistinguishedName -SearchBase "$OU"
    }

    if ($null -eq $computers) {
        Write-Host "[-] No computers were found in Active Directory. Please try again." -ForegroundColor Red
        return
    }

    foreach ($computer in $computers) {
        Write-Host "[+] Obtaining recovery key AD object for the system $($computer.DistinguishedName)"
        $RecoveryKeyObject = Get-ADObject -SearchBase "$($computer.DistinguishedName)" -Filter "objectclass -eq ""msFVE-RecoveryInformation""" -Properties msFVE-RecoveryPassword,msFVE-VolumeGuid

        if ($null -eq $RecoveryKeyObject) {
            Write-Host "[-] $($computer.DistinguishedName) does not have a recovery key in Active Directory." -ForegroundColor Yellow 
        }
        else {
            $KeyID = $RecoveryKeyObject.Name.split('{')[1].split('}')[0]
            $RecoveryKey = $RecoveryKeyObject | Select-Object -ExpandProperty msFVE-RecoveryPassword

            $DeviceData = @{
                Hostname = $computer.DistinguishedName
                KeyId = $KeyID
                RecoveryKey = $RecoveryKey
                Directory = "ActiveDirectory"
            }
            $BitLockerKeys.Add($DeviceData)
        }
    }
}

if (!$ActiveDirectory -and !$EntraID) {
    Write-Host "[-] You must provide at least one of the flags -ActiveDirectory or -EntraID" -ForegroundColor Red
    Write-Host "Usage"
    Write-Host "-ActiveDirectory: extract BitLocker keys from ActiveDirectory"
    Write-Host "-ActiveDirectory -OU ""OU=OurComputers,CN=Computers,DC=company,DC=local"": extract BitLocker keys for a specific AD organisational unit"
    Write-Host "-EntraID: extract BitLocker keys from Entra ID (formally known as Azure AD)"
    Write-Host "-ActiveDirectory -EntraID: extract BitLocker keys from both Active Directory and Entra ID"
    Exit
}

if ($ActiveDirectory -and [string]::IsNullOrEmpty($env:USERDNSDomain)) {
    Write-Host "[-] This machine is not domain joined, and therefore cannot obtain BitLocker keys from Active Directory." -ForegroundColor Red
    Write-Host "[-] Please run this script again from a domain-joined system running Windows Server."
    Write-Host "[-] Alternatively, run this script again without the -ActiveDirectory flag."
    Exit
}

Write-Host "[+] Checking system type"
$ProductType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

if ($ActiveDirectory -and $ProductType -eq 1) {
    Write-Host "[-] This script cannot obtain BitLocker keys from Active Directory because it is a client device." -ForegroundColor Red
    Write-Host "[-] Please run this script again from a domain-joined system running Windows Server."
    Write-Host "[-] Alternatively, run this script again without the -ActiveDirectory flag."
    Exit
}

if ($EntraID -and $OU -and !$ActiveDirectory) {
    Write-Host "[-] The -OU flag must be paired with the -ActiveDirectory flag." -ForegroundColor Red
    Exit
}

$OutputPath = "$PSScriptRoot\BitLockerKeys.csv"
if (Test-Path -Path "$OutputPath") {
    Write-Host "[-] BitLockerKeys.csv already exists on disk. To avoid data loss, this script will not run until this file is moved or manually deleted first." -ForegroundColor Red
    Exit
}
else {

}

$BitLockerKeys = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

if ($ActiveDirectory) {
    Write-Host "[+] Obtaining BitLocker recovery keys from Active Directory"
    Install-MicrosoftADTools -ProductType $ProductType
    Get-ADBitLockerKeys -BitLockerKeys $BitLockerKeys -OU $OU
}

if ($EntraID) {
    Write-Host "[+] Obtaining BitLocker recovery keys from Entra ID"
    Install-MicrosoftGraphCmdlets
    Get-EntraIDBitLockerKeys -BitLockerKeys $BitLockerKeys
}

if ($null -ne $BitLockerKeys) {
    Write-Host "[+] See the list of computers that had a recovery key in $($OutputPath)" -ForegroundColor Green    
    $BitLockerKeys | Select-Object Hostname, KeyID, RecoveryKey, Directory | Export-Csv "$OutputPath" -NoTypeInformation -ErrorAction Stop -Append
}

else {
    Write-Warning "[-] No results. Could not find any computers with BitLocker keys."
} 

Write-Host "[+] Done!" -ForegroundColor Green

# SIG # Begin signature block
# MIIuwwYJKoZIhvcNAQcCoIIutDCCLrACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAQZvE03fFolohT
# 8Y2YYj8KOuJKB2h6OMszM/IO+CO686CCE68wggWNMIIEdaADAgECAhAOmxiO+dAt
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
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBrzrh1qiWYqtCCvJcWq+vF
# Tjygv7ZtyT7qku1o0kpIvTANBgkqhkiG9w0BAQEFAASCAgB6p+yntYqmzQGKBDFn
# sXK4j61OkduCkmHUyY8j5IstHdbLnXvh5MKdOYDNzaTJ76rTVSgnhhOOdb3h4EVE
# v8ZHTR/L1jR2lIi9cJOoo9p/e6qh6yB7cjKQmUC69/RqM+gOB0JbJj1rASVeq8Gu
# ZOOPj0pjfUvDkdNhMspN1P2M76ZF/Dwb2LuyPxlGyQa1OkdeMbiyTLS1e0LkIrYT
# jyujri9chrBfKpRDT+U0xR3DL+B4RbTme2Ubvro8508n2f+3qJrueAWXvGeUoFw0
# QFPL07kzoAJY67zxdbdRegj+Y8Q4Eo1ktGcdCJxM4s3FrW8bA57b9VTKpPqE1PyZ
# rMVP8HEYq9DwCvgpBpLK9HZ+5Yuuw6Cyaz6O++ptj0xE9IqSa0Y+QY7ji0nhaddj
# jYHa6xsdm8aLSdKYEHuJSpGt3CAOD83s0KivTzAp/byXHXuCQ3qxlWQfyV4e8j+m
# mdBe5EzsJ517vRmxlbIr6zq2d3Mn6CPW6Gl4R3NeCZGuo0PKOqNLQ4yuCy4zAn+Q
# s/kflCpWk5ezeTPugq/kkloa2pQcQMDwp2mHxMygu6X+0CY46FVeV7fW3ONYwQbl
# tNrQqYPGqg5LafBL1SMJpj2CiIQvpo4d6aRpxG83AgXYu6KVqeBCwWJV2VHF0FTv
# lHgiyJJD5WBocPx6OdfO2aC80aGCF0Awghc8BgorBgEEAYI3AwMBMYIXLDCCFygG
# CSqGSIb3DQEHAqCCFxkwghcVAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcN
# AQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCB8VjaX
# U0ZHZIqDTDTL80+TEs3MmfSz9b8TSUDEYrW91QIRAMlIw6hh/cjzsXVBsbvGUa4Y
# DzIwMjQwNzI2MDA0OTMzWqCCEwkwggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f
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
# MjQwNzI2MDA0OTMzWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBRm8CsywsLJD4Jd
# zqqKycZPGZzPQDAvBgkqhkiG9w0BCQQxIgQg45yZUHCxZeGGMjO1nr+Nw6ZMdnt+
# aIrYC1HfsHrHD0gwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQg0vbkbe10IszR1EBX
# aEE2b4KK2lWarjMWr00amtQMeCgwDQYJKoZIhvcNAQEBBQAEggIAXfwdFCdXCHQb
# 3lb81ul+a8nBq6EOKchVUqmenYlYqmQku8WsHrc3oARRsQowxNyX27IY7eKrpGX5
# zNdlvK/w3MTWNR9TZDGBe76JpqNY7Wsg4JAmFf3qO0v4qVrShoKc9u8LL3ZdxYv6
# 6IdZUY3lNX6taoQxvkJzdsKGTP9Jzy/5RFsvr3lSY6L15cSF/KmgoRHOLGLoojoX
# etqpv+Ubldxqju61sgrEhm431iUrLvkOiPfrfRF2lPnW0SN6VXFGmupurlHjdCW4
# /RhUE7Mbjs/7QOziHjZo4KXXXBEbcj3SlLGXK9jGdjTYqfh+qxQksA5dWYemVPnc
# NH5CNPRy6JQGg8/p+VX5zXhj3YVbqPPTuPvfcRsPOMuK1pjmOo9qQ/ue+pS3qyk8
# ilb8/F8FCccKGn7EtZqC6VOkxwsPHiXQMZDvaatQYXIfqvFMImvMnn6YsZMqXd7S
# Q44+p43xZcy2pHCIsNQxM2DcSwGu7cM0OsSmdTbNaxMNKlJpaKpZjidWVbR377Fd
# q4sh4resiHgkw0gKVimWd9z17/3KdKuVu78auXX9eraikSb27sABbKY5XSSgQFrw
# L60GgCnOFCJPLYtv6//5AdIwppFISSbQWQ0bU42Djwbak9EvY48OBxZdyUtXQY0U
# DxJ/+mIOd1fOZDS6m07omSUq3Fjl4cA=
# SIG # End signature block
