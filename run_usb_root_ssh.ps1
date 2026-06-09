param(
    [ValidateSet("", "root-ssh", "preflight", "sysinfo", "wifi-status", "wifi-scan", "wifi-connect", "provision-wifi")]
    [string]$Action = "",

    [string]$HubIp = "",
    [string]$PublicKeyFile = "",
    [string]$PrivateKeyFile = "",

    [string]$Ssid = "",
    [string]$WifiPassword = "",
    [string]$Encryption = "WPA2-PSK",
    [switch]$NoSave,
    [switch]$ShowSsids,
    [switch]$WaitForLan,
    [int]$LanPort = 8088,
    [int]$LanWaitSeconds = 90
)

$ErrorActionPreference = "Stop"
Set-ExecutionPolicy -Scope Process Bypass -Force | Out-Null

function Read-PlainSecret {
    param([string]$Prompt)
    $secure = Read-Host $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Read-ActionChoice {
    Write-Host ""
    Write-Host "Harmony Hub USB Tool"
    Write-Host "1. Install root SSH"
    Write-Host "2. USB preflight"
    Write-Host "3. USB sysinfo"
    Write-Host "4. Wi-Fi status over USB"
    Write-Host "5. Wi-Fi scan over USB"
    Write-Host "6. Provision Wi-Fi over USB"
    Write-Host ""

    while ($true) {
        $choice = Read-Host "Choose an action [1-6]"
        switch ($choice.Trim()) {
            "1" { return "root-ssh" }
            "2" { return "preflight" }
            "3" { return "sysinfo" }
            "4" { return "wifi-status" }
            "5" { return "wifi-scan" }
            "6" { return "provision-wifi" }
            default { Write-Host "Enter a number from 1 to 6." }
        }
    }
}

$here = Split-Path -Parent $PSCommandPath
$tool = Join-Path $here "harmony_usb_root_ssh.ps1"
if (-not (Test-Path -LiteralPath $tool)) {
    throw "Missing tool script: $tool"
}

if ([string]::IsNullOrWhiteSpace($Action)) {
    $Action = Read-ActionChoice
}

if ($Action -eq "root-ssh" -and [string]::IsNullOrWhiteSpace($HubIp)) {
    $HubIp = Read-Host "Harmony Hub IP for optional SSH verification (leave blank to skip)"
}

if ($Action -eq "wifi-scan" -and -not $ShowSsids) {
    $answer = Read-Host "Show SSIDs in scan output? [y/N]"
    if ($answer.Trim().ToLowerInvariant() -in @("y", "yes")) {
        $ShowSsids = $true
    }
}

$wifiConnectActions = @("wifi-connect", "provision-wifi")
if ($Action -in $wifiConnectActions) {
    if ([string]::IsNullOrWhiteSpace($Ssid)) {
        $Ssid = Read-Host "Wi-Fi SSID"
    }
    if ([string]::IsNullOrWhiteSpace($Encryption)) {
        $Encryption = "WPA2-PSK"
    }
    if ($Encryption.ToUpperInvariant() -notin @("NONE", "OPEN") -and [string]::IsNullOrEmpty($WifiPassword)) {
        $WifiPassword = Read-PlainSecret "Wi-Fi password"
    }
    if (-not $WaitForLan) {
        $answer = Read-Host "Wait for LAN reachability after provisioning? [y/N]"
        if ($answer.Trim().ToLowerInvariant() -in @("y", "yes")) {
            $WaitForLan = $true
        }
    }
    if ($WaitForLan -and [string]::IsNullOrWhiteSpace($HubIp)) {
        $HubIp = Read-Host "Expected hub IP for LAN check"
    }
}

$args = @(
    "-Action", $Action,
    "-PackageRoot", "."
)

if (-not [string]::IsNullOrWhiteSpace($HubIp)) {
    $args += @("-HubIp", $HubIp)
}
if (-not [string]::IsNullOrWhiteSpace($PublicKeyFile)) {
    $args += @("-PublicKeyFile", $PublicKeyFile)
}
if (-not [string]::IsNullOrWhiteSpace($PrivateKeyFile)) {
    $args += @("-PrivateKeyFile", $PrivateKeyFile)
}
if (-not [string]::IsNullOrWhiteSpace($Ssid)) {
    $args += @("-Ssid", $Ssid)
}
if (-not [string]::IsNullOrEmpty($WifiPassword)) {
    $args += @("-WifiPassword", $WifiPassword)
}
if (-not [string]::IsNullOrWhiteSpace($Encryption)) {
    $args += @("-Encryption", $Encryption)
}
if ($NoSave) {
    $args += "-NoSave"
}
if ($ShowSsids) {
    $args += "-ShowSsids"
}
if ($WaitForLan) {
    $args += @("-WaitForLan", "-LanPort", $LanPort, "-LanWaitSeconds", $LanWaitSeconds)
}

Push-Location $here
try {
    & $tool @args
} finally {
    Pop-Location
}
