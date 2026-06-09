param(
    [ValidateSet("", "lan-root", "enable-xmpp", "usb-preflight", "usb-sysinfo", "usb-wifi-status", "usb-wifi-scan", "usb-provision-wifi", "usb-root-ssh", "usb-factory-reset", "usb-flash-firmware")]
    [string]$Action = "",

    [string]$HubHost = "",
    [string]$HubIp = "",
    [string[]]$HubId = @(),

    [string]$PrivateKey = "",
    [string]$PubKey = "",
    [string]$Dropbearmulti = "",
    [int]$XmppEnableWait = 90,
    [switch]$NoEnableXmpp,
    [switch]$NoShell,
    [switch]$DryRun,

    [string]$PublicKeyFile = "",
    [string]$PrivateKeyFile = "",
    [string]$Ssid = "",
    [string]$WifiPassword = "",
    [string]$Encryption = "WPA2-PSK",
    [switch]$NoSave,
    [switch]$ShowSsids,
    [switch]$WaitForLan,
    [int]$LanPort = 8088,
    [int]$LanWaitSeconds = 90,
    [string]$FirmwareFile = "",
    [int]$TargetSkin = 0,
    [int]$FirmwarePacketsPerChunk = 500,
    [switch]$Yes,
    [switch]$Force,
    [ValidateSet("auto", "native", "python", "hidapi", "hidraw", "winhid")]
    [string]$UsbBackend = "auto",

    [switch]$PauseOnExit
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

function Read-ToolAction {
    Write-Host ""
    Write-Host "Harmony Hub Tool"
    Write-Host "1. LAN root SSH install"
    Write-Host "2. Enable XMPP over LAN"
    Write-Host "3. USB preflight"
    Write-Host "4. USB sysinfo"
    Write-Host "5. Wi-Fi status over USB"
    Write-Host "6. Wi-Fi scan over USB"
    Write-Host "7. Provision Wi-Fi over USB"
    Write-Host "8. USB root SSH install"
    Write-Host "9. Factory reset over USB"
    Write-Host "10. Flash firmware over USB (.hfw2)"
    Write-Host ""

    while ($true) {
        $choice = Read-Host "Choose an action [1-10]"
        switch ($choice.Trim()) {
            "1" { return "lan-root" }
            "2" { return "enable-xmpp" }
            "3" { return "usb-preflight" }
            "4" { return "usb-sysinfo" }
            "5" { return "usb-wifi-status" }
            "6" { return "usb-wifi-scan" }
            "7" { return "usb-provision-wifi" }
            "8" { return "usb-root-ssh" }
            "9" { return "usb-factory-reset" }
            "10" { return "usb-flash-firmware" }
            default { Write-Host "Enter a number from 1 to 10." }
        }
    }
}

function Resolve-HostAlias {
    if ([string]::IsNullOrWhiteSpace($HubHost) -and -not [string]::IsNullOrWhiteSpace($HubIp)) {
        $script:HubHost = $HubIp
    }
    if ([string]::IsNullOrWhiteSpace($HubIp) -and -not [string]::IsNullOrWhiteSpace($HubHost)) {
        $script:HubIp = $HubHost
    }
}

function Get-PythonInvocation {
    $python = Get-Command py -ErrorAction SilentlyContinue
    if ($python) {
        return [pscustomobject]@{ Exe = "py"; Args = @("-3") }
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return [pscustomobject]@{ Exe = "python"; Args = @() }
    }

    $bundledPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
    if (Test-Path -LiteralPath $bundledPython) {
        return [pscustomobject]@{ Exe = $bundledPython; Args = @() }
    }

    throw "Python was not found. Install Python 3.10+ or run from Codex with its bundled Python runtime."
}

function Invoke-LanAction {
    param([bool]$EnableXmppOnly)

    if (-not $HubHost -and -not $DryRun) {
        $script:HubHost = Read-Host "Harmony Hub IP address"
    }

    if (-not $Dropbearmulti) {
        $script:Dropbearmulti = Join-Path $PSScriptRoot "dropbearmulti"
    }
    if (-not $PrivateKey) {
        $script:PrivateKey = Join-Path $env:USERPROFILE ".ssh\harmony_owner_ed25519"
    }
    if (-not $PubKey) {
        $script:PubKey = "$PrivateKey.pub"
    }

    if (-not $EnableXmppOnly -and -not (Test-Path -LiteralPath $Dropbearmulti)) {
        throw "dropbearmulti not found: $Dropbearmulti"
    }

    $python = Get-PythonInvocation
    $script = Join-Path $PSScriptRoot "harmony_xmpp_root_shell.py"
    $args = $python.Args + @(
        $script,
        "--dropbearmulti", $Dropbearmulti,
        "--private-key", $PrivateKey,
        "--pubkey", $PubKey
    )

    if ($HubHost) {
        $args += @("--host", $HubHost)
    }
    foreach ($id in @($HubId)) {
        if ($id) {
            $args += @("--hub-id", $id)
        }
    }
    if ($XmppEnableWait -ne 90) {
        $args += @("--xmpp-enable-wait", [string]$XmppEnableWait)
    }
    if ($NoEnableXmpp) {
        $args += "--no-enable-xmpp"
    }
    if ($EnableXmppOnly) {
        $args += "--enable-xmpp-only"
    }
    if ($NoShell) {
        $args += "--no-shell"
    }
    if ($DryRun) {
        $args += "--dry-run"
    }

    if ($EnableXmppOnly) {
        Write-Host "Running Harmony Hub XMPP enable flow..."
    } else {
        Write-Host "Running Harmony Hub LAN root SSH flow..."
    }
    & $python.Exe @args
    if ($LASTEXITCODE -ne 0) {
        throw "LAN action exited with code $LASTEXITCODE."
    }
}

function Invoke-UsbAction {
    param([string]$UsbAction)

    $requiresPythonBackend = $UsbAction -in @("factory-reset", "flash-firmware")
    $python = Get-PythonInvocation
    $tool = Join-Path $PSScriptRoot "harmony_usb_bridge.py"
    if (-not (Test-Path -LiteralPath $tool)) {
        throw "Missing Python USB bridge script: $tool"
    }

    $backend = if ($UsbBackend -in @("python", "native")) { "auto" } else { $UsbBackend }
    $args = [System.Collections.Generic.List[string]]::new()
    foreach ($arg in $python.Args) {
        $args.Add($arg)
    }
    $args.Add($tool)
    $args.Add("--action")
    $args.Add($UsbAction)
    $args.Add("--package-root")
    $args.Add(".")
    $args.Add("--backend")
    $args.Add($backend)
    if (-not [string]::IsNullOrWhiteSpace($HubIp)) {
        $args.Add("--hub-ip")
        $args.Add($HubIp)
    }
    if (-not [string]::IsNullOrWhiteSpace($PublicKeyFile)) {
        $args.Add("--public-key-file")
        $args.Add($PublicKeyFile)
    }
    if (-not [string]::IsNullOrWhiteSpace($PrivateKeyFile)) {
        $args.Add("--private-key-file")
        $args.Add($PrivateKeyFile)
    }
    if (-not [string]::IsNullOrWhiteSpace($Ssid)) {
        $args.Add("--ssid")
        $args.Add($Ssid)
    }
    if (-not [string]::IsNullOrEmpty($WifiPassword)) {
        $args.Add("--wifi-password")
        $args.Add($WifiPassword)
    }
    if (-not [string]::IsNullOrWhiteSpace($Encryption)) {
        $args.Add("--encryption")
        $args.Add($Encryption)
    }
    if ($NoSave) {
        $args.Add("--no-save")
    }
    if ($ShowSsids) {
        $args.Add("--show-ssids")
    }
    if ($WaitForLan) {
        $args.Add("--wait-for-lan")
        $args.Add("--lan-port")
        $args.Add([string]$LanPort)
        $args.Add("--lan-wait-seconds")
        $args.Add([string]$LanWaitSeconds)
    }
    if (-not [string]::IsNullOrWhiteSpace($FirmwareFile)) {
        $args.Add("--firmware-file")
        $args.Add($FirmwareFile)
    }
    if ($FirmwarePacketsPerChunk -ne 500) {
        $args.Add("--firmware-packets-per-chunk")
        $args.Add([string]$FirmwarePacketsPerChunk)
    }
    if ($Yes) {
        $args.Add("--yes")
    }
    if ($DryRun) {
        $args.Add("--dry-run")
    }

    if ($requiresPythonBackend -and $UsbBackend -eq "native") {
        Write-Host "Running Harmony Hub Python USB bridge action: $UsbAction (required for raw firmware/reset protocol)"
    } else {
        Write-Host "Running Harmony Hub Python USB bridge action: $UsbAction"
    }
    & $python.Exe @args
    if ($LASTEXITCODE -ne 0) {
        throw "USB action exited with code $LASTEXITCODE."
    }
}

try {
    Resolve-HostAlias
    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = Read-ToolAction
    }

    switch ($Action) {
        "lan-root" {
            Resolve-HostAlias
            Invoke-LanAction -EnableXmppOnly:$false
        }
        "enable-xmpp" {
            Resolve-HostAlias
            Invoke-LanAction -EnableXmppOnly:$true
        }
        "usb-preflight" {
            Invoke-UsbAction -UsbAction "preflight"
        }
        "usb-sysinfo" {
            Invoke-UsbAction -UsbAction "sysinfo"
        }
        "usb-wifi-status" {
            Invoke-UsbAction -UsbAction "wifi-status"
        }
        "usb-wifi-scan" {
            if (-not $ShowSsids) {
                $answer = Read-Host "Show SSIDs in scan output? [y/N]"
                if ($answer.Trim().ToLowerInvariant() -in @("y", "yes")) {
                    $ShowSsids = $true
                }
            }
            Invoke-UsbAction -UsbAction "wifi-scan"
        }
        "usb-provision-wifi" {
            Resolve-HostAlias
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
            Invoke-UsbAction -UsbAction "provision-wifi"
        }
        "usb-root-ssh" {
            Resolve-HostAlias
            if ([string]::IsNullOrWhiteSpace($HubIp)) {
                $HubIp = Read-Host "Harmony Hub IP for optional SSH verification (leave blank to skip)"
            }
            Invoke-UsbAction -UsbAction "root-ssh"
        }
        "usb-factory-reset" {
            Invoke-UsbAction -UsbAction "factory-reset"
        }
        "usb-flash-firmware" {
            if ([string]::IsNullOrWhiteSpace($FirmwareFile)) {
                $FirmwareFile = Read-Host "Path to .hfw2 firmware file"
            }
            Invoke-UsbAction -UsbAction "flash-firmware"
        }
    }
} catch {
    Write-Host ""
    Write-Host "ERROR:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
} finally {
    if ($PauseOnExit) {
        Write-Host ""
        Read-Host "Press Enter to close this window"
    }
}
