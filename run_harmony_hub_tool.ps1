param(
    [ValidateSet("", "lan-root", "enable-xmpp", "usb-preflight", "usb-sysinfo", "usb-hub-id", "usb-wifi-status", "usb-wifi-scan", "usb-provision-wifi", "usb-factory-reset", "usb-flash-firmware")]
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
    [switch]$IgnoreSavedHubId,
    [switch]$UseGlobalSavedHubId,
    [switch]$ClearSavedHubId,
    [switch]$DryRun,

    [string]$Ssid = "",
    [string]$WifiPassword = "",
    [string]$Encryption = "WPA2-PSK",
    [switch]$NoSave,
    [switch]$ShowSsids,
    [switch]$HideSsids,
    [switch]$RawOutput,
    [switch]$SaveHubId,
    [switch]$WaitForLan,
    [int]$LanPort = 8088,
    [int]$LanWaitSeconds = 90,
    [string]$FirmwareFile = "",
    [int]$FirmwarePacketsPerChunk = 500,
    [ValidateSet("auto", "hidapi", "hidraw", "winhid")]
    [string]$UsbBackend = "auto",
    [switch]$Yes,
    [switch]$Force,

    [switch]$PauseOnExit
)

$ErrorActionPreference = "Stop"

function Get-PythonInvocation {
    $venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPython) {
        return [pscustomobject]@{ Exe = $venvPython; Args = @() }
    }

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return [pscustomobject]@{ Exe = "py"; Args = @("-3") }
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return [pscustomobject]@{ Exe = "python"; Args = @() }
    }

    throw "Python 3 was not found. Install Python 3 or create .venv\Scripts\python.exe next to this launcher."
}

function Add-Arg {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Name,
        [string]$Value
    )
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        $List.Add($Name)
        $List.Add($Value)
    }
}

try {
    $tool = Join-Path $PSScriptRoot "run_harmony_hub_tool.py"
    if (-not (Test-Path -LiteralPath $tool)) {
        throw "run_harmony_hub_tool.py was not found next to this launcher."
    }

    $python = Get-PythonInvocation
    $toolArgs = [System.Collections.Generic.List[string]]::new()
    foreach ($arg in $python.Args) { $toolArgs.Add($arg) }
    $toolArgs.Add($tool)

    Add-Arg $toolArgs "--action" $Action
    Add-Arg $toolArgs "--hub-host" $HubHost
    Add-Arg $toolArgs "--hub-ip" $HubIp
    foreach ($id in @($HubId)) { Add-Arg $toolArgs "--hub-id" $id }
    Add-Arg $toolArgs "--private-key" $PrivateKey
    Add-Arg $toolArgs "--pubkey" $PubKey
    Add-Arg $toolArgs "--dropbearmulti" $Dropbearmulti
    if ($XmppEnableWait -ne 90) { Add-Arg $toolArgs "--xmpp-enable-wait" ([string]$XmppEnableWait) }
    if ($NoEnableXmpp) { $toolArgs.Add("--no-enable-xmpp") }
    if ($NoShell) { $toolArgs.Add("--no-shell") }
    if ($IgnoreSavedHubId) { $toolArgs.Add("--ignore-saved-hub-id") }
    if ($UseGlobalSavedHubId) { $toolArgs.Add("--use-global-saved-hub-id") }
    if ($ClearSavedHubId) { $toolArgs.Add("--clear-saved-hub-id") }
    if ($DryRun) { $toolArgs.Add("--dry-run") }

    Add-Arg $toolArgs "--usb-backend" $UsbBackend
    Add-Arg $toolArgs "--ssid" $Ssid
    if (-not [string]::IsNullOrEmpty($WifiPassword)) { Add-Arg $toolArgs "--wifi-password" $WifiPassword }
    Add-Arg $toolArgs "--encryption" $Encryption
    if ($NoSave) { $toolArgs.Add("--no-save") }
    if ($ShowSsids) { $toolArgs.Add("--show-ssids") }
    if ($HideSsids) { $toolArgs.Add("--hide-ssids") }
    if ($RawOutput) { $toolArgs.Add("--raw-output") }
    if ($SaveHubId) { $toolArgs.Add("--save-hub-id") }
    if ($WaitForLan) { $toolArgs.Add("--wait-for-lan") }
    if ($LanPort -ne 8088) { Add-Arg $toolArgs "--lan-port" ([string]$LanPort) }
    if ($LanWaitSeconds -ne 90) { Add-Arg $toolArgs "--lan-wait-seconds" ([string]$LanWaitSeconds) }
    Add-Arg $toolArgs "--firmware-file" $FirmwareFile
    if ($FirmwarePacketsPerChunk -ne 500) { Add-Arg $toolArgs "--firmware-packets-per-chunk" ([string]$FirmwarePacketsPerChunk) }
    if ($Yes) { $toolArgs.Add("--yes") }
    if ($Force) { $toolArgs.Add("--force") }

    & $python.Exe @toolArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Tool exited with code $LASTEXITCODE."
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
