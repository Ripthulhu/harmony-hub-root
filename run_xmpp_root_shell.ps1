param(
  [string]$HubHost,
  [string]$PrivateKey,
  [string]$PubKey,
  [string]$Dropbearmulti,
  [string[]]$HubId,
  [int]$XmppEnableWait = 90,
  [switch]$NoEnableXmpp,
  [switch]$EnableXmppOnly,
  [switch]$NoShell,
  [switch]$DryRun,
  [switch]$PauseOnExit
)

$ErrorActionPreference = "Stop"

try {
  if (-not $HubHost -and -not $DryRun) {
    $HubHost = Read-Host "Harmony Hub IP address"
  }
  if (-not $Dropbearmulti) {
    $Dropbearmulti = Join-Path $PSScriptRoot "dropbearmulti"
  }
  if (-not $PrivateKey) {
    $PrivateKey = Join-Path $env:USERPROFILE ".ssh\harmony_owner_ed25519"
  }
  if (-not $PubKey) {
    $PubKey = "$PrivateKey.pub"
  }

  if (-not (Test-Path -LiteralPath $Dropbearmulti)) {
    throw "dropbearmulti not found: $Dropbearmulti"
  }

  $python = Get-Command py -ErrorAction SilentlyContinue
  if ($python) {
    $exe = "py"
    $pyArgs = @("-3")
  } else {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
      $exe = "python"
      $pyArgs = @()
    } else {
      $bundledPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
      if (Test-Path -LiteralPath $bundledPython) {
        $exe = $bundledPython
        $pyArgs = @()
      } else {
        throw "Python was not found. Install Python 3.10+ or run from Codex with its bundled Python runtime."
      }
    }
  }

  $script = Join-Path $PSScriptRoot "harmony_xmpp_root_shell.py"
  $args = $pyArgs + @(
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

  Write-Host "Running Harmony Hub LAN root shell installer..."
  & $exe @args
  $exitCode = $LASTEXITCODE
  if ($exitCode -ne 0) {
    throw "Installer exited with code $exitCode."
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
