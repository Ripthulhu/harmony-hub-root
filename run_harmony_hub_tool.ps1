# Optional launcher. All options belong to the cross-platform Python CLI.
$ErrorActionPreference = 'Stop'
$tool = Join-Path $PSScriptRoot 'run_harmony_hub_tool.py'
$venv = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
try {
    if (Test-Path -LiteralPath $venv) {
        & $venv $tool @args
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 $tool @args
    } elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
        & python3 $tool @args
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python $tool @args
    } else {
        throw 'Python 3.10 or newer is required.'
    }
    exit $LASTEXITCODE
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
