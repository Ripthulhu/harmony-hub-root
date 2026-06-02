@echo off
setlocal
cd /d "%~dp0"

where pwsh >nul 2>nul
if %errorlevel%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_xmpp_root_shell.ps1" -PauseOnExit
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_xmpp_root_shell.ps1" -PauseOnExit
)
