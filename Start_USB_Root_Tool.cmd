@echo off
setlocal
set "SCRIPT=%~dp0run_usb_root_ssh.ps1"
where pwsh.exe >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
)
set "EXITCODE=%ERRORLEVEL%"
echo.
if not "%EXITCODE%"=="0" echo Tool exited with code %EXITCODE%.
pause
exit /b %EXITCODE%
