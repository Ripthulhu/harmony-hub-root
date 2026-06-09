@echo off
setlocal
set "SCRIPT=%~dp0run_harmony_hub_tool.ps1"
where pwsh.exe >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -PauseOnExit %*
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -PauseOnExit %*
)
set "EXITCODE=%ERRORLEVEL%"
echo.
if not "%EXITCODE%"=="0" echo Tool exited with code %EXITCODE%.
exit /b %EXITCODE%
