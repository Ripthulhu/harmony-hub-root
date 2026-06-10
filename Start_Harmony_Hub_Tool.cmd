@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "TOOL=%SCRIPT_DIR%run_harmony_hub_tool.py"

if not exist "%TOOL%" (
  echo ERROR: run_harmony_hub_tool.py was not found next to this launcher.
  echo Expected: "%TOOL%"
  echo.
  pause
  exit /b 1
)

set "PYTHON_EXE="
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" set "PYTHON_EXE=%SCRIPT_DIR%.venv\Scripts\python.exe"

if not defined PYTHON_EXE (
  where py.exe >nul 2>nul
  if %ERRORLEVEL% EQU 0 (
    py.exe -3 "%TOOL%" %*
    set "EXITCODE=%ERRORLEVEL%"
    goto :done
  )
)

if not defined PYTHON_EXE (
  where python.exe >nul 2>nul
  if %ERRORLEVEL% EQU 0 set "PYTHON_EXE=python.exe"
)

if not defined PYTHON_EXE (
  echo ERROR: Python 3 was not found.
  echo Install Python 3 or create .venv\Scripts\python.exe next to this launcher.
  echo.
  pause
  exit /b 1
)

"%PYTHON_EXE%" "%TOOL%" %*
set "EXITCODE=%ERRORLEVEL%"

:done
echo.
if not "%EXITCODE%"=="0" echo Tool exited with code %EXITCODE%.
if not "%HARMONY_NO_PAUSE%"=="1" pause
exit /b %EXITCODE%
