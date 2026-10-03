@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "TOOL=%SCRIPT_DIR%run_harmony_hub_tool.py"

if not exist "%TOOL%" (
  echo ERROR: run_harmony_hub_tool.py was not found next to this launcher.
  echo Expected: "%TOOL%"
  set "EXITCODE=1"
  goto :done
)

set "PYTHON_EXE="
if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" set "PYTHON_EXE=%SCRIPT_DIR%.venv\Scripts\python.exe"

if defined PYTHON_EXE goto :run_python
where py.exe >nul 2>nul
if not errorlevel 1 goto :run_py
where python.exe >nul 2>nul
if not errorlevel 1 (
  set "PYTHON_EXE=python.exe"
  goto :run_python
)
echo ERROR: Python 3.10 or newer was not found. Install Python or create .venv\Scripts\python.exe.
set "EXITCODE=1"
goto :done

:run_python
"%PYTHON_EXE%" "%TOOL%" %*
set "EXITCODE=%ERRORLEVEL%"
goto :done

:run_py
py.exe -3 "%TOOL%" %*
set "EXITCODE=%ERRORLEVEL%"

:done
echo.
if not "%EXITCODE%"=="0" echo Tool exited with code %EXITCODE%.
if "%~1"=="" if not "%HARMONY_NO_PAUSE%"=="1" pause
exit /b %EXITCODE%
