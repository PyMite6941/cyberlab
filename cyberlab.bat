@echo off
rem cyberlab - activate and run the cyberterminal environment
rem Usage: cyberlab.bat              # auto-detect binary or python mode
rem        cyberlab.bat --binary     # force the single-file dist/ binary
rem        cyberlab.bat --python     # force the venv + source files
rem        cyberlab.bat --install    # run install.py setup first

setlocal EnableDelayedExpansion
set ROOT_DIR=%~dp0
cd /d "%ROOT_DIR%"

set BINARY=dist\cyberterminal.exe
set VENV_PY=.venv\Scripts\python.exe
set MODE=auto

:parse
if "%~1"=="" goto launch
if "%~1"=="--binary" set MODE=binary & shift & goto parse
if "%~1"=="--python" set MODE=python & shift & goto parse
if "%~1"=="--install" (
    python install.py %*
    echo Install complete. Re-run: cyberlab.bat
    exit /b 0
)
if "%~1"=="--help" (
    echo Usage: cyberlab.bat [--binary|--python|--install]
    echo   --binary  Force the single-file dist\cyberterminal.exe (no Python needed)
    echo   --python  Force the venv + source files (Python required)
    echo   --install Run install.py setup before launching
    echo   (auto)    Use dist\cyberterminal.exe if present, else venv python
    exit /b 0
)
shift & goto parse

:launch
if "%MODE%"=="auto" (
    if exist "%BINARY%" (set MODE=binary) else (set MODE=python)
)

if "%MODE%"=="binary" (
    if not exist "%BINARY%" (
        echo No dist\cyberterminal.exe found.
        echo Run:  cyberlab.bat --install
        exit /b 1
    )
    "%BINARY%" %*
    exit /b %ERRORLEVEL%
) else (
    if not exist "%VENV_PY%" (
        echo .venv not found. Run: cyberlab.bat --install
        exit /b 1
    )
    "%VENV_PY%" -m src.terminal %*
    exit /b %ERRORLEVEL%
)
