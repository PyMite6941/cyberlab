@echo off
rem cyberterminal - Windows wrapper
rem Prefers the single-file binary in dist/ if present, falls back to the venv.
set ROOT_DIR=%~dp0
set BINARY=%ROOT_DIR%dist\cyberterminal.exe
set VENV_PY=%ROOT_DIR%.venv\Scripts\python.exe

if exist "%BINARY%" (
    "%BINARY%" %*
    exit /b %ERRORLEVEL%
)

if not exist "%VENV_PY%" (
    echo No dist\cyberterminal.exe and .venv not found. Run install.bat first.
    exit /b 1
)

"%VENV_PY%" -m src.terminal %*