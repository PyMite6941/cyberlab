@echo off
rem cyberterminal - Windows wrapper
if not exist ".venv\Scripts\python.exe" (
    echo .venv not found. Run install.bat first.
    exit /b 1
)
.venv\Scripts\python.exe -m cyberlab.terminal %*
