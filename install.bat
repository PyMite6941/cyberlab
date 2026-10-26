@echo off
rem cyberlab install - Windows wrapper
python install.py %*
if errorlevel 1 exit /b 1
