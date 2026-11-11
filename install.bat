@echo off
rem v2 is standard-library only; no project installation is required on Windows.
python --version
if errorlevel 1 exit /b 1
echo Use cyberlab.bat list to run the v2 CLI.
echo Target hosting is supported on Linux Mint; see README.md.
