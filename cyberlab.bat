@echo off
rem v2 CLI launcher. Target hosting is supported on Linux Mint; see README.md.
set "ROOT_DIR=%~dp0"
set "PYTHONPATH=%ROOT_DIR%v2;%PYTHONPATH%"
python -m cyberlab %*
exit /b %ERRORLEVEL%
