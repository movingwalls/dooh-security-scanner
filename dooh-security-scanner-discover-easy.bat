@echo off
rem Double-click launcher: finds devices on your own local network, then scans them.
cd /d "%~dp0"
call dooh-scan.bat --discover
pause
