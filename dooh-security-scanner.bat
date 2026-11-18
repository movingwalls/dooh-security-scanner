@echo off
rem Pass-through launcher, e.g.  dooh-security-scanner.bat -h 203.0.113.10
cd /d "%~dp0"
call dooh-scan.bat %*
