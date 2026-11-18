@echo off
rem Double-click launcher: scans the addresses listed in targets.txt (one per line).
cd /d "%~dp0"
if not exist targets.txt copy targets.example.txt targets.txt >/dev/null & echo Created targets.txt - edit it, then run this again. & notepad targets.txt & pause & exit /b 0
call dooh-scan.bat -t targets.txt
pause
