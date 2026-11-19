@echo off
rem Launcher for Windows. The *-windows-x64.zip bundle has its own Java (dooh-security-scanner.exe); the portable zip needs Java 17+.
cd /d "%~dp0"
if exist dooh-security-scanner.exe (
  dooh-security-scanner.exe %*
  exit /b %errorlevel%
)
where java >nul 2>nul
if errorlevel 1 (
  echo Java 17 or newer is required. Install it from https://adoptium.net and try again.
  exit /b 1
)
java -jar dooh-security-scanner.jar %*
