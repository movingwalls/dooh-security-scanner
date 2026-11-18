@echo off
rem Launcher for Windows (needs Java 17+; the *-windows.zip bundle does not - use dooh-security-scanner.exe).
cd /d "%~dp0"
where java >nul 2>nul
if errorlevel 1 (
  echo Java 17 or newer is required. Install it from https://adoptium.net and try again.
  exit /b 1
)
java -jar dooh-security-scanner.jar %*
