@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Necesitas instalar Node.js: https://nodejs.org
  pause
  exit /b
)
start "" http://localhost:3000
node server.js
