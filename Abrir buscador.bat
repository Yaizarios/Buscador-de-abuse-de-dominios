@echo off
cd /d "%~dp0"
set NODE=node
if exist "%~dp0node\node.exe" set NODE="%~dp0node\node.exe"
%NODE% -v >nul 2>nul
if errorlevel 1 (
  echo No se encuentra Node.js. Descargalo en https://nodejs.org o usa el zip con node incluido.
  pause
  exit /b
)
start "" http://localhost:3000
%NODE% server.js
