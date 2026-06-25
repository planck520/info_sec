@echo off
echo ========================================
echo  FlashBack Offline Installer Build
echo ========================================
echo.

REM Step 1: PyInstaller - Python backend
echo [1/3] Building Python backend...
pip install pyinstaller >nul 2>&1
REM Remove old spec so command-line args take effect (PyInstaller ignores CLI args if .spec exists)
if exist flashback-server.spec del flashback-server.spec
pyinstaller --noconfirm --onedir ^
  --name flashback-server ^
  --add-data "engine;engine" ^
  --add-data "server;server" ^
  --hidden-import uvicorn ^
  --hidden-import fastapi ^
  --hidden-import starlette ^
  --hidden-import requests ^
  --hidden-import pydantic ^
  --hidden-import websockets ^
  --hidden-import anyio ^
  --hidden-import h11 ^
  --hidden-import httpcore ^
  --hidden-import colorama ^
  --hidden-import sqlite3 ^
  --hidden-import engine.config_manager ^
  --hidden-import engine.ida_detector ^
  --hidden-import engine.llm_service ^
  --hidden-import engine.orchestrator ^
  --hidden-import server.routes.scan ^
  --hidden-import server.routes.results ^
  --hidden-import server.routes.settings ^
  --hidden-import server.routes.llm ^
  --hidden-import server.routes.history ^
  --hidden-import server.websocket ^
  main.py

if %ERRORLEVEL% NEQ 0 (
  echo PyInstaller failed!
  exit /b 1
)
echo   Done: flashback-server.exe

echo.
echo [2/3] Installing electron-builder...
call npm install --save-dev electron-builder >nul 2>&1
IF NOT EXIST node_modules\electron-builder (
  call npm install --save-dev electron-builder
)

echo.
echo [3/3] Building Electron installer...
call npx electron-builder --win --x64

if %ERRORLEVEL% NEQ 0 (
  echo electron-builder failed!
  exit /b 1
)

echo.
echo ========================================
echo  Build complete!
echo  Installer: release\FlashBack Setup *.exe
echo ========================================
