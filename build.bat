@echo off
rem Keep this file pure ASCII to avoid codepage problems.
cd /d "%~dp0"
python build.py
if errorlevel 1 echo.
pause
