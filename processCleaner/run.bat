@echo off
chcp 65001 >nul
cd /d "%~dp0"
py process_cleaner.py
pause
