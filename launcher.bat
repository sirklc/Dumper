@echo off
cd /d "%~dp0"
call venv\Scripts\activate.bat
python core\interactive_dumper.py
pause