@echo off
cd /d "%~dp0"
if not exist "venv" (
    echo 🔧 Kurulum gerekli! Otomatik kurulum başlatılıyor...
    call install.bat
)
call venv\Scripts\activate.bat
python core\interactive_dumper.py