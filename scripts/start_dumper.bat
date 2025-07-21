@echo off
chcp 65001 > nul
title PE Dumper Interactive v2.0
color 0B
cls

echo 🔍 PE Dumper Interactive v2.0
echo ==============================
echo.

REM Go to project root
cd /d "%~dp0\.."

REM Check if virtual environment exists
if not exist "venv" (
    echo ❌ Sanal ortam bulunamadı!
    echo 💡 Lütfen önce install.bat çalıştırın:
    echo    install.bat
    echo.
    pause
    exit /b 1
)

REM Activate virtual environment
echo 🔧 Sanal ortam aktifleştiriliyor...
call venv\Scripts\activate.bat

REM Check dependencies
echo 📦 Bağımlılıklar kontrol ediliyor...
python -c "import customtkinter, tkinter" >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Eksik bağımlılıklar!
    echo 💡 Gerekli paketler yükleniyor...
    pip install customtkinter --quiet
)

REM Launch interactive dumper
echo 🚀 PE Dumper Interactive başlatılıyor...
echo.
echo 📝 KULLANIM TALİMATLARI:
echo    1. Hedef .exe dosyasını seçin
echo    2. Çıktı klasörünü belirleyin
echo    3. "Launch Target Executable" butonuna tıklayın
echo    4. Authentication key'inizi girin
echo    5. "Key Unlocked - Start Dumping" butonuna tıklayın
echo.

python core\interactive_dumper.py

echo.
echo 👋 PE Dumper Interactive kapatıldı.
pause