@echo off
chcp 65001 > nul
title PE Dumper Interactive - Otomatik Kurulum
color 0A
cls

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                    🔍 PE Dumper Interactive v2.0                           ║
echo ║                           OTOMATIK KURULUM                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

echo [1/4] Python kurulumu kontrol ediliyor...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ❌ Python bulunamadı!
    echo.
    echo 💡 YAPILACAKLAR:
    echo    1. https://www.python.org/downloads/ adresine gidin
    echo    2. Python 3.7 veya üstünü indirin
    echo    3. Kurulum sırasında "Add Python to PATH" seçeneğini işaretleyin
    echo    4. Kurulum bittikten sonra bu dosyayı tekrar çalıştırın
    echo.
    echo Web sitesini açmak için herhangi bir tuşa basın...
    pause >nul
    start https://www.python.org/downloads/
    exit /b 1
) else (
    for /f "tokens=2" %%i in ('python --version') do set PYTHON_VERSION=%%i
    echo ✅ Python !PYTHON_VERSION! bulundu
)

echo.
echo [2/4] Sanal ortam oluşturuluyor...
if exist "venv" (
    echo ⚠️  Mevcut sanal ortam siliniyor...
    rmdir /s /q venv
)

echo Sanal ortam oluşturuluyor... (Bu biraz zaman alabilir)
python -m venv venv
if %errorlevel% neq 0 (
    echo ❌ Sanal ortam oluşturulamadı!
    echo Lütfen Python'u yeniden kurun.
    pause
    exit /b 1
)
echo ✅ Sanal ortam oluşturuldu

echo.
echo [3/4] Sanal ortam aktifleştiriliyor ve bağımlılıklar yükleniyor...
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo ❌ Sanal ortam aktifleştirilemedi!
    pause
    exit /b 1
)

echo Bağımlılıklar yükleniyor... (Bu işlem birkaç dakika sürebilir)
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

if %errorlevel% neq 0 (
    echo ❌ Bağımlılık kurulumu başarısız!
    echo.
    echo 💡 ÇÖZÜM ÖNERİLERİ:
    echo    1. İnternet bağlantınızı kontrol edin
    echo    2. Antivirüs programınızı geçici olarak kapatın
    echo    3. Windows'u yönetici olarak çalıştırın
    echo    4. Bu dosyayı tekrar çalıştırın
    echo.
    pause
    exit /b 1
)
echo ✅ Tüm bağımlılıklar yüklendi

echo.
echo [4/4] Başlatıcılar oluşturuluyor...

REM Create quick launcher
echo @echo off > launcher.bat
echo cd /d "%%~dp0" >> launcher.bat
echo call venv\Scripts\activate.bat >> launcher.bat
echo python core\interactive_dumper.py >> launcher.bat
echo pause >> launcher.bat

REM Create run.bat
echo @echo off > run.bat
echo cd /d "%%~dp0" >> run.bat
echo if not exist "venv" ( >> run.bat
echo     echo 🔧 Kurulum gerekli! Otomatik kurulum başlatılıyor... >> run.bat
echo     call install.bat >> run.bat
echo ) >> run.bat
echo call venv\Scripts\activate.bat >> run.bat
echo python core\interactive_dumper.py >> run.bat

REM Create desktop shortcut
set "DESKTOP=%USERPROFILE%\Desktop"
set "SHORTCUT_PATH=%DESKTOP%\PE Dumper Interactive.lnk"

powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%SHORTCUT_PATH%'); $Shortcut.TargetPath = '%CD%\launcher.bat'; $Shortcut.WorkingDirectory = '%CD%'; $Shortcut.IconLocation = 'shell32.dll,21'; $Shortcut.Description = 'PE Dumper Interactive - Security Testing Tool'; $Shortcut.Save()" 2>nul

if exist "%SHORTCUT_PATH%" (
    echo ✅ Masaüstü kısayolu oluşturuldu
) else (
    echo ⚠️  Masaüstü kısayolu oluşturulamadı
)

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                            🎉 KURULUM TAMAMLANDI!                          ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 📋 KULLANIM SEÇENEKLERİ:
echo    1️⃣  launcher.bat              - Hızlı başlatma
echo    2️⃣  run.bat                   - Tek tıkla çalıştırma  
echo    3️⃣  scripts\start_dumper.bat  - Detaylı başlatma
echo    4️⃣  Masaüstü kısayolu         - GUI'den başlat
echo.
echo 📖 DOKÜMANTASYON: docs\INTERACTIVE_GUIDE.md
echo.
echo ✨ Hazır! PE Dumper Interactive'i çalıştırabilirsiniz.
echo.
echo Herhangi bir tuşa basın...
pause >nul