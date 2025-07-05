@echo off
chcp 65001 > nul
title PE Dumper - Başlatma Scripti
color 0A

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                            PE DUMPER v1.0.0                                 ║
echo ║                     Windows Executable Analiz Aracı                         ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

echo [INFO] Python kurulumu kontrol ediliyor...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [HATA] Python bulunamadı! Lütfen Python 3.7+ kurun.
    echo        https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [INFO] Sanal ortam oluşturuluyor...
if not exist "venv" (
    python -m venv venv
    echo [INFO] Sanal ortam oluşturuldu.
) else (
    echo [INFO] Sanal ortam zaten mevcut.
)

echo [INFO] Sanal ortam aktifleştiriliyor...
call venv\Scripts\activate.bat

echo [INFO] Gerekli kütüphaneler yükleniyor...
pip install -r requirements.txt --quiet

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              KULLANIM KILAVUZU                              ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo Bu araç Windows .exe dosyalarını analiz eder ve içeriğini çıkarır.
echo.
echo NASIL KULLANILIR:
echo 1. Analiz etmek istediğiniz .exe dosyasının tam yolunu girin
echo 2. Eğer dosya şifreli ise, şifreyi girin
echo 3. Çıkarılan dosyalar masaüstünde 'extracted_TARIH_SAAT' klasöründe olacak
echo.
echo ÖRNEKLER:
echo   C:\Users\Kullanici\Desktop\program.exe
echo   D:\Indirilenler\uygulama.exe
echo   "C:\Program Files\MyApp\app.exe"  (boşluk varsa tırnak kullanın)
echo.
echo ÇIKTI KLASÖRLERİ:
echo   source_code/    - Kaynak kodlar ve kaynaklar
echo   drivers/        - Sürücü dosyaları
echo   certificates/   - Dijital sertifikalar
echo   dumps/          - Ham veriler ve orijinal dosya
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                            DOSYA YOLU GİRİNİZ                               ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

:input_loop
set /p "exe_path=Analiz edilecek .exe dosyasının tam yolunu girin: "

if "%exe_path%"=="" (
    echo [HATA] Dosya yolu boş olamaz!
    goto input_loop
)

if not exist "%exe_path%" (
    echo [HATA] Dosya bulunamadı: %exe_path%
    echo        Dosya yolunu kontrol edin ve tekrar deneyin.
    goto input_loop
)

echo.
echo [INFO] Dosya analiz ediliyor: %exe_path%
echo [INFO] Lütfen bekleyin...
echo.

python main.py "%exe_path%" --verbose

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                             İŞLEM TAMAMLANDI                               ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo Çıkarılan dosyalar masaüstünüzdeki 'extracted_TARIH_SAAT' klasöründe.
echo.
echo Başka bir dosya analiz etmek ister misiniz? (E/H)
set /p "again=Seçiminiz: "

if /i "%again%"=="E" (
    echo.
    goto input_loop
)

echo.
echo Teşekkürler! Programdan çıkılıyor...
timeout /t 3 /nobreak >nul