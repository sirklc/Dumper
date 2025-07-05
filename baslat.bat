@echo off
chcp 65001 > nul
title PE Dumper - Otomatik Kurulum ve Çalıştırma
color 0A

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                            PE DUMPER v1.0.0                                 ║
echo ║                     Windows Executable Analiz Aracı                         ║
echo ║                          OTOMATIK KURULUM                                    ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo Bu program otomatik olarak gerekli tüm kurulumları yapacak ve çalışacak.
echo Lütfen sabırla bekleyin...
echo.

echo [1/6] Python kurulumu kontrol ediliyor...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ╔══════════════════════════════════════════════════════════════════════════════╗
    echo ║                                HATA!                                        ║
    echo ╚══════════════════════════════════════════════════════════════════════════════╝
    echo.
    echo Python bulunamadı! Python kurmanız gerekiyor.
    echo.
    echo YAPILACAKLAR:
    echo 1. https://www.python.org/downloads/ adresine gidin
    echo 2. Python 3.7 veya üstünü indirin
    echo 3. Kurulum sırasında "Add Python to PATH" seçeneğini işaretleyin
    echo 4. Kurulum bittikten sonra bu dosyayı tekrar çalıştırın
    echo.
    echo Web sitesini açmak için herhangi bir tuşa basın...
    pause >nul
    start https://www.python.org/downloads/
    exit /b 1
) else (
    for /f "tokens=2" %%i in ('python --version') do set PYTHON_VERSION=%%i
    echo [BAŞARILI] Python !PYTHON_VERSION! bulundu.
)

echo.
echo [2/6] pip güncellemesi yapılıyor...
python -m pip install --upgrade pip --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo [UYARI] pip güncellemesinde sorun oldu, devam ediliyor...
) else (
    echo [BAŞARILI] pip güncellendi.
)

echo.
echo [3/6] Sanal ortam oluşturuluyor...
if not exist "venv" (
    echo Sanal ortam oluşturuluyor... (Bu biraz zaman alabilir)
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [HATA] Sanal ortam oluşturulamadı!
        echo Lütfen Python'u yeniden kurun.
        pause
        exit /b 1
    )
    echo [BAŞARILI] Sanal ortam oluşturuldu.
) else (
    echo [BAŞARILI] Sanal ortam zaten mevcut.
)

echo.
echo [4/6] Sanal ortam aktifleştiriliyor...
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo [HATA] Sanal ortam aktifleştirilemedi!
    pause
    exit /b 1
)
echo [BAŞARILI] Sanal ortam aktifleştirildi.

echo.
echo [5/6] Gerekli kütüphaneler yükleniyor...
echo Bu işlem internet bağlantısı gerektirir ve birkaç dakika sürebilir.
echo Lütfen sabırla bekleyin, program çalışıyor...
echo.

echo Kütüphaneler yükleniyor:
echo - requests (HTTP istekleri için)
pip install requests>=2.31.0 --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo [HATA] requests yüklenemedi!
    goto install_error
)
echo   ✓ requests yüklendi

echo - colorama (renkli çıktı için)
pip install colorama>=0.4.6 --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo [HATA] colorama yüklenemedi!
    goto install_error
)
echo   ✓ colorama yüklendi

echo - pefile (PE dosya analizi için)
pip install pefile>=2023.2.7 --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo [HATA] pefile yüklenemedi!
    goto install_error
)
echo   ✓ pefile yüklendi

echo - python-magic (dosya tipleri için)
pip install python-magic>=0.4.27 --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo [HATA] python-magic yüklenemedi!
    goto install_error
)
echo   ✓ python-magic yüklendi

echo - cryptography (şifreleme için)
pip install cryptography>=41.0.0 --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo [HATA] cryptography yüklenemedi!
    goto install_error
)
echo   ✓ cryptography yüklendi

echo - beautifulsoup4 (HTML parsing için)
pip install beautifulsoup4>=4.12.0 --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo [HATA] beautifulsoup4 yüklenemedi!
    goto install_error
)
echo   ✓ beautifulsoup4 yüklendi

echo - lxml (XML parser için)
pip install lxml>=4.9.0 --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo [HATA] lxml yüklenemedi!
    goto install_error
)
echo   ✓ lxml yüklendi

echo - py7zr (7z dosyaları için)
pip install py7zr>=0.20.6 --quiet --no-warn-script-location
if %errorlevel% neq 0 (
    echo [HATA] py7zr yüklenemedi!
    goto install_error
)
echo   ✓ py7zr yüklendi

echo.
echo [BAŞARILI] Tüm kütüphaneler başarıyla yüklendi!

echo.
echo [6/6] Kurulum tamamlandı! Program başlatılıyor...
echo.
timeout /t 2 /nobreak >nul

goto start_program

:install_error
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                               KURULUM HATASI                                ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo Kütüphane yüklenirken hata oluştu!
echo.
echo OLASI ÇÖZÜMLER:
echo 1. İnternet bağlantınızı kontrol edin
echo 2. Antivirüs programınızı geçici olarak kapatın
echo 3. Windows'u yönetici olarak çalıştırın (sağ tık -> Yönetici olarak çalıştır)
echo 4. Python'u yeniden kurun: https://www.python.org/downloads/
echo.
echo Bu dosyayı tekrar çalıştırmayı deneyin.
echo.
pause
exit /b 1

:start_program
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              KULLANIM KILAVUZU                              ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo ★ TEBRIKLER! Kurulum tamamlandı ve program hazır! ★
echo.
echo Bu araç Windows .exe dosyalarını analiz eder ve içeriğini çıkarır.
echo.
echo 📝 NASIL KULLANILIR:
echo 1. Analiz etmek istediğiniz .exe dosyasının tam yolunu girin
echo 2. Eğer dosya şifreli ise, şifreyi girin (yazarken görünmez, normal!)
echo 3. Çıkarılan dosyalar masaüstünde 'extracted_TARIH_SAAT' klasöründe olacak
echo.
echo 📁 DOSYA YOLU ÖRNEKLERI:
echo   C:\Users\%USERNAME%\Desktop\program.exe
echo   D:\Indirilenler\uygulama.exe
echo   "C:\Program Files\MyApp\app.exe"  (boşluk varsa tırnak kullanın)
echo.
echo 💡 DOSYA YOLU BULMA İPUCU:
echo   - Dosyaya SAĞ TIKLAYIN
echo   - "Özellikler" seçin
echo   - "Konum" kısmını kopyalayın + dosya adını ekleyin
echo   VEYA
echo   - Dosyayı seçin, SHIFT+SAĞ TIKLAYIN
echo   - "Yol olarak kopyala" seçin
echo.
echo 📂 ÇIKTI KLASÖRLERİ:
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
set /p "exe_path=📁 Analiz edilecek .exe dosyasının tam yolunu girin: "

if "%exe_path%"=="" (
    echo.
    echo ❌ [HATA] Dosya yolu boş olamaz!
    echo    Lütfen .exe dosyasının tam yolunu girin.
    echo.
    goto input_loop
)

if not exist "%exe_path%" (
    echo.
    echo ❌ [HATA] Dosya bulunamadı: %exe_path%
    echo.
    echo 💡 KONTROL EDİN:
    echo    - Dosya yolu doğru mu?
    echo    - Dosya gerçekten var mı?
    echo    - Boşluk varsa tırnak kullandınız mı?
    echo.
    echo Tekrar deneyin:
    echo.
    goto input_loop
)

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              ANALİZ BAŞLIYOR                                ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 🔍 Dosya analiz ediliyor: %exe_path%
echo ⏳ Lütfen bekleyin, bu işlem birkaç dakika sürebilir...
echo.

python main.py "%exe_path%" --verbose

if %errorlevel% neq 0 (
    echo.
    echo ❌ [HATA] Program çalışırken hata oluştu!
    echo.
    echo OLASI NEDENLER:
    echo - Dosya bozuk veya desteklenmeyen format
    echo - Dosya şifreli ve yanlış şifre girildi
    echo - Dosya kullanımda (başka program tarafından açık)
    echo - Yetersiz disk alanı
    echo.
    echo Farklı bir dosya denemek ister misiniz? (E/H)
    set /p "retry=Seçiminiz: "
    if /i "%retry%"=="E" (
        echo.
        goto input_loop
    )
    goto exit_program
)

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                             ✅ İŞLEM TAMAMLANDI                            ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 🎉 Başarılı! Çıkarılan dosyalar masaüstünüzdeki klasörde:
echo    📁 extracted_TARIH_SAAT
echo.
echo 📂 Masaüstünü açmak için Enter'a basın...
pause >nul
start %USERPROFILE%\Desktop
echo.
echo 🔄 Başka bir dosya analiz etmek ister misiniz? (E/H)
set /p "again=Seçiminiz: "

if /i "%again%"=="E" (
    echo.
    echo ╔══════════════════════════════════════════════════════════════════════════════╗
    echo ║                              YENİ ANALİZ                                    ║
    echo ╚══════════════════════════════════════════════════════════════════════════════╝
    echo.
    goto input_loop
)

:exit_program
echo.
echo 👋 Teşekkürler! PE Dumper'ı kullandığınız için teşekkürler.
echo    Program kapatılıyor...
timeout /t 3 /nobreak >nul
exit /b 0