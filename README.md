# 🔍 PE Dumper Interactive

Kendi geliştirdiğiniz PE dosyalarının güvenlik testlerini yapmak için interaktif GUI aracı.

## ⚡ Hızlı Başlangıç

### 🐧 Linux / macOS
```bash
./run.sh                    # Tek komutla kurulum + çalıştırma
./install.sh                # Manuel kurulum
./launcher.sh               # Hızlı başlatma
./scripts/start_dumper.sh   # Detaylı başlatma
```

### 🪟 Windows  
```batch
run.bat                     :: Tek tıkla kurulum + çalıştırma
install.bat                 :: Manuel kurulum
launcher.bat                :: Hızlı başlatma
scripts\start_dumper.bat    :: Detaylı başlatma
```

### 🚀 Önerilen Kullanım
- **Linux/macOS**: `./run.sh`
- **Windows**: `run.bat` (çift tıklama)

## 📋 Özellikler

### 🔓 Auth Bypass Sistemi
- ✅ Otomatik yaygın key testi
- ✅ Buffer overflow teknikleri  
- ✅ Zayıflık bazlı bypass
- ✅ Manuel key desteği

### 📦 Gelişmiş İçerik Çıkarma
- ✅ C++ kaynak kodları
- ✅ DLL dosyaları
- ✅ Driver dosyaları
- ✅ Sıkıştırılmış dosyalar
- ✅ Şifreli veriler
- ✅ Konfigürasyon dosyaları

### 🛡️ Güvenlik Analizi
- ✅ Vulnerability skorlaması
- ✅ Risk seviyesi analizi
- ✅ Güvenlik önerileri
- ✅ Detaylı raporlama

## 🎯 Kullanım Akışı

1. **📁 Dosya Seçimi**: Target .exe ve output klasörü
2. **🚀 Exe Başlatma**: "Launch Target Executable" 
3. **🔑 Key Girişi**: Auth key'ini hem GUI'de hem exe'de girin
4. **🔓 Dumping**: "Key Unlocked - Start Dumping" butonu
5. **📊 Sonuç**: Otomatik çıkarma ve rapor oluşturma

## 📁 Proje Yapısı

```
PE-Dumper/
├── 🚀 run.sh / run.bat           # Tek tıkla çalıştırma
├── 🚀 launcher.sh / launcher.bat # Hızlı başlatma  
├── ⚙️  install.sh / install.bat   # Otomatik kurulum
├── 📋 requirements.txt           # Bağımlılıklar
├── 📖 README.md                 # Ana döküman
├── core/                        # 🧠 Ana kod dosyaları
│   ├── main.py                  # PE dumper motoru
│   └── interactive_dumper.py    # GUI uygulaması
├── scripts/                     # 📜 Başlatma scriptleri
│   ├── start_dumper.sh          # Linux detaylı başlatıcı
│   └── start_dumper.bat         # Windows detaylı başlatıcı
└── docs/                        # 📚 Dokümantasyon
    └── INTERACTIVE_GUIDE.md     # Detaylı kullanım kılavuzu
```

## 🔧 Gereksinimler

- **Python**: 3.7+
- **Platform**: Linux, Windows, macOS
- **Bağımlılıklar**: Otomatik kurulur

## ⚠️ Güvenlik Uyarıları

- ✅ **Sadece kendi ürünlerinizi** test edin
- ✅ **Authentication key'lerinizi** güvende tutun  
- ✅ **Çıktı dosyalarını** güvenli yerlerde saklayın

## 📞 Destek

Sorun yaşarsanız:
1. Log alanından hata mesajlarını kontrol edin
2. Platform özel kılavuzları inceleyin:
   - **Linux/macOS**: `docs/INTERACTIVE_GUIDE.md`
   - **Windows**: `docs/WINDOWS_GUIDE.md`
3. Kullandığınız dosya türü ve boyutunu belirtin

---

**🎉 Başarılı güvenlik testleri dileriz!**

> PE Dumper Interactive ile kendi yazılımlarınızın güvenlik seviyesini test edin ve daha güvenli ürünler geliştirin.