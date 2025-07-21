# 🪟 PE Dumper Interactive - Windows Kullanım Kılavuzu

## 🚀 Hızlı Kurulum (Windows)

### ⚡ Tek Tıkla Başlatma
1. `run.bat` dosyasına **çift tıklayın**
2. İlk çalıştırmada otomatik kurulum yapılacak
3. GUI açıldıktan sonra kullanmaya başlayın

### 📦 Manuel Kurulum
1. `install.bat` dosyasına **çift tıklayın**
2. Kurulum tamamlandıktan sonra `launcher.bat` ile başlatın

## 🎯 Windows Özel Özellikler

### 🖥️ Masaüstü Kısayolu
- Kurulum sonrası otomatik masaüstü kısayolu oluşturulur
- "PE Dumper Interactive" adında kısayol
- Çift tıkla direkt çalıştırma

### 📁 Windows Explorer Entegrasyonu
- Masaüstünde "DumperOutput" klasörü otomatik açılır
- Sonuç dosyaları Windows Explorer'da görüntülenebilir

## 🔧 Windows Başlatma Seçenekleri

### 1️⃣ `run.bat` - En Kolay
```batch
# Çift tık -> Otomatik kurulum + çalıştırma
run.bat
```
**Özellikler:**
- Otomatik kurulum kontrolü
- Eksik bağımlılık yüklemesi
- Tek tıkla başlatma

### 2️⃣ `launcher.bat` - En Hızlı
```batch
# Çift tık -> Direkt çalıştırma (kurulum sonrası)
launcher.bat
```
**Özellikler:**
- Anında başlatma
- Kurulum öncesi kullanılmaz
- En hızlı seçenek

### 3️⃣ `install.bat` - Manuel Kurulum
```batch
# Çift tık -> Sadece kurulum
install.bat
```
**Özellikler:**
- Detaylı kurulum süreci
- Bağımlılık kontrolü
- Masaüstü kısayolu oluşturma

### 4️⃣ `scripts\start_dumper.bat` - Detaylı
```batch
# Çift tık -> Detaylı bilgi ile başlatma
scripts\start_dumper.bat
```
**Özellikler:**
- Detaylı sistem kontrolleri
- Kullanım talimatları
- Hata ayıklama bilgileri

## ⚠️ Windows Özel Uyarıları

### 🛡️ Windows Defender
- İlk çalıştırmada Windows Defender uyarısı alabilirsiniz
- "Daha fazla bilgi" -> "Yine de çalıştır" seçin
- Güvenilir yazılım olarak ekleyin

### 🔐 Yönetici İzinleri
- Kurulum için yönetici yetkisi gerekmez
- Ancak bazı PE dosyaları için gerekebilir
- "Yönetici olarak çalıştır" seçeneğini kullanın

### 📁 Dosya Yolları
- Türkçe karakter içeren yollardan kaçının
- Uzun dosya yollarından kaçının
- Tercihen C:\\ sürücüsü kullanın

## 🐛 Windows Sorun Giderme

### ❌ Python Bulunamadı Hatası
```
Çözüm:
1. https://python.org/downloads adresine gidin
2. Python 3.7+ indirin
3. Kurulumda "Add Python to PATH" işaretleyin
4. Kurulum sonrası sistemi yeniden başlatın
```

### ❌ Bağımlılık Kurulum Hatası
```
Çözüm:
1. Antivirüs programını geçici kapatın
2. İnternet bağlantısını kontrol edin
3. Windows'u yönetici olarak çalıştırın
4. install.bat'ı tekrar çalıştırın
```

### ❌ GUI Açılmıyor
```
Çözüm:
1. Komut istemi açın (cmd)
2. Proje klasörüne gidin
3. "python core/interactive_dumper.py" yazın
4. Hata mesajını kontrol edin
```

### ❌ Hedef EXE Çalışmıyor
```
Çözüm:
1. EXE dosyasının yolunda boşluk olmamalı
2. Yönetici yetkisi gerekebilir
3. Windows uyumluluk modunu deneyin
4. Antivirüs programını kontrol edin
```

## 💡 Windows Performans İpuçları

### ⚡ Hızlandırma
- SSD kullanın (mümkünse)
- Yeterli RAM'e sahip olun (min 4GB)
- Antivirüs real-time korumasını geçici kapatın
- Gereksiz arka plan programlarını kapatın

### 📊 Bellek Kullanımı
- Büyük PE dosyaları için daha fazla RAM gerekir
- 32-bit Python 2GB limit'i olabilir
- 64-bit Python önerilir

## 🎉 Windows'a Özel Avantajlar

### ✅ Yerel PE Desteği
- Windows PE formatı için optimize edilmiş
- Native Windows API kullanımı
- Daha iyi performans

### ✅ GUI Optimizasyonu
- Windows tema entegrasyonu
- Native Windows widget'ları
- Tanıdık kullanıcı deneyimi

### ✅ Dosya İşlemleri
- Windows dosya sistemi optimizasyonu
- NTFS özel özellik desteği
- Windows güvenlik modeli uyumluluğu

---

**🎯 Windows'ta sorunsuz PE Dumper deneyimi için bu kılavuzu takip edin!**

> Windows 10/11 üzerinde en iyi performans için 64-bit Python kullanmanız önerilir.