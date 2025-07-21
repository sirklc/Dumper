# 🔍 PE Dumper Interactive - Kullanım Kılavuzu

## 📋 Genel Bakış

PE Dumper Interactive, kendi geliştirdiğiniz uygulamaların güvenlik testlerini yapmak için tasarlanmış interaktif bir GUI aracıdır. Program, hedef exe dosyasını çalıştırıp, auth key'ini girdikten sonra otomatik olarak tüm içeriği çıkarır.

## 🚀 Başlatma

### Yöntem 1: Bash Script ile
```bash
./start_dumper.sh
```

### Yöntem 2: Manuel olarak
```bash
source venv/bin/activate
python interactive_dumper.py
```

## 📝 Kullanım Adımları

### 1. 📁 Dosya Seçimi
- **Target Executable**: Test edilecek .exe dosyasını seçin
- **Output Directory**: Çıkarılan dosyaların kaydedileceği klasörü belirleyin

### 2. 🚀 Executable Başlatma
- "🚀 Launch Target Executable" butonuna tıklayın
- Program hedef exe'yi çalıştıracak
- Durum: "✅ Running" olarak değişecek

### 3. 🔑 Authentication Key Girişi
- Hedef program auth ekranını açacak
- "Authentication Key" alanına bildiğiniz key'i girin
- Key, hedef programda da girilmelidir

### 4. 🔓 Dumping Başlatma
- Hedef programda key'i girdikten sonra
- "🔓 Key Unlocked - Start Dumping" butonuna tıklayın
- Otomatik dumping süreci başlayacak

## 📊 Çıktılar

### Çıkarılan Dosyalar:
- 📄 **source_code/**: Kaynak kodlar ve kaynaklar
- 🔧 **cpp_files/**: C++ dosyaları
- 📚 **dll_files/**: DLL dosyaları
- 🔧 **drivers/**: Driver dosyaları
- 📜 **certificates/**: Dijital sertifikalar
- 💾 **dumps/**: Ham veri ve PE bölümleri
- 🏃 **executables/**: Gömülü executable'lar

### Raporlar:
- 📊 **security_assessment_report.txt**: Güvenlik değerlendirme raporu
- 📝 **extraction_info.txt**: Çıkarma işlemi bilgileri

## ⚡ Özellikler

### 🔓 Auth Bypass Sistemi
- Otomatik yaygın key testi
- Buffer overflow teknikleri
- Zayıflık bazlı bypass
- Manuel key desteği

### 📦 Gelişmiş Çıkarma
- Sıkıştırılmış dosyalar (ZIP, RAR, 7z)
- Şifreli/yüksek entropi verileri
- Konfigürasyon dosyaları
- Registry verileri

### 🛡️ Güvenlik Analizi
- Vulnerability skorlaması
- Risk seviyesi analizi
- Auth güvenliği değerlendirme
- Güvenlik önerileri

## 🔧 Teknik Gereksinimler

### Gerekli Paketler:
- Python 3.7+
- customtkinter
- tkinter
- pefile
- colorama
- cryptography
- beautifulsoup4
- lxml

### Desteklenen Platformlar:
- ✅ Linux (Ana platform)
- ✅ Windows (CrossTk desteği ile)
- ✅ macOS (CrossTk desteği ile)

## 🚨 Güvenlik Uyarıları

1. **⚠️ Sadece Kendi Ürünlerinizi Test Edin**
   - Bu araç sadece kendi geliştirdiğiniz uygulamaları test etmek içindir
   - Başkalarının yazılımlarını test etmek yasal sorunlara yol açabilir

2. **🔒 Key Güvenliği**
   - Authentication key'lerinizi güvende tutun
   - Test sonrası key'leri değiştirin

3. **📁 Çıktı Güvenliği**
   - Çıkarılan dosyaları güvenli yerlerde saklayın
   - Hassas bilgiler içerebilir

## 🐛 Sorun Giderme

### GUI Açılmıyor
```bash
pip install customtkinter
pip install --upgrade tkinter
```

### PE Dosyası Yüklenmiyor
- Dosya yolunda Türkçe karakter olmasın
- Dosya izinlerini kontrol edin
- Dosya bozuk olmadığından emin olun

### Auth Bypass Çalışmıyor
- Manuel key girmeyi deneyin
- Key'in doğru olduğundan emin olun
- Log alanından hata mesajlarını kontrol edin

## 📞 Destek

Sorunlar için:
1. Log alanından hata mesajlarını kopyalayın
2. Kullandığınız dosya türü ve boyutunu belirtin
3. Adım adım ne yaptığınızı açıklayın

---

**🎉 Başarılı testler dileriz!**

> Bu araç, kendi yazılımlarınızın güvenlik seviyesini test ederek daha güvenli ürünler geliştirmenize yardımcı olur.