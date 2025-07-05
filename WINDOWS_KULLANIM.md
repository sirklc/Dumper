# Windows Kullanıcıları İçin PE Dumper Kullanım Kılavuzu

## 🚀 Hızlı Başlangıç

### Adım 1: Dosyaları İndirin
- Tüm dosyaları bilgisayarınıza indirin
- Dosyaları bir klasöre (örneğin `C:\PE-Dumper\`) çıkarın

### Adım 2: Python Kurulumu
Eğer Python kurulu değilse:
1. https://www.python.org/downloads/ adresinden Python 3.7+ indirin
2. Kurulum sırasında "Add Python to PATH" seçeneğini işaretleyin
3. Kurulumu tamamlayın

### Adım 3: Programı Çalıştırın
1. `baslat.bat` dosyasına **çift tıklayın**
2. Program otomatik olarak gerekli kurulumları yapacak
3. Analiz etmek istediğiniz .exe dosyasının tam yolunu girin

## 📁 Dosya Yolu Örnekleri

### Doğru Yol Örnekleri:
```
C:\Users\KullaniciAdi\Desktop\program.exe
D:\Indirilenler\uygulama.exe
"C:\Program Files\MyApp\app.exe"
```

### Yol Bulma İpuçları:
1. **Dosyaya sağ tıklayın** → "Özellikler"
2. **Konum** kısmını kopyalayın
3. Dosya adını da ekleyin

Veya:
1. **Dosyayı seçin**
2. **Shift** tuşuna basılı tutup **sağ tıklayın**
3. **"Yol olarak kopyala"** seçeneğini seçin

## 🔐 Kimlik Doğrulama

Eğer program "Authentication mechanism detected!" mesajı verirse:
- Dosya şifreli demektir
- Şifreyi girin (yazarken görünmez, bu normaldir)
- Enter tuşuna basın

## 📂 Sonuçlar Nerede?

Çıkarılan dosyalar masaüstünüzde şu klasörde olacak:
```
extracted_20231201_143022\
├── source_code\      - Kaynak kodlar
├── drivers\          - Sürücü dosyaları  
├── certificates\     - Sertifikalar
├── dumps\           - Ham veriler
└── extraction_info.txt - Analiz raporu
```

## ❌ Sorun Giderme

### "Python bulunamadı" Hatası
- Python kurulu değil
- Python'u yeniden kurun ve PATH'e eklemeyi unutmayın

### "Dosya bulunamadı" Hatası
- Dosya yolu yanlış
- Dosya adında Türkçe karakter var ise sorun olabilir
- Dosyayı başka bir klasöre taşıyın

### "Access Denied" Hatası
- Dosya kullanımda olabilir
- Dosyayı kapatın ve tekrar deneyin
- Yönetici olarak çalıştırın

## 🔄 Tekrar Kullanım

Program bittikten sonra:
- "E" yazıp Enter = Başka dosya analiz et
- "H" yazıp Enter = Çık

## 📞 Destek

Sorun yaşarsanız:
1. Hata mesajını tam olarak not edin
2. Hangi adımda takıldığınızı belirtin
3. Python sürümünüzü kontrol edin: `python --version`

---

**⚠️ ÖNEMLİ NOT:** Bu araç yalnızca analiz amaçlıdır. Kendi dosyalarınızı analiz etmek için kullanın.