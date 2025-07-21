#!/bin/bash

clear
echo "🔍 PE Dumper Interactive - Otomatik Kurulum"
echo "=========================================="
echo

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check Python
echo -e "${BLUE}[1/4]${NC} Python kurulumu kontrol ediliyor..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 bulunamadı!${NC}"
    echo -e "${YELLOW}💡 Lütfen Python 3.7+ kurun: https://python.org${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo -e "${GREEN}✅ Python ${PYTHON_VERSION} bulundu${NC}"

# Create virtual environment
echo -e "${BLUE}[2/4]${NC} Sanal ortam oluşturuluyor..."
if [ -d "venv" ]; then
    echo -e "${YELLOW}⚠️  Mevcut sanal ortam siliniyor...${NC}"
    rm -rf venv
fi

python3 -m venv venv
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Sanal ortam oluşturuldu${NC}"
else
    echo -e "${RED}❌ Sanal ortam oluşturulamadı!${NC}"
    exit 1
fi

# Activate virtual environment
echo -e "${BLUE}[3/4]${NC} Bağımlılıklar yükleniyor..."
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip --quiet

# Install requirements
pip install -r requirements.txt --quiet
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Tüm bağımlılıklar yüklendi${NC}"
else
    echo -e "${RED}❌ Bağımlılık yükleme hatası!${NC}"
    exit 1
fi

# Create launcher script
echo -e "${BLUE}[4/4]${NC} Başlatıcı oluşturuluyor..."

cat > launcher.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python core/interactive_dumper.py
EOF

chmod +x launcher.sh

# Create desktop shortcut (if possible)
if command -v xdg-desktop-menu &> /dev/null; then
    DESKTOP_FILE="$HOME/.local/share/applications/pe-dumper.desktop"
    cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=PE Dumper Interactive
Comment=Interactive PE file analysis tool
Exec=$(pwd)/launcher.sh
Icon=utilities-terminal
Terminal=false
Categories=Development;Security;
EOF
    echo -e "${GREEN}✅ Masaüstü kısayolu oluşturuldu${NC}"
fi

echo
echo -e "${GREEN}🎉 Kurulum tamamlandı!${NC}"
echo
echo -e "${YELLOW}📋 Kullanım seçenekleri:${NC}"
echo -e "   ${BLUE}1.${NC} ./launcher.sh           - Hızlı başlatma"
echo -e "   ${BLUE}2.${NC} ./scripts/start_dumper.sh - Detaylı başlatma"
echo -e "   ${BLUE}3.${NC} Masaüstü kısayolu       - GUI'den başlat"
echo
echo -e "${YELLOW}📖 Dokümantasyon:${NC} docs/INTERACTIVE_GUIDE.md"
echo
echo -e "${GREEN}✨ Hazır! PE Dumper Interactive'i çalıştırabilirsiniz.${NC}"