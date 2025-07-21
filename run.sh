#!/bin/bash

# Quick launcher for PE Dumper Interactive
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "🔧 Kurulum gerekli! Otomatik kurulum başlatılıyor..."
    ./install.sh
fi

source venv/bin/activate
python core/interactive_dumper.py