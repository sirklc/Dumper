#!/bin/bash

# PE Dumper Interactive Launcher
echo "🔍 PE Dumper Interactive v2.0"
echo "=============================="
echo

# Go to project root
cd "$(dirname "$0")/.."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "💡 Please run install.sh first:"
    echo "   ./install.sh"
    exit 1
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Check dependencies
echo "📦 Checking dependencies..."
python -c "import customtkinter, tkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Missing dependencies!"
    echo "💡 Installing required packages..."
    pip install customtkinter
fi

# Launch interactive dumper
echo "🚀 Starting PE Dumper Interactive..."
echo "📝 Usage Instructions:"
echo "   1. Select target .exe file"
echo "   2. Choose output directory"
echo "   3. Click 'Launch Target Executable'"
echo "   4. Enter your authentication key"
echo "   5. Click 'Key Unlocked - Start Dumping'"
echo

python core/interactive_dumper.py

echo "👋 PE Dumper Interactive closed."