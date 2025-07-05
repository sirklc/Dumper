# Dumper

A Python-based dumper tool for extracting and analyzing data.

## Setup

### Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Linux/macOS
# or
venv\Scripts\activate     # On Windows

# Install dependencies
pip install -r requirements.txt
```

### Requirements

- Python 3.7+
- Dependencies listed in `requirements.txt`

## Usage

```bash
# Activate virtual environment first
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the dumper
python main.py /path/to/executable.exe

# With verbose output
python main.py /path/to/executable.exe --verbose
```

## Project Structure

```
Dumper/
├── venv/                 # Virtual environment
├── requirements.txt      # Python dependencies
├── README.md            # This file
└── main.py              # Main application file
```

## Dependencies

- `requests` - HTTP library for making requests
- `beautifulsoup4` - HTML/XML parsing
- `lxml` - XML and HTML parser
- `colorama` - Cross-platform colored terminal text
- `pefile` - PE file analysis library
- `cryptography` - Cryptographic operations
- `py7zr` - 7z archive handling
- `python-magic` - File type detection

## Features

- **PE File Analysis**: Analyzes Windows PE executable files
- **Authentication Detection**: Automatically detects authentication mechanisms
- **Resource Extraction**: Extracts embedded resources, sections, and imports
- **Certificate Extraction**: Extracts digital certificates if present
- **Organized Output**: Creates timestamped folders with categorized extracted data
- **Verbose Logging**: Optional detailed output for debugging

## Output Structure

When extraction is complete, files are organized in `extracted_YYYYMMDD_HHMMSS/`:

```
extracted_20231201_143022/
├── source_code/          # Extracted resources and imports
├── drivers/              # Driver files (if found)
├── certificates/         # Digital certificates
├── dumps/               # Raw section dumps and original file
└── extraction_info.txt  # Extraction metadata
```