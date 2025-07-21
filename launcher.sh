#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python core/interactive_dumper.py
