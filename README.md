# APK Malware Scanner

A free, web-based tool to upload Android APK files and receive a static security analysis report.

## Features
- Static analysis using Androguard (no execution)
- Permission-based rule scoring (Clean, Suspicious, Malicious)
- SHA256 hash blacklist check
- Tailwind UI with Home, How It Works, About, and Result pages

## Requirements
- Python 3.10+
- Windows, macOS, or Linux

## Setup
```bash
python -m venv .venv
. .venv/Scripts/activate  # on Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run
```bash
python app.py
```
Open `http://localhost:5000` in your browser.

## Notes
- Max upload size: 150 MB
- Supported file types: `.apk`
- Blacklist file: `data/blacklist.json`

## Security
- Files are processed in a temp directory and deleted after analysis.
- No uploads are stored server-side beyond processing.

## Future Work
- Integrate ML-based classifier for improved detection.
