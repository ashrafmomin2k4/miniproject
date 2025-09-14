# Web Vulnerability Scanner

A free, web-based tool to scan websites for common security vulnerabilities and receive a comprehensive security analysis report.

## Features
- **SSL/TLS Security Checks** - Certificate validation, encryption strength
- **Security Headers Analysis** - HSTS, CSP, X-Frame-Options, X-XSS-Protection
- **Injection Vulnerability Testing** - SQL injection, XSS, directory traversal
- **Information Disclosure Detection** - Exposed sensitive files, server info leaks
- **Risk Assessment** - Automated scoring and classification (Low/Medium/High Risk)
- **Modern UI** - Clean Tailwind CSS interface with responsive design

## Security Checks Performed
- SSL certificate validity and configuration
- Missing security headers
- SQL injection vulnerabilities
- Cross-site scripting (XSS) vulnerabilities
- Directory traversal vulnerabilities
- Exposed sensitive files (config files, backups, etc.)
- Server information disclosure
- Technology stack detection

## Requirements
- Python 3.8+
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

## Usage
1. Enter a website URL in the input field
2. Click "Scan Website for Vulnerabilities"
3. Review the comprehensive security report
4. Follow recommendations to fix identified issues

## Security
- All scans are performed from the outside without requiring special access
- No data is stored or logged beyond the scan session
- Non-intrusive testing that respects rate limits

## Future Work
- Expand vulnerability detection patterns
- Add support for more web technologies
- Integrate advanced security testing techniques
- Add scheduled scanning capabilities
