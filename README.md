# webv.py - Ultimate Web Vulnerability Testing Suite

A powerful, all-in-one web vulnerability testing tool with comprehensive reconnaissance capabilities, SQLMap integration, and an intuitive GUI.

## Features

### 🔍 Comprehensive Reconnaissance
- **Basic Information Gathering**: IP resolution, WHOIS lookup, DNS records
- **HTTP Headers Analysis**: Security headers detection, server information
- **Technology Detection**: Framework and CMS identification (WordPress, Joomla, React, Angular, etc.)
- **Port Scanning**: Quick port scan for common services
- **Subdomain Enumeration**: Automated subdomain discovery
- **Directory Brute-forcing**: Common directory and file discovery

### 🗄️ SQLMap Integration
- One-click SQLMap execution
- Multiple preset configurations (Quick, Standard, Aggressive, Full Dump)
- Custom SQLMap options support
- Real-time output streaming
- Automatic result saving to `./loot/` directory

### 💣 Payload Library
- Pre-built payloads for common vulnerabilities:
  - XSS (Basic & Advanced)
  - LFI (Local File Inclusion)
  - RCE (Remote Code Execution)
  - SSRF (Server-Side Request Forgery)
  - SQL Injection
  - Command Injection
  - Path Traversal
  - XXE (XML External Entity)
- One-click payload copying to clipboard

### 📊 Reporting
- Export results as JSON
- Generate HTML reports
- All reports saved to `./reports/` directory

## Installation

### Automatic Setup (Recommended)
Just run the script - it will automatically:
1. Create a virtual environment
2. Install all required dependencies
3. Download SQLMap
4. Set up necessary directories

```bash
python3 webv.py
```

### Manual Setup
```bash
# Create virtual environment
python3 -m venv .webvulnx_venv
source .webvulnx_venv/bin/activate  # On Windows: .webvulnx_venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download SQLMap
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
```

## Usage

1. **Launch the application**:
   ```bash
   python3 webv.py
   ```

2. **Enter your target URL** in the target field

3. **Choose your testing method**:
   - **Reconnaissance Tab**: Run various recon checks
   - **SQLMap Tab**: Execute SQL injection testing
   - **Payloads Tab**: Browse and copy testing payloads

4. **View results** in the live output window

5. **Export reports** using the export buttons in the Reconnaissance tab

## Directory Structure

```
KOPro1/
├── webv.py                 # Main application
├── requirements.txt       # Python dependencies
├── .webvulnx_venv/        # Virtual environment (auto-created)
├── sqlmap/                # SQLMap installation (auto-downloaded)
├── loot/                  # SQLMap output directory
└── reports/               # Exported reports (JSON/HTML)
```

## Features Breakdown

### Reconnaissance Module
- **Basic Info**: DNS resolution, WHOIS data, DNS records (A, AAAA, MX, NS, TXT)
- **HTTP Headers**: Complete header analysis with security header detection
- **Technology Detection**: Identifies web frameworks, CMS, JavaScript libraries
- **Port Scan**: Scans common ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443)
- **Subdomain Enum**: Tests common subdomain names
- **Directory Brute**: Tests common directory and file paths

### SQLMap Integration
- Pre-configured with optimal settings
- Supports custom SQLMap command-line options
- Real-time output streaming
- Automatic result organization

### Payload Library
12+ pre-built payloads covering:
- Cross-Site Scripting (XSS)
- Local File Inclusion (LFI)
- Remote Code Execution (RCE)
- Server-Side Request Forgery (SSRF)
- SQL Injection
- Command Injection
- Path Traversal
- XML External Entity (XXE)

## Requirements

- Python 3.7+
- Internet connection (for initial setup and SQLMap download)
- Git (for SQLMap download)
- Tkinter (usually included with Python)

## Security & Legal Notice

⚠️ **IMPORTANT**: This tool is for **authorized security testing only**. 

- Only test systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse of this tool
- Always comply with applicable laws and regulations

## Tips

1. **Start with Reconnaissance**: Run basic info and HTTP headers first to understand your target
2. **Use Technology Detection**: Knowing the tech stack helps choose appropriate payloads
3. **Directory Brute-forcing**: Often reveals admin panels, backup files, or sensitive directories
4. **SQLMap Presets**: Start with "Quick Test" before running full scans
5. **Export Reports**: Save your findings for documentation and further analysis

## Troubleshooting

### Virtual Environment Issues
If you encounter issues, delete `.webvulnx_venv` and run the script again to recreate it.

### SQLMap Not Found
The script automatically downloads SQLMap. If it fails, ensure you have `git` installed and internet connectivity.

### Import Errors
Make sure you're running the script after the initial setup completes. The script will relaunch itself in the virtual environment.

## Contributing

Feel free to enhance this tool with:
- Additional reconnaissance techniques
- More payloads
- Integration with other security tools
- UI improvements
- Better error handling

## License

This tool is provided as-is for educational and authorized security testing purposes.

---

**Made with ❤️ for the security community**

