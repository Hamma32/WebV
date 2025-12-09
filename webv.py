#!/usr/bin/env python3
# webv.py - Ultimate Web Vulnerability Testing Suite
# Enhanced version with comprehensive recon, multiple tools, and better UI

import os
import sys
import subprocess
import shutil
import threading
import json
import time
from datetime import datetime
from urllib.parse import urlparse
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog

SCRIPT_PATH = os.path.abspath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)
VENV_DIR = os.path.join(SCRIPT_DIR, ".webvulnx_venv")
BIN_DIR = "Scripts" if os.name == "nt" else "bin"
PYTHON_VENV = os.path.join(VENV_DIR, BIN_DIR, "python")
SQLMAP_PATH = os.path.join(SCRIPT_DIR, "sqlmap", "sqlmap.py")
LOOT_DIR = os.path.join(SCRIPT_DIR, "loot")
REPORTS_DIR = os.path.join(SCRIPT_DIR, "reports")

# ========= AUTO VENV + SQLMAP SETUP =========
if not (os.path.exists(PYTHON_VENV) and os.path.samefile(sys.executable, PYTHON_VENV)):
    print("[+] webv.py - First time setup")

    if os.path.exists(VENV_DIR):
        shutil.rmtree(VENV_DIR, ignore_errors=True)

    print("    Creating virtual environment...")
    subprocess.check_call([sys.executable, "-m", "venv", VENV_DIR])

    print("    Installing Python packages...")
    subprocess.check_call([PYTHON_VENV, "-m", "pip", "install", "--upgrade", "pip", "--quiet"])
    subprocess.check_call([PYTHON_VENV, "-m", "pip", "install", "--quiet", 
                          "requests", "dnspython", "python-whois", "shodan", "beautifulsoup4", 
                          "urllib3", "colorama"])

    print("    Downloading sqlmap...")
    if os.path.exists("sqlmap"):
        shutil.rmtree("sqlmap")
    subprocess.check_call(["git", "clone", "--depth", "1", "https://github.com/sqlmapproject/sqlmap.git"])

    os.makedirs(LOOT_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    print("[+] Setup complete! Relaunching...")
    os.execv(PYTHON_VENV, [PYTHON_VENV, SCRIPT_PATH])

# ========= NOW INSIDE VENV → LAUNCH TOOL =========
import socket
import requests
import dns.resolver
import whois
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global state
sqlmap_proc = None
recon_data = {}
active_threads = []

class ReconEngine:
    def __init__(self, log_callback):
        self.log = log_callback
        self.results = {}
        
    def get_domain(self, url):
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        return parsed.netloc or parsed.path.split("/")[0]
    
    def basic_info(self, target):
        """Basic target information gathering"""
        domain = self.get_domain(target)
        self.log(f"\n[RECON] Basic Info for {domain}")
        self.log("=" * 80)
        
        # IP Resolution
        try:
            ip = socket.gethostbyname(domain)
            self.log(f"[+] IP Address: {ip}")
            self.results['ip'] = ip
        except Exception as e:
            self.log(f"[-] DNS Resolution failed: {e}")
        
        # WHOIS Lookup
        try:
            w = whois.whois(domain)
            if w.domain_name:
                self.log(f"[+] Domain: {w.domain_name}")
                self.log(f"[+] Registrar: {w.registrar}")
                if w.creation_date:
                    self.log(f"[+] Created: {w.creation_date}")
                self.results['whois'] = str(w)
        except Exception as e:
            self.log(f"[-] WHOIS lookup failed: {e}")
        
        # DNS Records
        try:
            self.log("\n[+] DNS Records:")
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        self.log(f"    {record_type}: {rdata}")
                except:
                    pass
        except Exception as e:
            self.log(f"[-] DNS enumeration failed: {e}")
    
    def http_headers(self, target):
        """Analyze HTTP headers"""
        url = target if target.startswith("http") else "http://" + target
        self.log(f"\n[RECON] HTTP Headers Analysis")
        self.log("=" * 80)
        
        try:
            r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            self.log(f"[+] Status Code: {r.status_code}")
            self.log(f"[+] Final URL: {r.url}")
            
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                              'X-XSS-Protection', 'Strict-Transport-Security',
                              'Content-Security-Policy', 'Server', 'X-Powered-By']
            
            self.log("\n[+] Security Headers:")
            for header in security_headers:
                value = r.headers.get(header, 'Not Set')
                status = "✓" if value != 'Not Set' else "✗"
                self.log(f"    {status} {header}: {value}")
            
            self.log("\n[+] All Headers:")
            for key, value in r.headers.items():
                self.log(f"    {key}: {value}")
            
            self.results['headers'] = dict(r.headers)
            self.results['status_code'] = r.status_code
            self.results['final_url'] = r.url
            
        except Exception as e:
            self.log(f"[-] HTTP request failed: {e}")
    
    def technology_detection(self, target):
        """Detect technologies used"""
        url = target if target.startswith("http") else "http://" + target
        self.log(f"\n[RECON] Technology Detection")
        self.log("=" * 80)
        
        technologies = []
        try:
            r = requests.get(url, timeout=10, verify=False)
            
            # Server detection
            server = r.headers.get('Server', '')
            if server:
                self.log(f"[+] Server: {server}")
                technologies.append(server)
            
            # X-Powered-By
            powered = r.headers.get('X-Powered-By', '')
            if powered:
                self.log(f"[+] Powered By: {powered}")
                technologies.append(powered)
            
            # Cookie analysis
            cookies = r.cookies
            if cookies:
                self.log(f"[+] Cookies: {len(cookies)} found")
                for cookie in cookies:
                    self.log(f"    - {cookie.name}: {cookie.value[:50]}")
            
            # HTML analysis
            soup = BeautifulSoup(r.text, 'html.parser')
            
            # Framework detection
            if soup.find('script', src=lambda x: x and 'jquery' in x.lower()):
                self.log("[+] jQuery detected")
                technologies.append("jQuery")
            
            if soup.find('script', src=lambda x: x and 'react' in x.lower()):
                self.log("[+] React detected")
                technologies.append("React")
            
            if soup.find('script', src=lambda x: x and 'angular' in x.lower()):
                self.log("[+] Angular detected")
                technologies.append("Angular")
            
            # CMS detection
            if 'wp-content' in r.text or 'wp-includes' in r.text:
                self.log("[+] WordPress detected")
                technologies.append("WordPress")
            
            if 'joomla' in r.text.lower():
                self.log("[+] Joomla detected")
                technologies.append("Joomla")
            
            self.results['technologies'] = technologies
            
        except Exception as e:
            self.log(f"[-] Technology detection failed: {e}")
    
    def port_scan(self, target, ports=None):
        """Basic port scanning"""
        domain = self.get_domain(target)
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]
        
        try:
            ip = socket.gethostbyname(domain)
        except:
            self.log(f"[-] Cannot resolve {domain}")
            return
        
        self.log(f"\n[RECON] Port Scan for {ip}")
        self.log("=" * 80)
        
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                self.log(f"[+] Port {port}: OPEN")
                open_ports.append(port)
            sock.close()
        
        if not open_ports:
            self.log("[-] No open ports found")
        self.results['open_ports'] = open_ports
    
    def subdomain_enum(self, target):
        """Basic subdomain enumeration"""
        domain = self.get_domain(target)
        self.log(f"\n[RECON] Subdomain Enumeration for {domain}")
        self.log("=" * 80)
        
        common_subs = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
                      'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 
                      'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin',
                      'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old',
                      'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
                      'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web',
                      'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
                      'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
                      'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat',
                      'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host',
                      'crm', 'cms', 'backup', 'mx2', 'static1', 'web1', 'web2', 'git']
        
        found = []
        for sub in common_subs[:20]:  # Limit for speed
            try:
                subdomain = f"{sub}.{domain}"
                ip = socket.gethostbyname(subdomain)
                self.log(f"[+] Found: {subdomain} -> {ip}")
                found.append(subdomain)
            except:
                pass
        
        if not found:
            self.log("[-] No subdomains found")
        self.results['subdomains'] = found
    
    def directory_bruteforce(self, target, wordlist=None):
        """Basic directory brute-forcing"""
        url = target if target.startswith("http") else "http://" + target
        url = url.rstrip('/')
        
        if wordlist is None:
            wordlist = ['admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin', 
                       'test', 'backup', 'config', 'api', 'dashboard', 'panel',
                       'cpanel', 'phpinfo', 'robots.txt', '.git', '.env', 'old',
                       'tmp', 'temp', 'uploads', 'images', 'files', 'assets']
        
        self.log(f"\n[RECON] Directory Brute-force")
        self.log("=" * 80)
        
        found = []
        for path in wordlist[:30]:  # Limit for speed
            try:
                test_url = f"{url}/{path}"
                r = requests.get(test_url, timeout=3, verify=False, allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    self.log(f"[+] {r.status_code} - {test_url}")
                    found.append({'url': test_url, 'status': r.status_code})
            except:
                pass
        
        if not found:
            self.log("[-] No directories found")
        self.results['directories'] = found

class SQLMapManager:
    def __init__(self, log_callback, results_callback=None):
        self.log = log_callback
        self.results_callback = results_callback
        self.process = None
        
    def run(self, target, options=None):
        """Run SQLMap with custom options"""
        if self.process and self.process.poll() is None:
            return False, "SQLMap already running!"
        
        url = target if target.startswith("http") else "http://" + target
        if "?" not in url:
            url += "/index.php?id=1"
        
        cmd = [
            PYTHON_VENV, SQLMAP_PATH, "-u", url,
            "--batch", "--random-agent", "--risk=3", "--level=5",
            "--dbs", "--threads=10", "--output-dir=" + LOOT_DIR
        ]
        
        if options:
            cmd.extend(options.split())
        
        self.log(f"[SQLMAP] Starting → {url}")
        self.log("sqlmap " + " ".join(cmd[2:]) + "\n" + "="*80)
        
        def thread():
            try:
                self.process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1, universal_newlines=True
                )
                for line in self.process.stdout:
                    self.log(line.rstrip())
                    if self.results_callback:
                        self.results_callback(line.rstrip())
                self.log("\n[+] SQLMap finished! Loot → ./loot/")
                if self.results_callback:
                    self.results_callback("\n[+] SQLMap finished! Loot → ./loot/")
            except Exception as e:
                error_msg = f"[-] SQLMap error: {e}"
                self.log(error_msg)
                if self.results_callback:
                    self.results_callback(error_msg)
        
        threading.Thread(target=thread, daemon=True).start()
        return True, "Started"
    
    def stop(self):
        """Stop SQLMap process"""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.log("[!] SQLMap stopped.")
            if self.results_callback:
                self.results_callback("[!] SQLMap stopped.")
            return True
        return False

class ReportGenerator:
    @staticmethod
    def save_json(data, filename):
        """Save results as JSON"""
        filepath = os.path.join(REPORTS_DIR, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return filepath
    
    @staticmethod
    def save_html(data, filename):
        """Save results as HTML report"""
        filepath = os.path.join(REPORTS_DIR, filename)
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WebV Recon Report</title>
    <style>
        body {{ font-family: monospace; background: #0d0d0d; color: #00ff00; padding: 20px; }}
        h1 {{ color: #ff0033; }}
        .section {{ margin: 20px 0; padding: 15px; background: #1a1a1a; border-left: 3px solid #ff0033; }}
        pre {{ background: #000; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>WebV Reconnaissance Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <div class="section">
        <h2>Results</h2>
        <pre>{json.dumps(data, indent=2, default=str)}</pre>
    </div>
</body>
</html>"""
        with open(filepath, 'w') as f:
            f.write(html)
        return filepath

# ========= GUI =========
class WebVApp:
    def __init__(self, root):
        self.root = root
        self.root.title("webv.py - Ultimate Web Vulnerability Testing Suite")
        
        # Set reasonable default size (smaller and more manageable)
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Use 80% of screen size or default to 1400x800
        width = min(int(screen_width * 0.8), 1400)
        height = min(int(screen_height * 0.8), 800)
        
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(1000, 600)  # Smaller minimum size
        self.root.configure(bg="#0d0d0d")
        
        # Make window resizable and center it
        self.root.resizable(True, True)
        
        # Center window on screen
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        self.recon_engine = ReconEngine(self.log)
        self.recon_data = {}
        self.terminal_results = []
        self.terminal_process = None
        self.command_history = []
        self.history_index = -1
        
        # Setup SQLMap with results callback
        def sqlmap_results_log(text):
            def _log():
                self.sqlmap_results_text.insert(tk.END, text + "\n")
                self.sqlmap_results_text.see(tk.END)
            self.root.after(0, _log)
        
        self.sqlmap_manager = SQLMapManager(self.log, sqlmap_results_log)
        
        self.setup_ui()
        
    def log(self, text):
        """Thread-safe logging"""
        def _log():
            self.output.insert(tk.END, text + "\n")
            self.output.see(tk.END)
            # Also update recon results if it's recon-related
            if "[RECON]" in text or "[+]" in text or "[-]" in text:
                self.recon_results_text.insert(tk.END, text + "\n")
                self.recon_results_text.see(tk.END)
        self.root.after(0, _log)
    
    def setup_ui(self):
        """Setup the user interface"""
        # Header (more compact)
        header = tk.Frame(self.root, bg="#0d0d0d")
        header.pack(pady=(5, 3), fill=tk.X)
        tk.Label(header, text="webv.py", font=("Impact", 28, "bold"), 
                fg="#ff0033", bg="#0d0d0d").pack()
        tk.Label(header, text="Ultimate Web Vulnerability Testing Suite", 
                font=("Consolas", 9), fg="#00ff00", bg="#0d0d0d").pack()
        
        # Target input (more compact)
        top = tk.Frame(self.root, bg="#0d0d0d")
        top.pack(pady=3, padx=10, fill=tk.X)
        tk.Label(top, text="Target:", font=("Consolas", 11), 
                fg="#00ff00", bg="#0d0d0d").pack(side=tk.LEFT, padx=5)
        self.entry = tk.Entry(top, width=50, font=("Consolas", 10), 
                             bg="#1a1a1a", fg="#00ff00", insertbackground="#00ff00")
        self.entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.entry.insert(0, "http://testphp.vulnweb.com/artists.php?artist=1")
        
        # Main container with paned window for resizable split
        main_container = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashwidth=8, 
                                        bg="#0d0d0d", sashrelief=tk.RAISED, sashpad=2)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Store reference for resizing
        self.main_container = main_container
        
        # Left pane: Main tabs
        left_pane = tk.Frame(main_container, bg="#0d0d0d")
        main_container.add(left_pane, minsize=500)
        
        # Notebook for main tabs
        notebook = ttk.Notebook(left_pane)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Recon Tab
        recon_frame = tk.Frame(notebook, bg="#0d0d0d")
        notebook.add(recon_frame, text="Reconnaissance")
        self.setup_recon_tab(recon_frame)
        
        # SQLMap Tab
        sqlmap_frame = tk.Frame(notebook, bg="#0d0d0d")
        notebook.add(sqlmap_frame, text="SQLMap")
        self.setup_sqlmap_tab(sqlmap_frame)
        
        # Payloads Tab
        payloads_frame = tk.Frame(notebook, bg="#0d0d0d")
        notebook.add(payloads_frame, text="Payloads")
        self.setup_payloads_tab(payloads_frame)
        
        # Results Tab
        results_frame = tk.Frame(notebook, bg="#0d0d0d")
        notebook.add(results_frame, text="Results")
        self.setup_results_tab(results_frame)
        
        # Right pane: Persistent Terminal and Output (always visible)
        right_pane = tk.Frame(main_container, bg="#0d0d0d")
        main_container.add(right_pane, minsize=350)
        
        # Vertical paned window for terminal and output
        right_paned = tk.PanedWindow(right_pane, orient=tk.VERTICAL, sashwidth=8,
                                     bg="#0d0d0d", sashrelief=tk.RAISED, sashpad=2)
        right_paned.pack(fill=tk.BOTH, expand=True)
        
        # Store reference for resizing
        self.right_paned = right_paned
        
        # Terminal section (top of right pane)
        terminal_section = tk.Frame(right_paned, bg="#0d0d0d")
        right_paned.add(terminal_section, minsize=150)
        self.setup_persistent_terminal(terminal_section)
        
        # Output section (bottom of right pane)
        output_section = tk.Frame(right_paned, bg="#0d0d0d")
        right_paned.add(output_section, minsize=150)
        self.setup_persistent_output(output_section)
        
        # Status bar
        status = tk.Frame(self.root, bg="#0d0d0d")
        status.pack(side=tk.BOTTOM, fill=tk.X, pady=2)
        tk.Label(status, text="webv.py • Auto sqlmap • Enhanced recon • Authorized testing only", 
                fg="gray", bg="#0d0d0d", font=("Consolas", 8)).pack()
        
        self.log("[+] webv.py loaded. Terminal and output are always visible on the right.")
    
    def setup_persistent_terminal(self, parent):
        """Setup persistent terminal panel (always visible)"""
        # Terminal header (more compact)
        term_header = tk.Frame(parent, bg="#1a1a1a")
        term_header.pack(fill=tk.X, padx=3, pady=(3, 0))
        tk.Label(term_header, text="Terminal", font=("bold", 10), 
                fg="#00ff00", bg="#1a1a1a").pack(side=tk.LEFT, padx=5, pady=2)
        
        # Command input (more compact)
        input_frame = tk.Frame(parent, bg="#0d0d0d")
        input_frame.pack(fill=tk.X, padx=3, pady=2)
        
        self.terminal_entry = tk.Entry(input_frame, font=("Consolas", 9),
                                      bg="#1a1a1a", fg="#00ff00", insertbackground="#00ff00")
        self.terminal_entry.pack(side=tk.LEFT, padx=3, fill=tk.X, expand=True)
        self.terminal_entry.bind('<Return>', lambda e: self.execute_terminal_command())
        self.terminal_entry.bind('<Up>', lambda e: self.navigate_history(-1))
        self.terminal_entry.bind('<Down>', lambda e: self.navigate_history(1))
        
        tk.Button(input_frame, text="▶", command=self.execute_terminal_command,
                 bg="#ff0033", fg="white", font=("bold", 9), width=2).pack(side=tk.LEFT, padx=1)
        tk.Button(input_frame, text="⏹", command=self.stop_terminal_command,
                 bg="#900000", fg="white", font=("bold", 9), width=2).pack(side=tk.LEFT, padx=1)
        
        # Quick command buttons (more compact)
        quick_frame = tk.Frame(parent, bg="#0d0d0d")
        quick_frame.pack(fill=tk.X, padx=3, pady=1)
        
        tk.Label(quick_frame, text="Quick:", font=("Consolas", 7), 
                fg="#888", bg="#0d0d0d").pack(side=tk.LEFT, padx=1)
        
        # Smart nmap button (auto-detect target)
        smart_nmap_btn = tk.Button(quick_frame, text="🔍 Nmap", 
                                   command=self.smart_nmap,
                                   bg="#ff0033", fg="white", font=("bold", 7), width=7)
        smart_nmap_btn.pack(side=tk.LEFT, padx=1)
        
        # Nmap presets dropdown
        nmap_preset_frame = tk.Frame(quick_frame, bg="#0d0d0d")
        nmap_preset_frame.pack(side=tk.LEFT, padx=1)
        
        tk.Label(nmap_preset_frame, text="N:", font=("Consolas", 7), 
                fg="#888", bg="#0d0d0d").pack(side=tk.LEFT)
        
        self.nmap_preset_var = tk.StringVar(value="Quick")
        nmap_presets = ["Quick", "Stealth", "Full", "Aggressive", "Vuln"]
        nmap_menu = tk.OptionMenu(nmap_preset_frame, self.nmap_preset_var, *nmap_presets,
                                  command=self.apply_nmap_preset)
        nmap_menu.config(bg="#333", fg="white", font=("bold", 7), width=6)
        nmap_menu.pack(side=tk.LEFT, padx=1)
        
        # Other quick commands (smaller)
        other_commands = [
            ("curl", "curl -I "),
            ("whois", "whois "),
            ("dig", "dig "),
        ]
        
        for cmd_name, cmd_prefix in other_commands:
            btn = tk.Button(quick_frame, text=cmd_name, 
                           command=lambda cp=cmd_prefix: self.insert_command_with_target(cp),
                           bg="#333", fg="white", font=("bold", 7), width=4)
            btn.pack(side=tk.LEFT, padx=1)
        
        # Terminal output (more compact)
        term_output_frame = tk.Frame(parent, bg="#1a1a1a")
        term_output_frame.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
        
        self.terminal_output = scrolledtext.ScrolledText(term_output_frame, bg="black", fg="#00ff00", 
                                                        font=("Consolas", 8), wrap=tk.WORD)
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
    
    def setup_persistent_output(self, parent):
        """Setup persistent output panel (always visible)"""
        # Output header (more compact)
        output_header = tk.Frame(parent, bg="#1a1a1a")
        output_header.pack(fill=tk.X, padx=3, pady=(3, 0))
        tk.Label(output_header, text="Live Output", font=("bold", 10), 
                fg="#00ff00", bg="#1a1a1a").pack(side=tk.LEFT, padx=5, pady=2)
        
        clear_btn = tk.Button(output_header, text="Clear", command=self.clear_output,
                             bg="#333", fg="white", font=("bold", 7), width=5)
        clear_btn.pack(side=tk.RIGHT, padx=3, pady=1)
        
        # Output area (more compact)
        output_frame = tk.Frame(parent, bg="#1a1a1a")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
        
        self.output = scrolledtext.ScrolledText(output_frame, bg="black", fg="#00ff00", 
                                               font=("Consolas", 8), wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
    
    def clear_output(self):
        """Clear main output"""
        self.output.delete(1.0, tk.END)
    
    def setup_recon_tab(self, parent):
        """Setup reconnaissance tab"""
        frame = tk.Frame(parent, bg="#0d0d0d")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Quick recon buttons
        quick_frame = tk.Frame(frame, bg="#0d0d0d")
        quick_frame.pack(fill=tk.X, pady=10)
        
        buttons = [
            ("Basic Info", self.run_basic_info),
            ("HTTP Headers", self.run_http_headers),
            ("Tech Detection", self.run_tech_detection),
            ("Port Scan", self.run_port_scan),
            ("Subdomain Enum", self.run_subdomain_enum),
            ("Directory Brute", self.run_directory_brute),
        ]
        
        for i, (text, cmd) in enumerate(buttons):
            btn = tk.Button(quick_frame, text=text, command=cmd,
                          bg="#00aa00", fg="white", font=("bold", 11),
                          width=15, height=2)
            btn.grid(row=i//3, column=i%3, padx=5, pady=5, sticky="ew")
        
        quick_frame.columnconfigure(0, weight=1)
        quick_frame.columnconfigure(1, weight=1)
        quick_frame.columnconfigure(2, weight=1)
        
        # Full recon button
        full_frame = tk.Frame(frame, bg="#0d0d0d")
        full_frame.pack(fill=tk.X, pady=20)
        tk.Button(full_frame, text="🚀 FULL RECON (All Checks)", 
                 command=self.run_full_recon,
                 bg="#ff0033", fg="white", font=("bold", 14),
                 height=2).pack(fill=tk.X, padx=10)
        
        # Export buttons
        export_frame = tk.Frame(frame, bg="#0d0d0d")
        export_frame.pack(fill=tk.X, pady=10)
        tk.Button(export_frame, text="Export JSON", command=self.export_json,
                 bg="#333", fg="white", font=("bold", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(export_frame, text="Export HTML", command=self.export_html,
                 bg="#333", fg="white", font=("bold", 10)).pack(side=tk.LEFT, padx=5)
    
    def setup_sqlmap_tab(self, parent):
        """Setup SQLMap tab"""
        frame = tk.Frame(parent, bg="#0d0d0d")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # SQLMap options
        options_frame = tk.Frame(frame, bg="#0d0d0d")
        options_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(options_frame, text="SQLMap Options (optional):", 
                font=("Consolas", 12), fg="#00ff00", bg="#0d0d0d").pack(anchor=tk.W)
        self.sqlmap_options = tk.Entry(options_frame, width=60, font=("Consolas", 11),
                                       bg="#1a1a1a", fg="#00ff00", insertbackground="#00ff00")
        self.sqlmap_options.pack(fill=tk.X, pady=5)
        self.sqlmap_options.insert(0, "--dbs --tables --columns --dump")
        
        # Preset buttons
        preset_frame = tk.Frame(frame, bg="#0d0d0d")
        preset_frame.pack(fill=tk.X, pady=10)
        
        presets = [
            ("Quick Test", "--batch --level=1 --risk=1"),
            ("Standard", "--batch --level=3 --risk=2 --dbs"),
            ("Aggressive", "--batch --level=5 --risk=3 --dbs --tables --columns"),
            ("Full Dump", "--batch --level=5 --risk=3 --dbs --tables --columns --dump"),
        ]
        
        for text, opts in presets:
            btn = tk.Button(preset_frame, text=text, 
                             command=lambda o=opts: self.sqlmap_options.delete(0, tk.END) or self.sqlmap_options.insert(0, o),
                             bg="#333", fg="white", font=("bold", 10), width=15)
            btn.pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        control_frame = tk.Frame(frame, bg="#0d0d0d")
        control_frame.pack(fill=tk.X, pady=20)
        
        tk.Button(control_frame, text="▶ START SQLMAP", command=self.start_sqlmap,
                 bg="#ff0033", fg="white", font=("bold", 14), height=2).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        tk.Button(control_frame, text="⏹ STOP", command=self.stop_sqlmap,
                 bg="#900000", fg="white", font=("bold", 14), height=2).pack(side=tk.LEFT, padx=5)
    
    def setup_payloads_tab(self, parent):
        """Setup payloads tab"""
        frame = tk.Frame(parent, bg="#0d0d0d")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        payloads = [
            ("XSS Basic", '<script>alert("XSS")</script>'),
            ("XSS Advanced", '<img src=x onerror=alert("XSS")>'),
            ("LFI", '../../../../etc/passwd'),
            ("LFI PHP", '....//....//....//etc/passwd'),
            ("RCE Unix", ';id;whoami'),
            ("RCE Windows", '&whoami'),
            ("SSRF", 'http://169.254.169.254/latest/meta-data/'),
            ("SQLi Basic", "' OR '1'='1"),
            ("SQLi Union", "' UNION SELECT NULL--"),
            ("Command Injection", ';cat /etc/passwd'),
            ("Path Traversal", '....//....//....//windows/win.ini'),
            ("XXE", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
        ]
        
        # Create grid of payload buttons
        payload_frame = tk.Frame(frame, bg="#0d0d0d")
        payload_frame.pack(fill=tk.BOTH, expand=True)
        
        for i, (name, payload) in enumerate(payloads):
            row = i // 3
            col = i % 3
            
            btn_frame = tk.Frame(payload_frame, bg="#1a1a1a", relief=tk.RAISED, borderwidth=2)
            btn_frame.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")
            
            tk.Label(btn_frame, text=name, font=("bold", 11), 
                    fg="#ff0033", bg="#1a1a1a").pack(pady=5)
            tk.Label(btn_frame, text=payload[:50] + ("..." if len(payload) > 50 else ""), 
                    font=("Consolas", 9), fg="#00ff00", bg="#1a1a1a", wraplength=200).pack(pady=2)
            tk.Button(btn_frame, text="Copy", 
                     command=lambda p=payload: self.copy_payload(p),
                     bg="#ff0033", fg="white", font=("bold", 9), width=10).pack(pady=5)
        
        payload_frame.columnconfigure(0, weight=1)
        payload_frame.columnconfigure(1, weight=1)
        payload_frame.columnconfigure(2, weight=1)
    
    def setup_terminal_tab(self, parent):
        """Setup terminal tab with additional info (terminal is now persistent)"""
        frame = tk.Frame(parent, bg="#0d0d0d")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        info_frame = tk.Frame(frame, bg="#1a1a1a", relief=tk.RAISED, borderwidth=2)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        info_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                          TERMINAL INFORMATION                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

The Terminal is now ALWAYS VISIBLE on the right side of the application!

You can:
  • Execute commands directly from the persistent terminal panel
  • Use {target} placeholder to auto-insert the target URL
  • Navigate command history with Up/Down arrows
  • View output in real-time

Quick Commands Available:
  • nmap - Network scanning
  • curl - HTTP requests
  • whois - Domain information

Examples:
  • nmap -sV -p- {target}
  • curl -I {target}
  • whois {target}

All terminal output is also saved to the Results tab for later review.
        """
        
        info_label = tk.Label(info_frame, text=info_text, font=("Consolas", 10),
                             fg="#00ff00", bg="#1a1a1a", justify=tk.LEFT, anchor="nw")
        info_label.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
    
    def setup_results_tab(self, parent):
        """Setup results tab to display all results"""
        frame = tk.Frame(parent, bg="#0d0d0d")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Results header with actions
        header_frame = tk.Frame(frame, bg="#0d0d0d")
        header_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(header_frame, text="Results & Findings", font=("bold", 16), 
                fg="#ff0033", bg="#0d0d0d").pack(side=tk.LEFT)
        
        action_frame = tk.Frame(header_frame, bg="#0d0d0d")
        action_frame.pack(side=tk.RIGHT)
        
        tk.Button(action_frame, text="Clear Results", command=self.clear_results,
                 bg="#333", fg="white", font=("bold", 10), width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Export All", command=self.export_all_results,
                 bg="#00aa00", fg="white", font=("bold", 10), width=12).pack(side=tk.LEFT, padx=5)
        
        # Results display with tabs
        results_notebook = ttk.Notebook(frame)
        results_notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Recon Results
        recon_results_frame = tk.Frame(results_notebook, bg="#0d0d0d")
        results_notebook.add(recon_results_frame, text="Recon Results")
        self.recon_results_text = scrolledtext.ScrolledText(recon_results_frame, bg="black", 
                                                           fg="#00ff00", font=("Consolas", 10), wrap=tk.WORD)
        self.recon_results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Terminal Results
        term_results_frame = tk.Frame(results_notebook, bg="#0d0d0d")
        results_notebook.add(term_results_frame, text="Terminal Results")
        self.term_results_text = scrolledtext.ScrolledText(term_results_frame, bg="black", 
                                                          fg="#00ff00", font=("Consolas", 10), wrap=tk.WORD)
        self.term_results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # SQLMap Results
        sqlmap_results_frame = tk.Frame(results_notebook, bg="#0d0d0d")
        results_notebook.add(sqlmap_results_frame, text="SQLMap Results")
        self.sqlmap_results_text = scrolledtext.ScrolledText(sqlmap_results_frame, bg="black", 
                                                            fg="#00ff00", font=("Consolas", 10), wrap=tk.WORD)
        self.sqlmap_results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Summary
        summary_frame = tk.Frame(results_notebook, bg="#0d0d0d")
        results_notebook.add(summary_frame, text="Summary")
        self.summary_text = scrolledtext.ScrolledText(summary_frame, bg="black", 
                                                      fg="#00ff00", font=("Consolas", 10), wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Initialize with welcome message
        self.update_summary()
    
    def get_target_host(self):
        """Extract host/IP from target URL"""
        target = self.entry.get().strip()
        if not target:
            return None
        
        # Remove protocol
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            host = parsed.netloc or parsed.path.split("/")[0]
        else:
            host = target.split("/")[0].split("?")[0]
        
        # Remove port if present
        if ":" in host:
            host = host.split(":")[0]
        
        return host
    
    def smart_nmap(self):
        """Smart nmap - auto-detect target and use intelligent scan"""
        host = self.get_target_host()
        if not host:
            messagebox.showwarning("No Target", "Enter a target URL first!")
            return
        
        preset = self.nmap_preset_var.get()
        
        # Smart detection: check if we have recon data
        use_stealth = False
        if hasattr(self, 'recon_engine') and self.recon_engine.results:
            # If we found open ports, use them for faster scan
            open_ports = self.recon_engine.results.get('open_ports', [])
            if open_ports:
                ports_str = ','.join(map(str, open_ports))
                nmap_commands = {
                    "Quick": f"nmap -sV -T4 -p {ports_str} {host}",
                    "Stealth": f"nmap -sS -T2 -f -p {ports_str} {host}",
                    "Full": f"nmap -sV -sC -A -p {ports_str} {host}",
                    "Aggressive": f"nmap -sV -sC -A -p {ports_str} --script vuln -T4 {host}",
                    "Vuln": f"nmap -sV --script vuln -p {ports_str} -T4 {host}"
                }
            else:
                nmap_commands = {
                    "Quick": f"nmap -sV -T4 --top-ports 1000 {host}",
                    "Stealth": f"nmap -sS -T2 -f --top-ports 100 {host}",
                    "Full": f"nmap -sV -sC -A -p- -T4 {host}",
                    "Aggressive": f"nmap -sV -sC -A -p- --script vuln -T4 {host}",
                    "Vuln": f"nmap -sV --script vuln -p- -T4 {host}"
                }
        else:
            # Default smart scan - start with quick, then suggest full
            nmap_commands = {
                "Quick": f"nmap -sV -T4 --top-ports 1000 {host}",
                "Stealth": f"nmap -sS -T2 -f --top-ports 100 {host}",
                "Full": f"nmap -sV -sC -A -p- -T4 {host}",
                "Aggressive": f"nmap -sV -sC -A -p- --script vuln -T4 {host}",
                "Vuln": f"nmap -sV --script vuln -p- -T4 {host}"
            }
        
        command = nmap_commands.get(preset, nmap_commands["Quick"])
        self.terminal_entry.delete(0, tk.END)
        self.terminal_entry.insert(0, command)
        
        # Log smart detection
        self.log(f"[SMART NMAP] Using {preset} scan for {host}")
        if hasattr(self, 'recon_engine') and self.recon_engine.results:
            open_ports = self.recon_engine.results.get('open_ports', [])
            if open_ports:
                self.log(f"[SMART NMAP] Detected {len(open_ports)} open ports, scanning specific ports")
        
        # Auto-execute
        self.execute_terminal_command()
    
    def apply_nmap_preset(self, preset):
        """Apply nmap preset to terminal with smart detection"""
        host = self.get_target_host()
        if not host:
            # Still allow setting command without target
            nmap_commands = {
                "Quick": "nmap -sV -T4 --top-ports 1000 ",
                "Stealth": "nmap -sS -T2 -f --top-ports 100 ",
                "Full": "nmap -sV -sC -A -p- -T4 ",
                "Aggressive": "nmap -sV -sC -A -p- --script vuln -T4 ",
                "Vuln": "nmap -sV --script vuln -p- -T4 "
            }
            command = nmap_commands.get(preset, nmap_commands["Quick"])
            self.terminal_entry.delete(0, tk.END)
            self.terminal_entry.insert(0, command)
            return
        
        # Smart detection: use known ports if available
        if hasattr(self, 'recon_engine') and self.recon_engine.results:
            open_ports = self.recon_engine.results.get('open_ports', [])
            if open_ports:
                ports_str = ','.join(map(str, open_ports))
                nmap_commands = {
                    "Quick": f"nmap -sV -T4 -p {ports_str} {host}",
                    "Stealth": f"nmap -sS -T2 -f -p {ports_str} {host}",
                    "Full": f"nmap -sV -sC -A -p {ports_str} {host}",
                    "Aggressive": f"nmap -sV -sC -A -p {ports_str} --script vuln -T4 {host}",
                    "Vuln": f"nmap -sV --script vuln -p {ports_str} -T4 {host}"
                }
            else:
                nmap_commands = {
                    "Quick": f"nmap -sV -T4 --top-ports 1000 {host}",
                    "Stealth": f"nmap -sS -T2 -f --top-ports 100 {host}",
                    "Full": f"nmap -sV -sC -A -p- -T4 {host}",
                    "Aggressive": f"nmap -sV -sC -A -p- --script vuln -T4 {host}",
                    "Vuln": f"nmap -sV --script vuln -p- -T4 {host}"
                }
        else:
            nmap_commands = {
                "Quick": f"nmap -sV -T4 --top-ports 1000 {host}",
                "Stealth": f"nmap -sS -T2 -f --top-ports 100 {host}",
                "Full": f"nmap -sV -sC -A -p- -T4 {host}",
                "Aggressive": f"nmap -sV -sC -A -p- --script vuln -T4 {host}",
                "Vuln": f"nmap -sV --script vuln -p- -T4 {host}"
            }
        
        command = nmap_commands.get(preset, nmap_commands["Quick"])
        self.terminal_entry.delete(0, tk.END)
        self.terminal_entry.insert(0, command)
    
    def insert_command_with_target(self, cmd_prefix):
        """Insert command with auto-target"""
        host = self.get_target_host()
        if host:
            self.terminal_entry.insert(tk.END, cmd_prefix + host)
        else:
            self.terminal_entry.insert(tk.END, cmd_prefix)
    
    def execute_terminal_command(self):
        """Execute terminal command"""
        command = self.terminal_entry.get().strip()
        if not command:
            messagebox.showwarning("Empty", "Enter a command!")
            return
        
        if self.terminal_process and self.terminal_process.poll() is None:
            messagebox.showinfo("Running", "Command already running! Stop it first.")
            return
        
        # Add to history
        if command not in self.command_history:
            self.command_history.append(command)
        self.history_index = len(self.command_history)
        
        # Display command
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.terminal_output.insert(tk.END, f"\n[{timestamp}] $ {command}\n")
        self.terminal_output.insert(tk.END, "=" * 80 + "\n")
        self.terminal_output.see(tk.END)
        
        # Also add to results
        self.term_results_text.insert(tk.END, f"\n[{timestamp}] $ {command}\n")
        self.term_results_text.insert(tk.END, "=" * 80 + "\n")
        self.term_results_text.see(tk.END)
        
        # Execute command
        def run_command():
            try:
                # Auto-replace {target} placeholder if exists
                host = self.get_target_host()
                if host and "{target}" in command:
                    cmd = command.replace("{target}", host)
                else:
                    cmd = command
                
                # Split command for shell execution
                self.terminal_process = subprocess.Popen(
                    cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1, universal_newlines=True
                )
                
                for line in self.terminal_process.stdout:
                    def update_output(line=line):
                        self.terminal_output.insert(tk.END, line)
                        self.terminal_output.see(tk.END)
                        self.term_results_text.insert(tk.END, line)
                        self.term_results_text.see(tk.END)
                    self.root.after(0, update_output)
                
                def finish():
                    self.terminal_output.insert(tk.END, f"\n[+] Command finished (exit code: {self.terminal_process.returncode})\n")
                    self.terminal_output.see(tk.END)
                    self.term_results_text.insert(tk.END, f"\n[+] Command finished (exit code: {self.terminal_process.returncode})\n")
                    self.term_results_text.see(tk.END)
                    self.update_summary()
                self.root.after(0, finish)
                
            except Exception as e:
                error_msg = f"[-] Error executing command: {e}\n"
                def show_error():
                    self.terminal_output.insert(tk.END, error_msg)
                    self.terminal_output.see(tk.END)
                    self.term_results_text.insert(tk.END, error_msg)
                    self.term_results_text.see(tk.END)
                self.root.after(0, show_error)
        
        threading.Thread(target=run_command, daemon=True).start()
    
    def stop_terminal_command(self):
        """Stop running terminal command"""
        if self.terminal_process and self.terminal_process.poll() is None:
            self.terminal_process.terminate()
            self.terminal_output.insert(tk.END, "\n[!] Command stopped by user.\n")
            self.terminal_output.see(tk.END)
            self.term_results_text.insert(tk.END, "\n[!] Command stopped by user.\n")
            self.term_results_text.see(tk.END)
            return True
        return False
    
    def navigate_history(self, direction):
        """Navigate command history with up/down arrows"""
        if not self.command_history:
            return
        
        if direction == -1:  # Up arrow
            if self.history_index > 0:
                self.history_index -= 1
        else:  # Down arrow
            if self.history_index < len(self.command_history) - 1:
                self.history_index += 1
            else:
                self.terminal_entry.delete(0, tk.END)
                return
        
        self.terminal_entry.delete(0, tk.END)
        self.terminal_entry.insert(0, self.command_history[self.history_index])
        return "break"
    
    def clear_terminal_output(self):
        """Clear terminal output"""
        if hasattr(self, 'terminal_output'):
            self.terminal_output.delete(1.0, tk.END)
    
    def clear_results(self):
        """Clear all results"""
        if messagebox.askyesno("Confirm", "Clear all results?"):
            self.recon_results_text.delete(1.0, tk.END)
            self.term_results_text.delete(1.0, tk.END)
            self.sqlmap_results_text.delete(1.0, tk.END)
            self.summary_text.delete(1.0, tk.END)
            self.update_summary()
    
    def update_summary(self):
        """Update summary tab with current findings"""
        self.summary_text.delete(1.0, tk.END)
        
        summary = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          WEBV.PY RESULTS SUMMARY                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[RECONNAISSANCE RESULTS]
"""
        
        if self.recon_engine.results:
            summary += f"""
✓ Reconnaissance data collected
  - IP Address: {self.recon_engine.results.get('ip', 'N/A')}
  - Open Ports: {len(self.recon_engine.results.get('open_ports', []))} found
  - Subdomains: {len(self.recon_engine.results.get('subdomains', []))} found
  - Directories: {len(self.recon_engine.results.get('directories', []))} found
  - Technologies: {', '.join(self.recon_engine.results.get('technologies', [])) or 'None detected'}
"""
        else:
            summary += "  No reconnaissance data yet. Run recon checks first.\n"
        
        summary += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        summary += "[TERMINAL COMMANDS]\n"
        
        if hasattr(self, 'command_history') and self.command_history:
            summary += f"  Commands executed: {len(self.command_history)}\n"
            summary += "  Recent commands:\n"
            for cmd in self.command_history[-5:]:
                summary += f"    - {cmd}\n"
        else:
            summary += "  No commands executed yet.\n"
        
        summary += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        summary += "[SQLMAP]\n"
        summary += "  Check SQLMap tab for execution status.\n"
        summary += "  Results saved to: ./loot/\n"
        
        summary += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        summary += "[EXPORT OPTIONS]\n"
        summary += "  - Use 'Export JSON' in Recon tab for structured data\n"
        summary += "  - Use 'Export HTML' in Recon tab for formatted reports\n"
        summary += "  - Use 'Export All' button above to save all results\n"
        
        self.summary_text.insert(1.0, summary)
    
    def export_all_results(self):
        """Export all results to a file"""
        filename = f"all_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(REPORTS_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WEBV.PY - COMPLETE RESULTS EXPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("RECONNAISSANCE RESULTS\n")
            f.write("=" * 80 + "\n")
            f.write(self.recon_results_text.get(1.0, tk.END))
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("TERMINAL RESULTS\n")
            f.write("=" * 80 + "\n")
            f.write(self.term_results_text.get(1.0, tk.END))
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("SQLMAP RESULTS\n")
            f.write("=" * 80 + "\n")
            f.write(self.sqlmap_results_text.get(1.0, tk.END))
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("SUMMARY\n")
            f.write("=" * 80 + "\n")
            f.write(self.summary_text.get(1.0, tk.END))
        
        self.log(f"[+] All results exported to: {filepath}")
        messagebox.showinfo("Exported", f"All results saved to:\n{filepath}")
    
    def copy_payload(self, payload):
        """Copy payload to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(payload)
        self.log(f"[+] Payload copied to clipboard: {payload[:50]}...")
    
    def run_basic_info(self):
        target = self.entry.get().strip()
        if not target:
            messagebox.showwarning("Empty", "Enter target URL!")
            return
        threading.Thread(target=lambda: self.recon_engine.basic_info(target), daemon=True).start()
    
    def run_http_headers(self):
        target = self.entry.get().strip()
        if not target:
            messagebox.showwarning("Empty", "Enter target URL!")
            return
        threading.Thread(target=lambda: self.recon_engine.http_headers(target), daemon=True).start()
    
    def run_tech_detection(self):
        target = self.entry.get().strip()
        if not target:
            messagebox.showwarning("Empty", "Enter target URL!")
            return
        threading.Thread(target=lambda: self.recon_engine.technology_detection(target), daemon=True).start()
    
    def run_port_scan(self):
        target = self.entry.get().strip()
        if not target:
            messagebox.showwarning("Empty", "Enter target URL!")
            return
        threading.Thread(target=lambda: self.recon_engine.port_scan(target), daemon=True).start()
    
    def run_subdomain_enum(self):
        target = self.entry.get().strip()
        if not target:
            messagebox.showwarning("Empty", "Enter target URL!")
            return
        threading.Thread(target=lambda: self.recon_engine.subdomain_enum(target), daemon=True).start()
    
    def run_directory_brute(self):
        target = self.entry.get().strip()
        if not target:
            messagebox.showwarning("Empty", "Enter target URL!")
            return
        threading.Thread(target=lambda: self.recon_engine.directory_bruteforce(target), daemon=True).start()
    
    def run_full_recon(self):
        target = self.entry.get().strip()
        if not target:
            messagebox.showwarning("Empty", "Enter target URL!")
            return
        
        def full_recon():
            self.log("\n" + "="*80)
            self.log("[+] STARTING FULL RECONNAISSANCE")
            self.log("="*80)
            self.recon_engine.basic_info(target)
            self.recon_engine.http_headers(target)
            self.recon_engine.technology_detection(target)
            self.recon_engine.port_scan(target)
            self.recon_engine.subdomain_enum(target)
            self.recon_engine.directory_bruteforce(target)
            self.log("\n[+] Full reconnaissance complete!")
            self.recon_data = self.recon_engine.results
            self.root.after(0, self.update_summary)
        
        threading.Thread(target=full_recon, daemon=True).start()
    
    def start_sqlmap(self):
        target = self.entry.get().strip()
        if not target:
            messagebox.showwarning("Empty", "Enter target URL!")
            return
        
        options = self.sqlmap_options.get().strip()
        success, msg = self.sqlmap_manager.run(target, options if options else None)
        if not success:
            messagebox.showinfo("Info", msg)
    
    def stop_sqlmap(self):
        self.sqlmap_manager.stop()
    
    def export_json(self):
        if not self.recon_engine.results:
            messagebox.showwarning("No Data", "Run reconnaissance first!")
            return
        filename = f"recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = ReportGenerator.save_json(self.recon_engine.results, filename)
        self.log(f"[+] Report saved: {filepath}")
        messagebox.showinfo("Exported", f"Report saved to:\n{filepath}")
    
    def export_html(self):
        if not self.recon_engine.results:
            messagebox.showwarning("No Data", "Run reconnaissance first!")
            return
        filename = f"recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = ReportGenerator.save_html(self.recon_engine.results, filename)
        self.log(f"[+] Report saved: {filepath}")
        messagebox.showinfo("Exported", f"Report saved to:\n{filepath}")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebVApp(root)
    root.mainloop()
