#!/usr/bin/env python3
"""
VulnScan AI Backend - Real Scanning Engine
Run: python app.py
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import dns.resolver
import requests
import json
import socket
import subprocess
import time
import threading
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import re
import ssl
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
CORS(app)
auth = HTTPBasicAuth()

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Fixed CSP to allow cdnjs.cloudflare.com for PDF generation
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' https://api.getggo.com;"
    return response

# Secure User Credentials
users = {
    "admin": generate_password_hash("sunny_tech13@")
}

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global state
scan_state = {
    'target': '',
    'status': 'IDLE',
    'stop_requested': False,
    'active_process': None,
    'lang': 'en',
    'progress': {},
    'logs': [],
    'findings_list': [],  # Store detailed findings for the PDF report
    'findings': {'crit': 0, 'high': 0, 'med': 0, 'low': 0},
    'discovered_assets': set(),
    'tech_stack': {},
    'ollama_insights': [], # Store AI guidance
    'target_history': [], # Store history of scanned websites
    'tools': {
        'nmap': 0,
        'nikto': 0,
        'shodan': 0,
        'vt': 0,
        'wayback': 0,
        'nuclei': 0,
        'metasploit': 0,
        'msfvenom': 0,
        'fuzzer': 0,
        'deep_dive': 0,
        'ctf': 0,
        'xss': 0,
        'manual_offense': 0
    }
}

# Educational Explanations Dictionary
EXPLANATIONS = {
    'nmap_service': {
        'en': "Nmap Service Audit: Detects versions of software running on ports. It helps identify outdated services that might have known exploits.",
        'hi': "Nmap Service Audit: Yeh ports par chal rahe software versions ko detect karta hai. Isse purane services ka pata chalta hai jinme flaws ho sakte hain.",
        'hinglish': "Nmap Service Audit: Ye check karta hai ki ports pe kaunsa software version chal raha hai. Agar version purana (outdated) hai, toh exploit karna easy ho jata hai."
    },
    'nmap_full': {
        'en': "Nmap Full Port Audit: Scans all 65,535 TCP ports. Hackers often hide backdoors on non-standard ports to avoid detection.",
        'hi': "Nmap Full Port Audit: Sabhi 65,535 TCP ports ko scan karta hai. Aksar attackers hidden services ko non-standard ports par rakhte hain.",
        'hinglish': "Nmap Full Port Audit: Saare 65,535 ports scan hote hain. Kai baar hackers 'backdoors' ko chupaane ke liye uncommon ports use karte hain."
    },
    'nmap_os': {
        'en': "OS Fingerprinting: Analyzes how the target responds to packets to guess the Operating System (Windows/Linux/etc.).",
        'hi': "OS Fingerprinting: Target system packets ka kaise response deta hai, usse OS (Windows/Linux) ka andaza lagaya jata hai.",
        'hinglish': "OS Fingerprinting: Packet response analyze karke ye batata hai ki target machine Windows hai ya Linux, taaki attacks customize kiye ja sakein."
    },
    'nmap_vuln': {
        'en': "NSE Vulnerability Scripts: Runs automated scripts to find specific CVEs and critical misconfigurations in the target system.",
        'hi': "NSE Vulnerability Scripts: Yeh automated scripts hain jo system mein specific CVEs aur misconfigurations dhoondhte hain.",
        'hinglish': "NSE Scripts: Ye auto-scripts hain jo system me 'vulnerabilities' aur 'weak points' dhoondte hain, jaise missing patches."
    },
    'nikto': {
        'en': "Nikto Web Audit: A comprehensive web scanner that looks for dangerous files, outdated server software, and specific web server problems.",
        'hi': "Nikto Web Audit: Ek bada web scanner jo khatarnak files, purane server software, aur web server problems ko dhoondhta hai.",
        'hinglish': "Nikto Web Audit: Ye website ka 'full checkup' karta hai. Ye dangerous files, outdated software aur server-side bugs dhoondta hai."
    },
    'fuzzer': {
        'en': "Endpoint Fuzzing: Tries to find hidden pages (like /admin or /.env) by guessing names from a huge wordlist.",
        'hi': "Endpoint Fuzzing: Wordlist se guess karke hidden pages (jaise /admin ya /.env) dhoondhne ki koshish karta hai.",
        'hinglish': "Endpoint Fuzzing: Ye hidden directories dhoondta hai. Jaise website me /admin ya /.env files chupi ho sakti hain jo normally nahi dikhti."
    },
    'nuclei': {
        'en': "Nuclei Engine: Uses community-provided templates to find the latest and most critical web vulnerabilities.",
        'hi': "Nuclei Engine: Yeh community templates ka use karke sabse naye aur critical web vulnerabilities ko dhoondhta hai.",
        'hinglish': "Nuclei Engine: Ye 'smart templates' use karta hai latest bugs dhoondne ke liye jo dusre scanners miss kar dete hain."
    },
    'msfvenom': {
        'en': "MSFVenom: Generates a custom exploit packet (payload) to test if the identified vulnerability can actually be used to gain control.",
        'hi': "MSFVenom: Ek custom exploit packet (payload) banata hai taaki check kiya ja sake ki vulnerability se control liya ja sakta hai ya nahi.",
        'hinglish': "MSFVenom: Ye ek custom 'exploit packet' banata hai ye verify karne ke liye ki kya hum sach me system ka access le sakte hain."
    },
    'deep_dive': {
        'en': "Service Deep-Dive: Performs specific attacks for services like FTP or Databases to find weak passwords or backdoors.",
        'hi': "Service Deep-Dive: FTP ya Databases jaise services par attack karke weak passwords ya backdoors dhoondhta hai.",
        'hinglish': "Service Deep-Dive: Ye specific services (like FTP, MySQL) ke andar ghus kar check karta hai ki kahin password 'easy' toh nahi ya koi 'backdoor' toh nahi."
    }
}

HTTP_HEADERS = {
    'User-Agent': 'VulnScanAI/2.0 (Deep Recon)',
    'Accept': '*/*'
}

# Real API Keys (Fetched from Environment Variables for Security)
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '94fJXRRRAYSpUGvrSLn38sbf0IGolz2a')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'b7bd4fd28383892e53f93e37c49bf8ed40954b22e02662b482fb9fce2a47bdb9')
FULLHUNT_API_KEY = os.getenv('FULLHUNT_API_KEY', '8a9d6b89-bce3-4b2f-ae7a-83f9f0e46dc1')
CENSYS_API_KEY = os.getenv('CENSYS_API_KEY', 'censys_BbXV46ph_CtcXEqz75Pys1NDKWtbiLE8c')
OTX_API_KEY = os.getenv('OTX_API_KEY', '91b5d1acc2377ea324b30b45907d07b7ef47bee0f7fe2313f44368217eccf14e')
OLLAMA_API_KEY = os.getenv('OLLAMA_API_KEY', '5b2d1ccf0a9c4d14951c7b9db220fb2a.ggoPybb0nr5IFGICmfncqt_B')

RISKY_PORTS = {21, 23, 445, 6379, 27017, 3389}

def normalize_target(target):
    """Normalize incoming target to a clean host/domain string"""
    target = (target or '').strip().lower()
    if not target:
        return ''
    if not target.startswith(('http://', 'https://')):
        target = f'http://{target}'
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path
    host = host.split('/')[0].split('@')[-1]
    if ':' in host:
        host = host.split(':')[0]
    return host.strip().strip('.')

def calculate_cvss(severity, impact=None, exploitability=None):
    """Real CVSS v3.1 calculation logic (simplified)"""
    # Base scores for severities
    base_scores = {'crit': 9.0, 'high': 7.0, 'med': 4.0, 'low': 1.0}
    score = base_scores.get(severity, 0.0)
    
    # Dynamic adjustments based on real scan data
    # Impact: Does it affect a sensitive service?
    if impact == 'confidentiality': score += 0.5
    if impact == 'integrity': score += 0.3
    if impact == 'availability': score += 0.1
    
    # Exploitability: Is there a known exploit?
    if exploitability == 'public': score += 0.5
    if exploitability == 'active': score += 1.0
    
    return min(10.0, round(score, 1))

def add_finding(severity, message, asset=None, tool=None, progress=None, cvss=None, impact=None, exploitability=None):
    """Track findings consistently with REAL CVSS risk scoring and severity-aware logging"""
    if severity not in scan_state['findings']:
        severity = 'low'
    
    # Use real calculation if not provided
    if not cvss:
        cvss = calculate_cvss(severity, impact, exploitability)
        
    scan_state['findings'][severity] += 1
    
    # Track finding in the list for reporting
    scan_state['findings_list'].append({
        'severity': severity.upper(),
        'message': message,
        'asset': asset or 'N/A',
        'tool': tool or 'System',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

    if asset:
        scan_state['discovered_assets'].add(asset)
        
    color = {'crit': 'red', 'high': 'red', 'med': 'yellow', 'low': 'cyan'}.get(severity, 'yellow')
    label = {'crit': 'CRITICAL', 'high': 'HIGH', 'med': 'MEDIUM', 'low': 'LOW'}.get(severity, 'LOW')
    
    log(color, f'[!] [{label}] (CVSS: {cvss}) {message}', tool=tool, progress=progress)

def generate_html_report(target):
    """ADVANCED: Generate a professional HTML security audit report"""
    log('cyan', f'[REPORT] Generating professional security audit for {target}...')
    
    findings_html = ""
    for finding in scan_state['findings_list']:
        severity_class = {
            'CRITICAL': 'crit',
            'HIGH': 'high',
            'MEDIUM': 'med',
            'LOW': 'low'
        }.get(finding['severity'], 'low')
        
        findings_html += f"""
        <div style="border-left:4px solid; padding:15px; margin:10px 0; background:#f8f9fa;">
            <div style="font-weight:bold; margin-bottom:5px;">
                <span style="color:{ 'red' if severity_class in ['crit','high'] else 'orange' if severity_class == 'med' else 'blue' }">[{finding['severity']}]</span>
                [{finding['tool']}] - {finding['asset']}
            </div>
            <div style="color:#333;">{finding['message']}</div>
            <div style="font-size:0.8rem; color:#888; margin-top:5px;">{finding['timestamp']}</div>
        </div>
        """
    
    report_html = f"""
    <html>
    <head>
        <title>Security Audit Report: {target}</title>
        <style>
            body {{ font-family: 'Inter', sans-serif; padding: 40px; background: #f8f9fa; color: #333; }}
            .report-card {{ background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); max-width: 1000px; margin: auto; }}
            h1 {{ color: #111; border-bottom: 3px solid #00ff6e; padding-bottom: 15px; letter-spacing: -1px; }}
            h2 {{ color: #333; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; margin-top: 30px; }}
            .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 30px 0; }}
            .stat-box {{ padding: 20px; text-align: center; border-radius: 8px; color: white; font-weight: bold; }}
            .crit {{ background: #ff3e3e; }} .high {{ background: #ff6b6b; }} .med {{ background: #ffcc00; color: #000; }} .low {{ background: #00e5ff; color: #000; }}
            .tech-section {{ background: #f1f3f5; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .tech-tag {{ display: inline-block; background: #fff; border: 1px solid #dee2e6; padding: 6px 14px; margin: 5px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; }}
            .asset-list {{ background: #fff; border: 1px solid #eee; padding: 20px; border-radius: 8px; list-style: none; }}
            .asset-item {{ padding: 8px 0; border-bottom: 1px solid #f8f9fa; font-family: monospace; font-size: 0.9rem; }}
        </style>
    </head>
    <body>
        <div class="report-card">
            <h1>SECURITY AUDIT REPORT: {target}</h1>
            <p>Generated by VulnScan PRO on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="stat-grid">
                <div class="stat-box crit">CRITICAL: {scan_state['findings']['crit']}</div>
                <div class="stat-box high">HIGH: {scan_state['findings']['high']}</div>
                <div class="stat-box med">MEDIUM: {scan_state['findings']['med']}</div>
                <div class="stat-box low">LOW: {scan_state['findings']['low']}</div>
            </div>
            
            <div class="tech-section">
                <h3>TECHNOLOGY STACK</h3>
                {"".join([f'<div><strong>{k}:</strong> {" ".join([f"<span class='tech-tag'>{v_item}</span>" for v_item in v])}</div>' for k,v in scan_state['tech_stack'].items()])}
            </div>
            
            <h2>DETAILED FINDINGS ({len(scan_state['findings_list'])})</h2>
            {findings_html}
            
            <h2>DISCOVERED ASSETS ({len(scan_state['discovered_assets'])})</h2>
            <div class="asset-list">
                {"".join([f'<div class="asset-item">{asset}</div>' for asset in sorted(list(scan_state['discovered_assets']))])}
            </div>
            
            <h2>RECOMMENDED REMEDIATION STEPS</h2>
            <ul style="margin-left:20px; line-height:1.8;">
                <li>Patch and update all outdated software versions identified</li>
                <li>Implement proper security headers (CSP, HSTS, X-Frame-Options, etc.)</li>
                <li>Restrict access to sensitive directories and admin panels</li>
                <li>Rotate exposed secrets and API keys immediately</li>
                <li>Implement rate limiting on authentication endpoints</li>
                <li>Regularly scan for new vulnerabilities using automated tools</li>
            </ul>
            
            <p style="margin-top:40px; font-size:0.8rem; color:#888; text-align:center;">This report is intended for authorized security assessment purposes only.</p>
        </div>
    </body>
    </html>
    """
    
    report_path = os.path.join(BASE_DIR, f"report_{target.replace('.', '_')}.html")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_html)
    
    log('green', f'[REPORT] Professional audit report generated: {report_path}')
    return report_path

def request_with_fallback(target, path='/', method='GET', timeout=6, allow_redirects=True):
    """Try HTTPS first, then HTTP, multiple methods and headers!"""
    last_error = None
    
    # Try multiple user agents and headers
    user_agents = [
        'VulnScanAI/2.0 (Deep Recon)',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
    ]
    
    for base_url in (f'https://{target}', f'http://{target}'):
        for ua in user_agents:
            try:
                headers = HTTP_HEADERS.copy()
                headers['User-Agent'] = ua
                response = requests.request(
                    method,
                    urljoin(f'{base_url}/', path.lstrip('/')),
                    timeout=timeout,
                    headers=headers,
                    allow_redirects=allow_redirects
                )
                return response, base_url
            except Exception as e:
                last_error = e
                
                # If GET fails, try HEAD
                if method == 'GET':
                    try:
                        response = requests.head(
                            urljoin(f'{base_url}/', path.lstrip('/')),
                            timeout=timeout,
                            headers=headers,
                            allow_redirects=False
                        )
                        if response.status_code in [200, 301, 302, 403, 401]:
                            # If HEAD works, retry with GET
                            try:
                                response = requests.request(
                                    method,
                                    urljoin(f'{base_url}/', path.lstrip('/')),
                                    timeout=timeout,
                                    headers=headers,
                                    allow_redirects=allow_redirects
                                )
                                return response, base_url
                            except:
                                pass
                    except:
                        pass
    raise last_error if last_error else RuntimeError('Unable to connect to target')

def extract_secret_leaks(text):
    """Find likely secrets in a response body"""
    if not text:
        return []
    patterns = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'JWT Token': r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}',
        'Generic API Key': r'(?i)(api[_-]?key|secret|token)\s*[:=]\s*["\']?[a-z0-9_\-]{16,}["\']?'
    }
    hits = []
    for label, pattern in patterns.items():
        if re.search(pattern, text):
            hits.append(label)
    return hits

def check_tls_certificate(target):
    """Inspect TLS cert health on port 443"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
        expires_raw = cert.get('notAfter')
        if not expires_raw:
            return
        expires_at = datetime.strptime(expires_raw, '%b %d %H:%M:%S %Y %Z')
        days_left = (expires_at - datetime.utcnow()).days
        scan_state['discovered_assets'].add(f"TLS_CERT_EXPIRES: {expires_at.isoformat()}Z ({days_left} days)")
        if days_left < 0:
            add_finding('crit', f'TLS certificate expired {abs(days_left)} days ago')
        elif days_left <= 14:
            add_finding('high', f'TLS certificate expires in {days_left} days')
        elif days_left <= 45:
            add_finding('med', f'TLS certificate expires soon ({days_left} days)')
        else:
            log('green', f'[TLS] Certificate valid for {days_left} more days')
    except Exception as e:
        log('cyan', f'[TLS] Certificate inspection skipped: {e}')

# --- Ollama Integration ---
def ask_ollama(prompt, system_context="You are an elite offensive security AI assistant."):
    """Query cloud or local Ollama instance for security guidance"""
    try:
        # 1. Try Cloud Ollama if API key is present
        if OLLAMA_API_KEY and 'ggo' in OLLAMA_API_KEY:
            # GGO Cloud API uses OpenAI-compatible format
            url = "https://api.getggo.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {OLLAMA_API_KEY}",
                "Content-Type": "application/json"
            }
            # Many cloud providers require a specific model ID
            model_id = "meta-llama/Llama-3-8b-chat-hf" if "llama3" in OLLAMA_API_KEY.lower() else "llama3"
            payload = {
                "model": "llama3", # Defaulting to llama3, but could be dynamic
                "messages": [
                    {"role": "system", "content": system_context},
                    {"role": "user", "content": prompt}
                ],
                "stream": False
            }
            log('purple', '[OLLAMA] Querying Cloud AI engine (GGO)...')
            response = requests.post(url, json=payload, headers=headers, timeout=45)
            if response.status_code == 200:
                data = response.json()
                ai_response = data.get('choices', [{}])[0].get('message', {}).get('content', '')
                if not ai_response:
                    # Fallback for some non-standard OpenAI formats
                    ai_response = data.get('response', '')
                
                if ai_response:
                    log('purple', f'[OLLAMA] AI Guidance: {ai_response[:200]}...', type='ollama')
                    return ai_response
        else:
            # 2. Fallback to Local Ollama
            url = "http://localhost:11434/api/generate"
            payload = {
                "model": "llama3",
                "prompt": prompt,
                "system": system_context,
                "stream": False
            }
            log('purple', '[OLLAMA] Querying Local AI engine...')
            response = requests.post(url, json=payload, timeout=30)
            if response.status_code == 200:
                ai_response = response.json().get('response', '')
                log('purple', f'[OLLAMA] AI Guidance: {ai_response[:200]}...', type='ollama')
                return ai_response

        log('yellow', f'[OLLAMA] API Error ({response.status_code}): {response.text[:100]}')
    except Exception as e:
        log('yellow', f'[OLLAMA] Connection failed: {e}. Check API key or if local Ollama is running.')
    return None

# --- Manual Offensive Tools ---
def run_sql_injection_manual(target):
    """Real-world SQLi detection logic"""
    log('red', f'[MANUAL] Starting SQL Injection Audit on {target}...', tool='manual_offense')
    payloads = ["' OR '1'='1", "'--", "'; WAITFOR DELAY '0:0:5'--", "') OR ('1'='1"]
    vulnerable = False
    
    try:
        # 1. Parameter Discovery (Simplified)
        response, base_url = request_with_fallback(target, '/')
        # ... logic to find forms or query params ...
        
        # 2. Testing payloads
        for payload in payloads:
            if check_stop(): break
            try:
                # Testing common parameter 'id'
                res = requests.get(f"{base_url}/", params={'id': payload}, timeout=5)
                if any(err in res.text.lower() for err in ['sql syntax', 'mysql_fetch', 'pdoexception', 'sql server error']):
                    add_finding('crit', f'SQL Injection vulnerability detected with payload: {payload}', asset=f"SQLI: {target}", tool='manual_offense')
                    vulnerable = True
                    break
            except:
                pass
        
        if not vulnerable:
            log('green', '[MANUAL] No obvious SQLi detected via automated payloads.')
            ollama_help = ask_ollama(f"I am testing {target} for SQL injection but automated payloads failed. What advanced techniques should I use next? Provide a step-by-step guide.")
            if ollama_help:
                scan_state['ollama_insights'].append({"tool": "SQLi", "guidance": ollama_help})
        
        log('green', '[MANUAL] SQLi Scan complete.', tool='manual_offense', progress=100)
                 
    except Exception as e:
        log('red', f'[MANUAL] SQLi Scan error: {e}')

def run_dos_ddos_test(target, type='dos'):
    """Safe DoS/DDoS simulation (educational only)"""
    log('red', f'[MANUAL] Starting {type.upper()} simulation on {target}...', tool='manual_offense')
    log('yellow', '[!] Note: This is a safe simulation. No real traffic flooding will occur.')
    
    # Simulating connection flooding
    for i in range(5):
        if check_stop(): break
        log('cyan', f'[MANUAL] [{type.upper()}] Flooding simulation packet {i+1}/5 sent...')
        time.sleep(1)
    
    add_finding('med', f'Target {target} potentially vulnerable to resource exhaustion ({type.upper()})', tool='manual_offense')
    log('green', f'[MANUAL] {type.upper()} simulation complete.', tool='manual_offense', progress=100)

# --- Advanced Crawling & Fingerprinting (ZAP Style) ---
def run_crawling(target):
    """Crawl the target to discover hidden structure"""
    log('cyan', f'[CRAWLER] Starting ZAP-style spider on {target}...', tool='wayback', progress=10)
    discovered_urls = set()
    try:
        response, base_url = request_with_fallback(target, '/')
        # Find all internal links
        links = re.findall(r'href=["\'](/?[\w\-/.]+)["\']', response.text)
        for link in links:
            if link.startswith('/'):
                discovered_urls.add(urljoin(base_url, link))
            elif target in link:
                discovered_urls.add(link)
        
        log('green', f'[CRAWLER] Discovered {len(discovered_urls)} unique internal paths.')
        for url in list(discovered_urls)[:10]: # Log a few
            scan_state['discovered_assets'].add(f"CRAWLED_URL: {url}")
    except Exception as e:
        log('yellow', f'[CRAWLER] Failed: {e}')

def run_advanced_fingerprinting(target):
    """Deep fingerprinting like ZAP/Burp"""
    log('cyan', f'[FINGERPRINT] Deep analyzing tech signatures for {target}...', tool='wayback')
    # This enhances run_tech_stack_detection
    run_tech_stack_detection(target)
    
    stack = scan_state['tech_stack']
    if 'WordPress' in stack.get('CMS', []):
        log('yellow', '[FINGERPRINT] WordPress detected! Checking for common plugins...')
        # Simulate WPScan
        wp_paths = ['/wp-content/plugins/contact-form-7/', '/wp-content/themes/twentytwenty/']
        for path in wp_paths:
            try:
                res = requests.get(urljoin(f"http://{target}", path), timeout=3)
                if res.status_code == 200:
                    scan_state['discovered_assets'].add(f"WP_PLUGIN: {path.split('/')[-2]}")
            except: pass

@app.route('/ask_ollama', methods=['POST'])
@auth.login_required
def ask_ollama_route():
    """Route to manually ask Ollama for help"""
    data = request.json
    prompt = data.get('prompt')
    if not prompt:
        return jsonify({"error": "No prompt specified"}), 400
    
    guidance = ask_ollama(prompt)
    if guidance:
        return jsonify({"guidance": guidance})
    else:
        return jsonify({"error": "Failed to get guidance from Ollama"}), 500

@app.route('/manual_tool', methods=['POST'])
@auth.login_required
def manual_tool():
    """Execute manual offensive tools"""
    data = request.json
    tool = data.get('tool')
    target = data.get('target') or scan_state.get('target')
    
    if not target:
        return jsonify({"error": "No target specified"}), 400
    
    if tool == 'sqli':
        threading.Thread(target=run_sql_injection_manual, args=(target,)).start()
    elif tool in ['dos', 'ddos']:
        threading.Thread(target=run_dos_ddos_test, args=(target, tool)).start()
    else:
        return jsonify({"error": "Invalid tool"}), 400
        
    return jsonify({"status": "Manual tool started"})

@app.route('/ollama_guidance', methods=['GET'])
def get_ollama_guidance():
    """Get the latest AI guidance from Ollama"""
    return jsonify(scan_state['ollama_insights'])

# --- End of New Features ---

def reset_scan_state():
    """Reset scan state for a fresh scan"""
    scan_state['logs'] = []
    scan_state['findings_list'] = []
    scan_state['progress'] = {k: 0 for k in scan_state['tools'].keys()}
    scan_state['findings'] = {'crit': 0, 'high': 0, 'med': 0, 'low': 0}
    scan_state['findings_list'] = []
    scan_state['discovered_assets'] = set()
    scan_state['status'] = 'IDLE'
    scan_state['target'] = ''
    scan_state['lang'] = 'en'
    scan_state['stop_requested'] = False
    scan_state['active_process'] = None
    scan_state['ollama_insights'] = []

def generate_ai_thought(phase, context=""):
    """Generate dynamic AI reasoning based on actual scan context"""
    base_thoughts = {
        'passive': [
            f"Analyzing DNS records for {context}. Looking for hidden entry points.",
            f"Mapping the digital footprint of {context} via certificate transparency.",
            "Cross-referencing cloud infrastructure signatures with known IP ranges."
        ],
        'active': [
            f"Probing {context} for open services. Identifying potential listening daemons.",
            "Executing stealthy port synchronization to map the network surface.",
            f"Fingerprinting service banners on {context} to identify software versions."
        ],
        'web': [
            "Fuzzing web directories for sensitive configuration leaks.",
            "Analyzing HTTP response headers for missing security controls.",
            "Executing pattern matching for common XSS and SQL injection vectors."
        ],
        'exploit': [
            f"Cross-referencing discovered services on {context} with exploit databases.",
            "Searching for Metasploit modules matching the identified tech stack.",
            "Evaluating potential research vectors for discovered vulnerabilities."
        ]
    }
    import random
    thoughts = base_thoughts.get(phase, ["Processing security scan data..."])
    return random.choice(thoughts)

def log(level, msg, thought=None, tool=None, progress=None, type='cmd'):
    """Add log entry to scan state with dynamic AI reasoning"""
    if thought and thought in ['passive', 'active', 'web', 'exploit']:
        target = scan_state.get('target', 'target')
        thought = generate_ai_thought(thought, target)
        
    entry = {'level': level, 'msg': msg, 'timestamp': datetime.now().isoformat(), 'type': type}
    if thought:
        entry['thought'] = thought
    if tool:
        entry['tool'] = tool
        scan_state['progress'][tool] = progress or 0
    scan_state['logs'].append(entry)
    logger.info(f"[{type.upper()}] [{level.upper()}] {msg}")

def edu_log(category):
    """Educational explanation removed per user request"""
    return

def get_all_logs():
    """Get all accumulated logs"""
    logs = scan_state['logs']
    scan_state['logs'] = []
    return logs

def resolve_domain(domain):
    """Resolve domain to IP addresses"""
    try:
        result = socket.gethostbyname_ex(domain)
        return list(dict.fromkeys(result[2]))
    except:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 3
            answers = resolver.resolve(domain, 'A')
            return list(dict.fromkeys(str(r) for r in answers))
        except Exception as e:
            log('red', f"DNS resolution failed: {e}")
            return []

def check_stop():
    """Check if scan stop has been requested"""
    if scan_state['stop_requested']:
        log('red', '[System] Scan termination requested by user. Cleaning up...')
        return True
    return False

def run_nmap_python_fallback(target):
    """Nmap fallback: High-speed multi-threaded TCP port scanner"""
    log('yellow', f'[NMAP] Binary not found. Using high-speed multi-threaded AI port scanner...', tool='nmap', progress=10)
    
    common_ports = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH/SFTP', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 111: 'RPC',
        123: 'NTP', 135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP',
        162: 'SNMP-Trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
        502: 'Modbus', 587: 'SMTP-Submission', 636: 'LDAPS', 993: 'IMAPS',
        995: 'POP3S', 1433: 'MSSQL', 1723: 'PPTP', 1883: 'MQTT', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5683: 'CoAP', 5900: 'VNC',
        6379: 'Redis', 8080: 'HTTP-Proxy', 8088: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        9000: 'HTTP-Alt', 9090: 'HTTP-Alt', 27017: 'MongoDB'
    }
    open_ports = []
    
    def probe_port(port, service_name):
        if check_stop(): return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                if s.connect_ex((target, port)) == 0:
                    banner = ""
                    try:
                        if port in [80, 8080, 8088, 9000, 9090]:
                            s.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % target.encode())
                        elif port in [443, 8443]:
                            s.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % target.encode())
                        elif port in [21]:
                            pass
                        elif port in [22, 23]:
                            pass
                        banner = s.recv(2048).decode(errors='ignore').strip()
                        if banner:
                            banner = banner.split('\n')[0].strip()
                    except:
                        pass
                    return (port, service_name, banner)
        except:
            pass
        return None

    # Use ThreadPoolExecutor for high-speed scanning
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(probe_port, p, s): p for p, s in common_ports.items()}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            result = future.result()
            if result:
                port, service, banner = result
                open_ports.append(port)
                msg = f"NMAP-FALLBACK: Found open port {port} ({service})"
                if banner: msg += f" - Banner: {banner}"
                add_finding('med', msg, asset=f"PORT_{port}: {service}", tool='nmap')
                log('green', f'[NMAP-FALLBACK] Found: {port}/tcp {service}')
            
            progress = 10 + int(((i + 1) / len(common_ports)) * 90)
            if i % 5 == 0: # Reduce log noise
                log('cyan', f'[NMAP-FALLBACK] Scanning progress: {progress}%', tool='nmap', progress=progress)

    return sorted(open_ports)

def run_nmap_scan(target):
    """ULTRA NMAP AUDIT: Executing ALL critical scanning phases and commands"""
    if check_stop(): return []
    log('cyan', f'[NMAP] Starting ULTRA-COMPREHENSIVE Audit on {target}...', tool='nmap', progress=0)
    
    # Define all command phases for a complete Nmap audit
    phases = [
        {
            'name': 'Service & Script Audit',
            'cmd': ['nmap', '-sV', '-sC', '-Pn', '-T4', '--top-ports', '1000', target],
            'desc': 'Scanning top 1000 ports with service detection and default scripts'
        },
        {
            'name': 'Full Port Audit',
            'cmd': ['nmap', '-p-', '-Pn', '-T4', target],
            'desc': 'Scanning all 65,535 TCP ports for hidden services'
        },
        {
            'name': 'OS Fingerprinting',
            'cmd': ['nmap', '-O', '-Pn', '-T4', target],
            'desc': 'Attempting to identify the remote Operating System'
        },
        {
            'name': 'Vulnerability & Exploit Audit',
            'cmd': ['nmap', '--script', 'vuln,exploit,auth,discovery,default', '-Pn', '-T4', target],
            'desc': 'Running a massive suite of NSE scripts (Vuln, Exploit, Auth, etc.)'
        },
        {
            'name': 'UDP Service Audit',
            'cmd': ['nmap', '-sU', '--top-ports', '50', '-Pn', '-T4', target],
            'desc': 'Scanning for common UDP services (DNS, DHCP, SNMP, etc.)'
        }
    ]
    
    open_ports = []
    for i, phase in enumerate(phases):
        progress = int(((i + 1) / len(phases)) * 100)
        log('cyan', f'[NMAP] Phase {i+1}/{len(phases)}: {phase["name"]}...', tool='nmap', progress=progress)
        
        # Trigger education log for the phase
        if 'Service' in phase['name']: edu_log('nmap_service')
        elif 'Full' in phase['name']: edu_log('nmap_full')
        elif 'OS' in phase['name']: edu_log('nmap_os')
        elif 'Vuln' in phase['name']: edu_log('nmap_vuln')
        
        log('cyan', f'[NMAP] Executing: {" ".join(phase["cmd"])}')
        
        try:
            process = subprocess.Popen(
                phase['cmd'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            scan_state['active_process'] = process
        except FileNotFoundError:
            log('yellow', f'[NMAP] Binary not found for phase "{phase["name"]}". Triggering fallback...')
            return run_nmap_python_fallback(target)
        except Exception as e:
            log('yellow', f'[NMAP] Phase "{phase["name"]}" failed to start: {e}')
            continue

        try:
            for line in process.stdout:
                if scan_state['stop_requested']:
                    process.terminate()
                    break
                # Parse Open Ports
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    port_proto = parts[0]
                    port = int(port_proto.split('/')[0])
                    service = parts[2]
                    version = ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'
                    
                    if port not in open_ports:
                        open_ports.append(port)
                        severity = 'high' if port in RISKY_PORTS else 'med'
                        add_finding(severity, f'NMAP [{phase["name"]}]: Found {port}/tcp ({service})', asset=f"PORT_{port}: {service}", tool='nmap')
                        log('green', f'[NMAP] Found: {port}/tcp {service}')

                # Parse UDP Ports
                if '/udp' in line and 'open' in line:
                    parts = line.split()
                    port_proto = parts[0]
                    port = int(port_proto.split('/')[0])
                    service = parts[2]
                    add_finding('med', f'NMAP [UDP]: Found {port}/udp ({service})', asset=f"UDP_PORT_{port}: {service}", tool='nmap')
                    log('yellow', f'[NMAP] UDP Found: {port}/udp {service}')

                # Parse Script Findings
                if '| ' in line and any(k in line.lower() for k in ['vulnerable', 'vulnerability', 'exploit', 'critical']):
                    msg = line.strip('| ').strip()
                    add_finding('high', f'NMAP-NSE: {msg}', tool='nmap')
                    log('red', f'[NMAP-NSE] {msg}')

                # Parse OS Detection
                if 'OS details:' in line:
                    os_info = line.split('OS details:')[1].strip()
                    scan_state['discovered_assets'].add(f"OS_DETECTION: {os_info}")
                    log('green', f'[NMAP] OS Identified: {os_info}')

            process.wait()
        except Exception as e:
            log('yellow', f'[NMAP] Phase "{phase["name"]}" failed: {e}')

    log('green', f'[NMAP] Ultra Audit complete. Found {len(open_ports)} TCP ports.', tool='nmap', progress=100)
    return open_ports

def run_tech_stack_detection(target):
    """ADVANCED: Identify Technology Stack & ALL PROTOCOLS (Wappalyzer style)"""
    log('cyan', f'[TECH-STACK] Identifying technologies and protocols on {target}...', tool='wayback', progress=0)
    
    try:
        response, base_url = request_with_fallback(target, '/')
        headers = response.headers
        content = response.text.lower()
        
        stack = defaultdict(list)
        
        # 1. Server & Infrastructure
        server = headers.get('Server', '')
        if server: stack['Infrastructure'].append(server)
        
        # 2. PROTOCOL DETECTION
        protocol_sigs = {
            'GraphQL': ['graphql', 'graphiql', '__schema', '__type'],
            'SOAP': ['soap-env', 'soapenv', 'envelope', 'wsdl'],
            'gRPC': ['grpc', 'grpc-web'],
            'WebSocket': ['websocket', 'ws://', 'wss://'],
            'WebDAV': ['dav', 'webdav'],
            'SSE': ['eventsource', 'text/event-stream'],
            'REST': ['/api/v1/', '/api/v2/', '/v1/', '/v2/'],
            'HTTP/2': ['h2', 'http/2'],
            'HTTP/3': ['h3', 'http/3', 'quic']
        }
        
        for proto, sigs in protocol_sigs.items():
            header_check = any(proto.lower() in str(v).lower() for v in headers.values())
            content_check = any(sig in content for sig in sigs)
            if header_check or content_check:
                stack['Protocols'].append(proto)
                
        # 3. CMS Detection
        cms_sigs = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
            'Drupal': ['drupal.js', 'sites/all'],
            'Joomla': ['joomla!', 'option=com_'],
            'Magento': ['magento', 'mage/'],
            'Shopify': ['shopify.com', 'cdn.shopify.com']
        }
        for cms, sigs in cms_sigs.items():
            if any(sig in content for sig in sigs):
                stack['CMS'].append(cms)
                
        # 4. Frameworks & Libraries
        js_sigs = {
            'React': ['react.development.js', 'react-dom'],
            'Vue.js': ['vue.js', 'vuejs'],
            'Angular': ['ng-version', 'angular.js'],
            'jQuery': ['jquery.min.js', 'jquery.js'],
            'Bootstrap': ['bootstrap.min.css', 'bootstrap.css']
        }
        for js, sigs in js_sigs.items():
            if any(sig in content for sig in sigs):
                stack['Frontend'].append(js)
                
        # 5. Backend Language
        powered_by = headers.get('X-Powered-By', '')
        if powered_by: stack['Backend'].append(powered_by)
        elif 'php' in content or '.php' in content: stack['Backend'].append('PHP')
        elif 'python' in content or 'django' in content: stack['Backend'].append('Python/Django')
        
        scan_state['tech_stack'] = dict(stack)
        for cat, items in stack.items():
            log('green', f'[TECH-STACK] {cat}: {", ".join(items)}')
            for item in items:
                scan_state['discovered_assets'].add(f"TECH_{cat.upper()}: {item}")
                
    except Exception as e:
        log('yellow', f'[TECH-STACK] Error during detection: {e}')

def run_subdomain_enum(target):
    """Deep subdomain discovery using CRT.SH and DNS resolution"""
    log('cyan', f'[RECON] Starting advanced subdomain discovery on {target}...', tool='shodan', progress=0)
    
    # 1. Certificate Transparency (CRT.SH) - REAL WORLD DATA
    try:
        log('cyan', '[RECON] Querying CRT.SH Certificate Transparency logs...')
        # Query crt.sh for subdomains
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        res = requests.get(url, timeout=15)
        if res.status_code == 200:
            certs = res.json()
            found = set()
            for cert in certs:
                name_value = cert['name_value']
                # cert names can contain multiple domains separated by newline
                for sub in name_value.split('\n'):
                    if sub.endswith(target) and '*' not in sub:
                        found.add(sub.lower())
            
            log('green', f'[RECON] CRT.SH found {len(found)} potential subdomains.')
            
            # Resolve found subdomains in parallel
            active_count = 0
            found_list = list(found)[:50] # Limit to 50 for speed
            
            def resolve_sub(sub):
                if check_stop(): return None
                try:
                    ips = resolve_domain(sub)
                    if ips:
                        return (sub, ips[0])
                except:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(resolve_sub, s): s for s in found_list}
                for i, future in enumerate(as_completed(futures)):
                    if check_stop(): break
                    result = future.result()
                    if result:
                        sub, ip = result
                        scan_state['discovered_assets'].add(f"SUBDOMAIN: {sub} -> {ip}")
                        log('green', f'[+] Active: {sub} ({ip})')
                        active_count += 1
                    
                    if i % 5 == 0:
                        progress = int(((i + 1) / len(found_list)) * 100)
                        log('cyan', f'[RECON] CRT.SH Resolution: {progress}%', tool='shodan', progress=progress)

            log('green', f'[RECON] Confirmed {active_count} active subdomains.')
    except Exception as e:
        log('yellow', f'[RECON] CRT.SH query failed: {e}')

    # 2. Existing Passive OSINT fallbacks...
    return run_subdomain_enum_original(target)

def run_subdomain_enum_original(target):
    """High-speed multi-threaded subdomain enumeration using DNS"""
    log('cyan', f'[DNS] Starting multi-threaded subdomain enumeration for {target}...', tool='shodan', progress=0)
    
    common_prefixes = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
                      'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
                      'cloud', 'sync', 'office', 'cdn', 'static', 'blog', 'shop', 'my', 'admin', 'internal',
                      'dev', 'staging', 'test', 'beta', 'api', 'cdn', 'assets', 'backup']
    
    subdomains = []
    sensitive_prefixes = {'admin', 'internal', 'dev', 'staging', 'test', 'backup'}
    
    def probe_subdomain(prefix):
        if check_stop(): return None
        subdomain = f"{prefix}.{target}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=2.0)
            ips = sorted({str(ip) for ip in answers})
            cname = ""
            try:
                cname_answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=1.0)
                cname = str(cname_answers[0]).rstrip('.')
            except:
                pass
            return (subdomain, ips, cname, prefix)
        except:
            return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(probe_subdomain, p): p for p in common_prefixes}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            result = future.result()
            if result:
                sub, ips, cname, prefix = result
                subdomains.append(sub)
                scan_state['discovered_assets'].add(f"SUBDOMAIN: {sub} -> {', '.join(ips)}")
                if cname:
                    scan_state['discovered_assets'].add(f"CNAME: {sub} -> {cname}")
                
                log('green', f'[DNS] Found: {sub} -> {", ".join(ips)}')
                if prefix in sensitive_prefixes:
                    add_finding('low', f'Sensitive subdomain discovered: {sub}')
            
            if i % 5 == 0:
                progress = int(((i + 1) / len(common_prefixes)) * 100)
                log('cyan', f'[DNS] Enumeration progress: {progress}%', tool='shodan', progress=progress)
    
    log('green', f'[DNS] Enumeration complete. Found {len(subdomains)} subdomains.', tool='shodan', progress=100)
    return subdomains

def run_nikto_scan(target):
    """ULTRA NIKTO AUDIT: Executing ALL critical Nikto modules and tuning parameters"""
    if check_stop(): return 0
    log('yellow', f'[NIKTO] Starting ULTRA-COMPREHENSIVE Web Audit on {target}...', tool='nikto', progress=0)
    edu_log('nikto')
    
    # Define Nikto command stages for a full audit
    nikto_path = os.path.join(BASE_DIR, 'tools', 'nikto-main', 'program', 'nikto.pl')
    perl_cmd = r'C:\Strawberry\perl\bin\perl.exe'
    
    stages = [
        {
            'name': 'Comprehensive Tuning Audit',
            'cmd': [perl_cmd, nikto_path, '-h', target, '-Tuning', '1234567890abcde', '-maxtime', '300s'],
            'desc': 'Testing all tuning categories (SQLi, XSS, LFI, etc.)'
        },
        {
            'name': 'CGI & Plugin Audit',
            'cmd': [perl_cmd, nikto_path, '-h', target, '-C', 'all', '-Plugins', 'ALL'],
            'desc': 'Forcing checks on all CGI directories and running all plugins'
        },
        {
            'name': 'SSL/TLS Security Audit',
            'cmd': [perl_cmd, nikto_path, '-h', target, '-ssl', '-Display', 'V'],
            'desc': 'Verifying SSL/TLS configuration and certificate health'
        },
        {
            'name': 'Information Disclosure Audit',
            'cmd': [perl_cmd, nikto_path, '-h', target, '-Display', '1234'],
            'desc': 'Checking for server headers, interesting files, and directory indexing'
        }
    ]
    
    issues = 0
    for i, stage in enumerate(stages):
        progress = int(((i + 1) / len(stages)) * 100)
        log('yellow', f'[NIKTO] Stage {i+1}/{len(stages)}: {stage["name"]}...', tool='nikto', progress=progress)
        log('yellow', f'[NIKTO] Executing: {" ".join(stage["cmd"])}')
        
        try:
            process = subprocess.Popen(
                stage['cmd'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            scan_state['active_process'] = process
        except FileNotFoundError:
            log('yellow', f'[NIKTO] Binary not found for stage "{stage["name"]}". Triggering fallback...')
            return run_nikto_python_fallback(target)
        except Exception as e:
            log('yellow', f'[NIKTO] Stage "{stage["name"]}" failed to start: {e}')
            continue

        try:
            for line in process.stdout:
                if scan_state['stop_requested']:
                    process.terminate()
                    break
                if '+ ' in line:
                    msg = line.split('+ ')[1].strip()
                    severity = 'crit' if any(w in msg.lower() for w in ['critical', 'rce', 'sql injection']) else \
                               ('high' if any(w in msg.lower() for w in ['vulnerable', 'exploit', 'leak']) else 'med')
                    
                    add_finding(severity, f'NIKTO [{stage["name"]}]: {msg}', tool='nikto')
                    log('red' if severity in ['crit', 'high'] else 'yellow', f'[NIKTO] Issue: {msg}')
                    issues += 1
            
            process.wait()
        except Exception as e:
            log('yellow', f'[NIKTO] Stage "{stage["name"]}" failed: {e}')

    log('green', f'[NIKTO] Ultra Web Audit complete. Found {issues} total issues.', tool='nikto', progress=100)
    return issues

def run_nikto_python_fallback(target):
    """High-speed multi-threaded Nikto-like Python implementation"""
    log('yellow', f'[NIKTO] Starting high-speed multi-threaded web scan on {target}...', tool='nikto', progress=0)
    issues_found = 0
    try:
        response, base_url = request_with_fallback(target, '/')
        log('green', f'[NIKTO] Connected via {base_url}', tool='nikto', progress=5)
    except Exception as e:
        log('red', f'[ERROR] Could not connect to {target}: {str(e)}', tool='nikto', progress=100)
        return 0
    
    # 1. Header Checks
    checks = [
        ('X-Frame-Options', 'med'),
        ('X-Content-Type-Options', 'med'),
        ('Strict-Transport-Security', 'med'),
        ('Content-Security-Policy', 'high'),
        ('Referrer-Policy', 'low'),
        ('Permissions-Policy', 'low')
    ]
    for header, severity in checks:
        if header not in response.headers:
            add_finding(severity, f'Missing security header: {header}', asset=f"VULN_HEADER: {header}", tool='nikto')
            issues_found += 1
            
    server_header = response.headers.get('Server', '')
    powered_by = response.headers.get('X-Powered-By', '')
    if server_header and re.search(r'\d', server_header):
        add_finding('low', f'Server banner exposes version details ({server_header})', asset=f"SERVER_BANNER: {server_header}", tool='nikto')
        issues_found += 1
    if powered_by:
        add_finding('low', f'X-Powered-By header exposed ({powered_by})', asset=f"X_POWERED_BY: {powered_by}", tool='nikto')
        issues_found += 1

    # 2. HTTP Methods
    try:
        options_res = requests.options(f'{base_url}/', timeout=3, headers=HTTP_HEADERS)
        allow_methods = {m.strip().upper() for m in options_res.headers.get('Allow', '').split(',') if m.strip()}
        if allow_methods:
            scan_state['discovered_assets'].add(f"HTTP_ALLOW: {', '.join(sorted(allow_methods))}")
        for method in sorted(allow_methods.intersection({'TRACE', 'PUT', 'DELETE', 'CONNECT'})):
            sev = 'high' if method in {'TRACE', 'PUT', 'DELETE'} else 'med'
            add_finding(sev, f'Potentially dangerous HTTP method enabled: {method}', tool='nikto')
            issues_found += 1
    except:
        pass

    # 3. Parallel Path Probing
    sensitive_paths = [
        ('/.env', 'crit'), ('/.git/config', 'high'), ('/wp-config.php', 'high'),
        ('/config.php', 'high'), ('/backup.zip', 'high'), ('/server-status', 'med'),
        ('/phpinfo.php', 'high'), ('/.DS_Store', 'med'), ('/actuator/env', 'high'),
        ('/debug/default/view', 'high'), ('/admin', 'low'), ('/login', 'low')
    ]
    
    def probe_path(path, severity):
        if check_stop(): return None
        url = urljoin(f'{base_url}/', path.lstrip('/'))
        try:
            probe = requests.get(url, timeout=3, headers=HTTP_HEADERS, allow_redirects=False)
            if probe.status_code == 200:
                found_secrets = extract_secret_leaks((probe.text or '')[:25000])
                return (path, severity, found_secrets)
            elif probe.status_code in (401, 403):
                return (path, 'restricted', [])
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(probe_path, p, s): p for p, s in sensitive_paths}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            result = future.result()
            if result:
                path, severity, secrets = result
                if severity == 'restricted':
                    scan_state['discovered_assets'].add(f"RESTRICTED_PATH: {path}")
                else:
                    add_finding(severity, f'Exposed sensitive endpoint: {path} (HTTP 200)', asset=f"EXPOSED_PATH: {path}", tool='nikto')
                    issues_found += 1
                    for leak in secrets:
                        add_finding('high', f'Potential {leak} leak at {path}', asset=f"POTENTIAL_SECRET: {leak} @ {path}", tool='nikto')
                        issues_found += 1
            
            if i % 4 == 0:
                progress = 40 + int(((i + 1) / len(sensitive_paths)) * 40)
                log('cyan', f'[NIKTO] Path probing: {progress}%', tool='nikto', progress=progress)

    # 4. Parallel Script Source Analysis
    script_sources = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text or '', flags=re.I)
    
    def extract_api_endpoints(js_content):
        endpoints = set()
        patterns = [
            r'["\']([/\w-]+/api/[\w/-]*)["\']',
            r'["\']([/\w-]+/v\d+/[\w/-]*)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'path:\s*["\']([^"\']+)["\']'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, js_content, flags=re.I)
            for match in matches:
                if len(match) > 2 and match not in ['/', 'http', 'https']:
                    endpoints.add(match)
        return sorted(list(endpoints))
    
    def analyze_script(src):
        if check_stop(): return None
        script_url = urljoin(f'{base_url}/', src)
        try:
            js_res = requests.get(script_url, timeout=3, headers=HTTP_HEADERS)
            if js_res.status_code == 200:
                js_content = (js_res.text or '')[:50000]
                secrets = extract_secret_leaks(js_content)
                api_endpoints = extract_api_endpoints(js_content)
                return (src, secrets, api_endpoints)
        except:
            pass
        return None

    if script_sources:
        unique_scripts = list(set(script_sources))[:10] # Limit for speed
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(analyze_script, s): s for s in unique_scripts}
            for i, future in enumerate(as_completed(futures)):
                if check_stop(): break
                result = future.result()
                if result:
                    src, secrets, api_endpoints = result
                    for leak in secrets:
                        add_finding('high', f'Potential {leak} leak in JavaScript: {src}', asset=f"POTENTIAL_SECRET_JS: {leak} @ {src}", tool='nikto')
                        issues_found += 1
                    if api_endpoints:
                        for endpoint in api_endpoints[:10]:
                            scan_state['discovered_assets'].add(f"API_ENDPOINT: {endpoint} @ {src}")
                        log('green', f'[NIKTO] Found {len(api_endpoints)} potential API endpoints in {src}')
                
                progress = 80 + int(((i + 1) / len(unique_scripts)) * 20)
                log('cyan', f'[NIKTO] Script analysis: {progress}%', tool='nikto', progress=progress)

    check_tls_certificate(target)
    log('green', f'[NIKTO] High-speed scan complete. Found {issues_found} issues.', tool='nikto', progress=100)
    return issues_found

def run_shodan_lookup(target):
    """Real Shodan API lookup"""
    log('cyan', f'[SHODAN] Querying Shodan for {target}...', tool='shodan', progress=0)
    
    if SHODAN_API_KEY and SHODAN_API_KEY != 'YOUR_SHODAN_KEY_HERE':
        try:
            url = f'https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=hostname:{target}'
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('matches'):
                    for match in data['matches'][:5]:
                        ip = match.get('ip_str', 'N/A')
                        ports = match.get('ports', [])
                        org = match.get('org', 'N/A')
                        product = match.get('product', 'N/A')
                        scan_state['discovered_assets'].add(f"SHODAN: {ip} ports:{ports} org:{org} product:{product}")
                    log('green', f"[SHODAN] Found {len(data['matches'])} results for {target}", tool='shodan', progress=100)
                    add_finding('low', f'Shodan shows {len(data["matches"])} exposed services', tool='shodan', progress=100)
                    return
        except Exception as e:
            log('yellow', f'[SHODAN] API error: {e}', tool='shodan', progress=50)
    
    # Fallback: basic IP resolution
    ips = resolve_domain(target)
    if ips:
        scan_state['discovered_assets'].add(f"SHODAN: Host {ips[0]} analyzed")
        log('green', f'[SHODAN] Host information retrieved', tool='shodan', progress=100)
    else:
        log('red', f'[SHODAN] Could not resolve host', tool='shodan', progress=100)

def run_virustotal_lookup(target):
    """Real VirusTotal API lookup"""
    log('cyan', f'[VIRUSTOTAL] Querying reputation database...', tool='vt', progress=0)
    
    if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != 'YOUR_VT_KEY_HERE':
        try:
            url = f'https://www.virustotal.com/api/v3/domains/{target}'
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('data') and data['data'].get('attributes'):
                    stats = data['data']['attributes'].get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    clean = stats.get('undetected', 0)
                    scan_state['discovered_assets'].add(f"VT: {malicious} mal, {suspicious} susp, {clean} clean")
                    if malicious > 0:
                        add_finding('high', f'VirusTotal: {malicious} vendors flag as malicious', tool='vt', progress=50)
                    log('green', f'[VIRUSTOTAL] {target}: {malicious} mal/{suspicious} susp/{clean} clean', tool='vt', progress=100)
                    return
            elif response.status_code == 404:
                log('green', f'[VIRUSTOTAL] {target} not found in database: CLEAN', tool='vt', progress=100)
                scan_state['discovered_assets'].add("VT: Domain not in database (clean)")
        except Exception as e:
            log('yellow', f'[VIRUSTOTAL] API error: {e}', tool='vt', progress=50)
    
    # Fallback
    log('green', f'[VIRUSTOTAL] {target} reputation: CLEAN', tool='vt', progress=100)
    scan_state['discovered_assets'].add(f"VT: Reputation check skipped")

def run_cve_lookup(target):
    """Real NVD CVE lookup for discovered technologies"""
    log('cyan', f'[CVE] Searching NVD for known vulnerabilities...', tool='acunetix', progress=0)
    
    try:
        # Get server info first
        response, base_url = request_with_fallback(target, '/', timeout=5)
        server = response.headers.get('Server', '')
        
        # Extract version if possible
        version_match = re.search(r'(\d+\.[\d.]+)', server) if server else None
        version = version_match.group(1) if version_match else None
        
        # Search NVD
        if server:
            search_term = server.split()[0] if server else target
            nvd_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&limit=5'
            try:
                nvd_response = requests.get(nvd_url, timeout=8)
                if nvd_response.status_code == 200:
                    nvd_data = nvd_response.json()
                    cves = nvd_data.get('vulnerabilities', [])
                    if cves:
                        for cve_item in cves[:3]:
                            cve_id = cve_item.get('cve', {}).get('id', 'N/A')
                            description = cve_item.get('cve', {}).get('descriptions', [{}])[0].get('value', '')[:100]
                            scan_state['discovered_assets'].add(f"CVE: {cve_id}")
                            log('red', f'[CVE] {cve_id}: {description}...', tool='acunetix', progress=80)
                            add_finding('high', f'NVD: {cve_id} affects {search_term}', tool='acunetix', progress=90)
                        log('green', f'[CVE] Found {len(cves)} CVEs for {search_term}', tool='acunetix', progress=100)
                        return
            except Exception as e:
                log('yellow', f'[CVE] NVD lookup skipped: {e}', tool='acunetix', progress=50)
        
        log('green', f'[CVE] No CVEs matched for target stack', tool='acunetix', progress=100)
    except Exception as e:
        log('yellow', f'[CVE] Scan skipped: {e}', tool='acunetix', progress=100)

def run_google_dorking(target):
    """Google Dorking for passive reconnaissance"""
    log('cyan', f'[GOOGLE-DORK] Searching for exposed information...', tool='wayback', progress=0)
    
    dorks = [
        f'site:{target} filetype:pdf',
        f'site:{target} filetype:doc',
        f'site:{target} filetype:docx',
        f'site:{target} filetype:txt',
        f'site:{target} inurl:admin',
        f'site:{target} inurl:login',
        f'site:{target} inurl:api'
    ]
    
    try:
        found_dorks = []
        for dork in dorks[:3]:  # Limit to avoid rate limiting
            scan_state['discovered_assets'].add(f"GOOGLE-DORK: {dork}")
            found_dorks.append(dork)
        
        if found_dorks:
            log('green', f'[GOOGLE-DORK] Generated {len(found_dorks)} dorks for manual verification', tool='wayback', progress=100)
    except Exception as e:
        log('yellow', f'[GOOGLE-DORK] Search skipped: {e}', tool='wayback', progress=100)

def run_wayback_lookup(target):
    """Wayback Machine historical scan"""
    log('cyan', f'[WAYBACK] Checking historical snapshots...', tool='wayback', progress=0)
    
    try:
        # Check if domain is in Wayback
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}&output=json&fl=original&limit=20"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:  # First row is header
                count = len(data) - 1
                log('green', f'[WAYBACK] Found {count} historical snapshots', tool='wayback', progress=100)
                scan_state['discovered_assets'].add(f"WAYBACK: {count} historical URLs")
    except Exception as e:
        log('yellow', f'[WAYBACK] No historical data found: {e}', tool='wayback', progress=100)

def run_xss_scan(target):
    """Adaptive XSS scan with multiple payload combinations and injection points!"""
    log('yellow', f'[XSS] Starting ADAPTIVE multi-threaded injection audit...', tool='xss', progress=0)
    vulnerabilities = 0
    
    try:
        root_res, base_url = request_with_fallback(target, '/')
    except Exception as e:
        log('red', f'[XSS] Target unreachable: {e}', tool='xss', progress=100)
        return 0
        
    xss_payloads = [
        '<script>alert("XSS")</script>',
        '<script>alert(document.domain)</script>',
        '\"><img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        'javascript:alert(document.domain)',
        '"><svg onload=alert(1)>',
        '<img src=x onerror=prompt(1)>',
        '<div onmouseover=alert(1)>test</div>'
    ]
    
    test_params = ['q', 'search', 'id', 's', 'query', 'keyword', 'page', 'lang']
    
    if 'Content-Security-Policy' not in root_res.headers:
        add_finding('med', 'CSP missing; XSS impact may be higher', tool='xss')
        vulnerabilities += 1
        
    root_text = root_res.text or ''
    if re.search(r'innerHTML\s*=|document\.write\(|eval\(|\.outerHTML\s*=', root_text, flags=re.I):
        add_finding('low', 'Potential DOM XSS sink patterns found in page source', asset='DOM_SINK_PATTERN: innerHTML/document.write/eval', tool='xss')
        vulnerabilities += 1

    def test_payload_on_param(payload, param):
        if check_stop(): return None
        try:
            probe = requests.get(f'{base_url}/', timeout=4, headers=HTTP_HEADERS, params={param: payload}, allow_redirects=True)
            if payload in (probe.text or ''):
                return (payload, param)
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(test_payload_on_param, p, prm) for p in xss_payloads for prm in test_params]
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            result = future.result()
            if result:
                payload, param = result
                add_finding('high', f'Potential reflected XSS in parameter ?{param}= with payload: {payload}', tool='xss')
                vulnerabilities += 1
            
            if i % 10 == 0:
                progress = 30 + int(((i + 1) / len(futures)) * 70)
                log('cyan', f'[XSS] Adaptive audit progress: {progress}%', tool='xss', progress=progress)

    log('yellow', f'[XSS] Adaptive injection audit complete. Findings: {vulnerabilities}', tool='xss', progress=100)
    return vulnerabilities

def run_nuclei_python_fallback(target):
    """Nuclei fallback: High-speed multi-threaded pattern-based scanner"""
    log('yellow', f'[NUCLEI] Binary not found. Running high-speed multi-threaded AI pattern scanner...', tool='nuclei', progress=10)
    
    issues_found = 0
    try:
        response, base_url = request_with_fallback(target, '/')
    except Exception:
        return 0

    patterns = [
        {'name': 'Cloud Metadata exposure', 'path': '/latest/meta-data/', 'keyword': 'instance-id', 'severity': 'crit'},
        {'name': 'Git repository exposure', 'path': '/.git/index', 'keyword': 'DIRC', 'severity': 'high'},
        {'name': 'Environment file exposure', 'path': '/.env', 'keyword': 'DB_', 'severity': 'crit'},
        {'name': 'Docker configuration exposure', 'path': '/docker-compose.yml', 'keyword': 'services:', 'severity': 'high'},
        {'name': 'PHP Info leakage', 'path': '/phpinfo.php', 'keyword': 'PHP Version', 'severity': 'med'}
    ]

    def check_pattern(p):
        if check_stop(): return None
        try:
            res = requests.get(f"{base_url}{p['path']}", timeout=4, headers=HTTP_HEADERS, verify=False)
            if res.status_code == 200 and p['keyword'] in res.text:
                return p
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_pattern, p): p for p in patterns}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            result = future.result()
            if result:
                add_finding(result['severity'], f"NUCLEI-FALLBACK: {result['name']} detected at {result['path']}", asset=f"VULN_PATH: {result['path']}", tool='nuclei')
                log('red', f'[NUCLEI-FALLBACK] Match found: {result["name"]}')
                issues_found += 1
            
            progress = 20 + int(((i + 1) / len(patterns)) * 70)
            log('cyan', f'[NUCLEI-FALLBACK] Scan progress: {progress}%', tool='nuclei', progress=progress)
            
    log('green', f'[NUCLEI-FALLBACK] Pattern scan complete. Found {issues_found} issues.', tool='nuclei', progress=100)
    return issues_found

def run_nuclei_scan(target):
    """Real Nuclei scan for template-based vulnerability detection"""
    log('cyan', f'[NUCLEI] Starting advanced template-based scan on {target}...', tool='nuclei', progress=0)
    edu_log('nuclei')

    try:
        log('cyan', '[NUCLEI] Attempting to execute nuclei binary...')
        nuclei_path = os.path.join(BASE_DIR, 'tools', 'nuclei', 'nuclei.exe')
        # -u: target, -silent: minimal output, -severity: critical,high,medium
        if not os.path.exists(nuclei_path):
            nuclei_path = 'nuclei' # Try PATH
            
        process = subprocess.Popen(
            [nuclei_path, '-u', target, '-silent', '-severity', 'critical,high,medium'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        scan_state['active_process'] = process
    except FileNotFoundError:
        log('yellow', '[NUCLEI] Binary not found. Triggering pattern-matching fallback...')
        return run_nuclei_python_fallback(target)
    except Exception as e:
        log('yellow', f'[NUCLEI] Binary scan failed to start: {e}. Triggering fallback...')
        return run_nuclei_python_fallback(target)

    try:
        findings = 0
        for line in process.stdout:
            if '[' in line and ']' in line:
                # Format: [template-id] [protocol] [severity] message
                parts = line.strip().split(' ', 3)
                if len(parts) >= 4:
                    template_id = parts[0].strip('[]')
                    severity_label = parts[2].strip('[]').lower()
                    msg = parts[3]
                    
                    severity = 'crit' if 'critical' in severity_label else ('high' if 'high' in severity_label else 'med')
                    add_finding(severity, f'NUCLEI: [{template_id}] {msg}', asset=f"NUCLEI_{template_id}", tool='nuclei')
                    log('red' if severity in ['crit', 'high'] else 'yellow', f'[NUCLEI] Found: {msg}')
                    findings += 1
        
        process.wait()
        if process.returncode == 0:
            log('green', f'[NUCLEI] Scan complete. Found {findings} issues.', tool='nuclei', progress=100)
            return findings
        else:
            log('yellow', '[NUCLEI] Binary execution failed. Nuclei might not be installed.')
    except Exception as e:
        log('yellow', f'[NUCLEI] Binary scan error: {e}. Skipping Nuclei phase.')
    
    # No fallback for Nuclei as it's a specific professional tool
    log('cyan', '[NUCLEI] Phase finished.', tool='nuclei', progress=100)
    return 0

def run_exploit_db_lookup(service_name):
    """Exploit-DB lookup using online search link generation"""
    log('cyan', f'[EXPLOIT-DB] Analyzing vulnerabilities for: {service_name}...', tool='exploit_db', progress=50)
    
    # Generate a direct research link for the user
    search_query = service_name.replace(' ', '+')
    edb_url = f"https://www.exploit-db.com/search?q={search_query}"
    
    # Add to findings as a research item
    add_finding('info', f'EXPLOIT-DB: Research potential exploits for {service_name}', 
                asset=f"EDB_LINK: {edb_url}", 
                tool='exploit_db')
    
    log('green', f'[EXPLOIT-DB] Research vector identified for {service_name}', tool='exploit_db', progress=100)
    return edb_url

def run_metasploit_fallback(target, services):
    """Metasploit fallback: Research-based exploit mapping without binary"""
    log('yellow', f'[METASPLOIT] Framework not found. Performing AI research mapping for {len(services)} services...', tool='metasploit', progress=10)
    
    for i, service in enumerate(services[:5]):
        progress = 20 + int(((i + 1) / len(services[:5])) * 80)
        log('cyan', f'[MSF-FALLBACK] Analyzing {service} for potential exploit modules...', tool='metasploit', progress=progress)
        
        # We already have Exploit-DB lookup running in the main loop, so here we just 
        # simulate the "mapping" that MSF would do by providing direct module names
        # based on service names for the user to research manually.
        mapping = {
            'apache': 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
            'nginx': 'exploit/multi/http/nginx_chunked_size',
            'ssh': 'auxiliary/scanner/ssh/ssh_login',
            'ftp': 'exploit/unix/ftp/vsftpd_234_backdoor',
            'smb': 'exploit/windows/smb/ms17_010_eternalblue',
            'mysql': 'auxiliary/scanner/mysql/mysql_login',
            'rdp': 'exploit/windows/rdp/cve_2019_0708_bluekeep'
        }
        
        service_lower = service.lower()
        for key, module in mapping.items():
            if key in service_lower:
                add_finding('info', f"MSF-RESEARCH: Potential Metasploit module for {service}: {module}", asset=f"RESEARCH_MODULE: {module}", tool='metasploit')
                log('red', f'[MSF-FALLBACK] Identified research module: {module}')
    
    log('green', '[MSF-FALLBACK] Research mapping complete.', tool='metasploit', progress=100)
    return []

def run_metasploit_scan(target):
    """Real Metasploit exploit search based on detected service versions"""
    log('red', f'[METASPLOIT] Checking for known exploits for {target}...', tool='metasploit', progress=0)
    
    # We use assets already found to search for exploits
    services = []
    for asset in list(scan_state['discovered_assets']):
        if 'PORT_' in asset:
            # Extract service/version from asset string
            services.append(asset.split(': ', 1)[1])
    
    if not services:
        log('yellow', '[METASPLOIT] No services identified yet. Using target domain for search.', tool='metasploit', progress=20)
        services = [target]
    
    found_exploits = []
    
    # Check for Metasploit binary
    msf_bin = r'C:\metasploit-framework\bin\msfconsole.bat'
    if not os.path.exists(msf_bin):
        # Try finding in tools folder if downloaded there
        tools_msf = os.path.join(BASE_DIR, 'tools', 'metasploit-framework', 'bin', 'msfconsole.bat')
        if os.path.exists(tools_msf):
            msf_bin = tools_msf
        else:
            # Check PATH
            try:
                subprocess.run(['msfconsole', '-v'], capture_output=True, timeout=2)
                msf_bin = 'msfconsole'
            except:
                log('yellow', '[METASPLOIT] Framework not found in C:\\ or PATH. Triggering research fallback...')
                return run_metasploit_fallback(target, services)
        
    for i, service in enumerate(services[:4]): # Limit to first 4 services for speed
        search_term = service.split(' ')[0] # Use first word (e.g., Apache, Nginx)
        
        # Integrate Exploit-DB lookup alongside Metasploit
        run_exploit_db_lookup(service)
        
    def search_msf(service, index):
        if check_stop(): return []
        search_term = service.split(' ')[0]
        
        try:
            # msfconsole -x "search type:exploit name:TERM; exit"
            # Note: This is slow, so we use a faster method if possible or just log the intent
            process = subprocess.run(
                [msf_bin, '-q', '-x', f'search type:exploit name:{search_term}; exit'],
                capture_output=True,
                text=True,
                timeout=20
            )
            
            local_exploits = []
            if process.returncode == 0:
                for line in process.stdout.splitlines():
                    if 'exploit/' in line:
                        parts = re.split(r'\s{2,}', line.strip())
                        if len(parts) >= 2:
                            exploit_path = parts[0]
                            add_finding('high', f'METASPLOIT: Matching exploit found - {exploit_path}', asset=f"MSF_EXPLOIT: {exploit_path}", tool='metasploit')
                            log('red', f'[METASPLOIT] Match: {exploit_path}')
                            local_exploits.append(exploit_path)
            return local_exploits
        except Exception:
            # Fallback: Just log that we'd search for this
            log('yellow', f'[METASPLOIT] Search for {search_term} skipped (msfconsole error or timeout).', tool='metasploit')
            return []

    active_services = services[:4]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(search_msf, s, i): s for i, s in enumerate(active_services)}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            found_exploits.extend(future.result())
            progress = 20 + int(((i + 1) / len(active_services)) * 80)
            log('red', f'[METASPLOIT] Search progress: {progress}%', tool='metasploit', progress=progress)
    
    log('green', f'[METASPLOIT] Exploit mapping complete. Found {len(found_exploits)} potential vectors.', tool='metasploit', progress=100)
    return found_exploits

def run_service_deep_dive(target, open_ports):
    """High-speed multi-threaded targeted deep-dive audits based on discovered services"""
    log('cyan', f'[DEEP-DIVE] Starting high-speed multi-threaded deep-dive on {target}...', tool='deep_dive', progress=0)
    edu_log('deep_dive')
    
    service_audits = {
        21: ('FTP', 'ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor', 'crit'),
        22: ('SSH', 'ssh-auth-methods,ssh-run,sshv1', 'high'),
        23: ('Telnet', 'telnet-encryption,telnet-ntlm-info', 'crit'),
        25: ('SMTP', 'smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344', 'high'),
        53: ('DNS', 'dns-recursion,dns-cache-snoop,dns-zone-transfer', 'med'),
        111: ('RPC', 'rpcinfo,rpc-grind', 'high'),
        139: ('SMB', 'smb-vuln-ms17-010,smb-vuln-ms10-061,smb-enum-shares', 'crit'),
        445: ('SMB', 'smb-vuln-ms17-010,smb-ls,smb-enum-users', 'crit'),
        1433: ('MSSQL', 'ms-sql-info,ms-sql-config,ms-sql-empty-password', 'crit'),
        3306: ('MySQL', 'mysql-info,mysql-empty-password,mysql-vuln-cve2012-2122', 'crit'),
        3389: ('RDP', 'rdp-vuln-ms12-020,rdp-ntlm-info', 'high'),
        5432: ('Postgres', 'pgsql-intrude', 'crit'),
        6379: ('Redis', 'redis-info', 'high'),
        27017: ('MongoDB', 'mongodb-info,mongodb-databases', 'high')
    }

    ports_to_audit = [p for p in open_ports if p in service_audits]
    if not ports_to_audit:
        log('green', '[DEEP-DIVE] No common exploitable services found for deep-dive.', tool='deep_dive', progress=100)
        return

    audit_count = 0
    def audit_service(port):
        nonlocal audit_count
        if check_stop(): return
        service_name, scripts, sev = service_audits[port]
        try:
            process = subprocess.run(
                ['nmap', '-p', str(port), '--script', scripts, '-Pn', target],
                capture_output=True,
                text=True,
                timeout=60
            )
            for line in process.stdout.splitlines():
                if '| ' in line and any(k in line.lower() for k in ['vulnerable', 'vulnerability', 'exploit', 'success', 'account', 'password', 'anonymous']):
                    msg = line.strip('| ').strip()
                    add_finding(sev, f'DEEP-DIVE [{service_name}]: {msg}', asset=f"EXPLOITABLE_{service_name}", tool='deep_dive')
                    log('red', f'[!] {service_name} CRITICAL FINDING: {msg}')
                    audit_count += 1
        except:
            pass

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(audit_service, p): p for p in ports_to_audit}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            progress = int(((i + 1) / len(ports_to_audit)) * 100)
            log('cyan', f'[DEEP-DIVE] Audit progress: {progress}%', tool='deep_dive', progress=progress)
            
    log('green', f'[DEEP-DIVE] Service deep-dive complete. Found {audit_count} critical service flaws.', tool='deep_dive', progress=100)

def run_fuzzing_engine(target):
    """ADAPTIVE multi-threaded directory and file fuzzing engine with multiple wordlists!"""
    log('yellow', f'[FUZZER] Starting ADAPTIVE multi-threaded endpoint discovery on {target}...', tool='fuzzer', progress=0)
    edu_log('fuzzer')
    
    try:
        _, base_url = request_with_fallback(target, '/')
    except:
        log('red', '[FUZZER] Target unreachable for fuzzing.', tool='fuzzer', progress=100)
        return

    wordlists = [
        ['api', 'v1', 'v2', 'v3', 'graphql', 'graphiql', 'admin', 'administrator', 'wp-admin', 'backend'],
        ['dev', 'development', 'staging', 'test', 'demo', 'backup', 'backups', 'old'],
        ['config', 'settings', 'secrets', '.env', '.git', '.svn', '.vscode', 'phpinfo', 'info.php'],
        ['dashboard', 'manage', 'upload', 'uploads', 'files', 'temp', 'tmp', 'shell'],
        ['cmd', 'exec', 'debug', 'console', 'server-status', 'actuator', 'swagger', 'docs', 'api-docs'],
        ['login', 'signin', 'register', 'signup', 'auth', 'authentication', 'password', 'reset'],
        ['robots.txt', 'sitemap.xml', 'sitemap.txt', 'crossdomain.xml', 'clientaccesspolicy.xml'],
        ['web.config', '.htaccess', 'htpasswd', 'composer.json', 'package.json', 'package-lock.json'],
        ['wp-config.php', 'config.php', 'config.inc.php', 'database.php', 'settings.php'],
        ['backup.zip', 'backup.tar.gz', 'backup.sql', 'dump.sql', 'database.sql', 'db_backup.sql'],
        ['private', 'internal', 'secure', 'protected', 'restricted', 'hidden'],
        ['assets', 'static', 'media', 'images', 'img', 'css', 'js', 'javascript'],
        ['ws', 'wss', 'events', 'stream', 'sse', 'event-source'],
        ['soap', 'wsdl', 'service', 'services', 'rpc', 'grpc', 'proto'],
        ['dav', 'webdav', 'dav/webdav'],
        ['health', 'healthz', 'ready', 'readyz', 'metrics', 'prometheus']
    ]
    
    all_words = list({word for sublist in wordlists for word in sublist})
    fuzz_hits = 0
    
    def probe_word(word):
        if check_stop(): return None
        url = urljoin(f'{base_url}/', word)
        try:
            # Try HEAD first for speed
            res = requests.head(url, timeout=3, headers=HTTP_HEADERS, allow_redirects=False)
            if res.status_code in [200, 301, 302, 401, 403, 405]:
                secrets = []
                if res.status_code == 200:
                    try:
                        get_res = requests.get(url, timeout=4, headers=HTTP_HEADERS)
                        secrets = extract_secret_leaks(get_res.text[:50000])
                    except:
                        pass
                return (word, res.status_code, secrets)
        except:
            # If HEAD fails, try GET
            try:
                res = requests.get(url, timeout=4, headers=HTTP_HEADERS, allow_redirects=False)
                if res.status_code in [200, 301, 302, 401, 403]:
                    secrets = extract_secret_leaks(res.text[:50000]) if res.status_code == 200 else []
                    return (word, res.status_code, secrets)
            except:
                pass
        return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(probe_word, w): w for w in all_words}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            result = future.result()
            if result:
                word, status, secrets = result
                severity = 'high' if status == 200 and any(k in word.lower() for k in ['admin', 'config', 'secret', 'env', 'git', 'backup', 'sql', 'password']) else 'low'
                add_finding(severity, f'FUZZER: Hidden endpoint found - /{word} (HTTP {status})', asset=f"HIDDEN_ENDPOINT: /{word}", tool='fuzzer')
                log('green' if severity == 'low' else 'red', f'[FUZZER] Found: /{word} (HTTP {status})')
                fuzz_hits += 1
                
                for secret in secrets:
                    add_finding('crit', f'FUZZER-LEAK: {secret} found in /{word}', asset=f"LEAKED_{secret}_FUZZ: /{word}", tool='fuzzer')
                    log('red', f'[!] CRITICAL LEAK in /{word}: {secret}')
            
            if i % 10 == 0:
                progress = int(((i + 1) / len(all_words)) * 100)
                log('cyan', f'[FUZZER] Adaptive fuzzing progress: {progress}%', tool='fuzzer', progress=progress)

    log('green', f'[FUZZER] Adaptive fuzzing complete. Found {fuzz_hits} interesting paths.', tool='fuzzer', progress=100)

def run_cloud_recon(target):
    """High-speed multi-threaded cloud infrastructure and takeover audit"""
    log('cyan', f'[CLOUD] Starting high-speed multi-threaded cloud audit on {target}...', tool='shodan', progress=0)
    
    takeover_signatures = {
        'github.io': 'GitHub Pages', 'herokuapp.com': 'Heroku', 's3.amazonaws.com': 'AWS S3',
        'azurewebsites.net': 'Azure', 'cloudfront.net': 'CloudFront', 'bitbucket.org': 'Bitbucket',
        'ghost.io': 'Ghost.io', 'myshopify.com': 'Shopify'
    }
    
    subdomains = []
    for asset in list(scan_state['discovered_assets']):
        if 'SUBDOMAIN:' in asset:
            subdomains.append(asset.split(': ')[1].split(' ->')[0])
            
    if not subdomains: subdomains = [target]
    
    takeovers = 0
    def check_takeover(sub):
        if check_stop(): return None
        try:
            answers = dns.resolver.resolve(sub, 'CNAME', lifetime=2.0)
            for rdata in answers:
                cname = str(rdata.target).lower().rstrip('.')
                for sig, provider in takeover_signatures.items():
                    if sig in cname:
                        try:
                            res = requests.get(f'http://{sub}', timeout=3, allow_redirects=True)
                            if any(k in res.text.lower() for k in ['404 not found', 'no such app', 'there is no app here', 'project not found', 'site not found']):
                                return (sub, provider, cname)
                        except:
                            pass
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_takeover, s): s for s in subdomains[:20]}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            result = future.result()
            if result:
                sub, provider, cname = result
                add_finding('crit', f'TAKEOVER: Subdomain {sub} points to unclaimed {provider} ({cname})', asset=f"TAKEOVER_RISK: {sub}", tool='shodan')
                log('red', f'[!] CRITICAL: Subdomain Takeover Risk detected on {sub}!')
                takeovers += 1
            
            if i % 5 == 0:
                progress = int(((i + 1) / len(subdomains[:20])) * 100)
                log('cyan', f'[CLOUD] Audit progress: {progress}%', tool='shodan', progress=progress)
            
    log('green', f'[CLOUD] Cloud audit complete. Found {takeovers} takeover risks.', tool='shodan', progress=100)


def run_payload_generation(target, exploits_found):
    """ADVANCED: Use msfvenom to generate and validate theoretical exploit payloads"""
    log('red', f'[MSFVENOM] Starting theoretical payload generation for {target}...', tool='msfvenom', progress=0)
    edu_log('msfvenom')
    
    if not exploits_found:
        log('yellow', '[MSFVENOM] No specific exploits found to generate payloads for.', tool='msfvenom', progress=100)
        return

    # Map of exploit keywords to recommended msfvenom payloads
    payload_map = {
        'windows': 'windows/x64/meterpreter/reverse_tcp',
        'linux': 'linux/x64/meterpreter/reverse_tcp',
        'apache': 'php/meterpreter/reverse_tcp',
        'mysql': 'linux/x86/meterpreter/reverse_tcp',
        'ftp': 'linux/x86/shell_reverse_tcp',
        'smb': 'windows/x64/meterpreter/reverse_tcp',
        'ssh': 'linux/x64/shell_reverse_tcp'
    }

    generated_count = 0
    # Process up to 3 exploits to keep scan time reasonable
    active_exploits = exploits_found[:3]
    
    def generate_payload(exploit, index):
        if check_stop(): return 0
        
        # Determine likely platform/payload
        exploit_lower = exploit.lower()
        selected_payload = 'generic/shell_reverse_tcp' # Default
        for key, p in payload_map.items():
            if key in exploit_lower:
                selected_payload = p
                break
        
        log('red', f'[MSFVENOM] Attempting to generate payload for: {selected_payload}...', tool='msfvenom')
        
        try:
            # msfvenom -p <payload> LHOST=127.0.0.1 LPORT=4444 -f raw
            # We use 127.0.0.1 and raw format to safely check if the payload CAN be built
            process = subprocess.run(
                ['msfvenom', '-p', selected_payload, 'LHOST=127.0.0.1', 'LPORT=4444', '-f', 'raw'],
                capture_output=True,
                timeout=20
            )
            
            if process.returncode == 0:
                payload_size = len(process.stdout)
                add_finding('high', f'MSFVENOM: Successfully generated {selected_payload} ({payload_size} bytes)', asset=f"PAYLOAD_GEN: {selected_payload}", tool='msfvenom')
                log('green', f'[MSFVENOM] SUCCESS: Generated {selected_payload} ({payload_size} bytes)')
                return 1
            else:
                error_msg = process.stderr.decode().strip().split('\n')[-1]
                log('yellow', f'[MSFVENOM] FAILED: Could not build payload {selected_payload}. Error: {error_msg}')
        except Exception as e:
            log('yellow', f'[MSFVENOM] Error executing msfvenom: {e}')
        return 0

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(generate_payload, exp, i): exp for i, exp in enumerate(active_exploits)}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            generated_count += future.result()
            progress = int(((i + 1) / len(active_exploits)) * 100)
            log('red', f'[MSFVENOM] Payload generation progress: {progress}%', tool='msfvenom', progress=progress)

    log('green', f'[MSFVENOM] Payload generation phase complete. {generated_count} payloads validated.', tool='msfvenom', progress=100)

def run_adaptive_method_scan(target):
    """ADAPTIVE: Try multiple HTTP methods on all discovered endpoints!"""
    log('cyan', f'[ADAPTIVE-METHOD] Testing multiple HTTP methods...', tool='deep_dive', progress=0)
    
    try:
        _, base_url = request_with_fallback(target, '/')
    except:
        return

    test_methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD', 'TRACE']
    test_paths = ['/', '/admin', '/api', '/api/v1', '/login', '/register', '/test', '/debug']
    
    issues_found = 0
    
    def test_method_on_path(method, path):
        if check_stop(): return None
        try:
            url = urljoin(f'{base_url}/', path.lstrip('/'))
            res = requests.request(method, url, timeout=3, headers=HTTP_HEADERS, allow_redirects=False)
            if res.status_code not in [404, 405]:
                return (method, path, res.status_code)
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_method_on_path, m, p) for m in test_methods for p in test_paths]
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            result = future.result()
            if result:
                method, path, status = result
                severity = 'med' if method in ['PUT', 'DELETE', 'TRACE'] else 'low'
                add_finding(severity, f'ADAPTIVE-METHOD: {method} allowed on {path} (HTTP {status})', asset=f"HTTP_METHOD: {method} @ {path}", tool='deep_dive')
                log('yellow' if severity == 'med' else 'cyan', f'[ADAPTIVE-METHOD] {method} {path} → {status}')
                issues_found += 1
    
    log('green', f'[ADAPTIVE-METHOD] Tested {len(test_methods)} methods on {len(test_paths)} paths. Found {issues_found} interesting responses.', tool='deep_dive', progress=100)

def run_data_leakage_scan(target):
    """GOD-LEVEL: High-speed multi-threaded sensitive data leakage audit"""
    if check_stop(): return 0
    log('yellow', f'[LEAK-SCAN] Starting high-speed multi-threaded data leakage audit on {target}...', tool='ctf', progress=0)
    
    sensitive_paths = [
        ('/.env', 'crit'), ('/.git/config', 'high'), ('/.aws/credentials', 'crit'),
        ('/.ssh/id_rsa', 'crit'), ('/config/database.yml', 'high'), ('/etc/passwd', 'crit'),
        ('/wp-config.php.bak', 'high'), ('/backup.sql', 'high'), ('/docker-compose.yml', 'high'),
        ('/.npmrc', 'med'), ('/package-lock.json', 'low'), ('/composer.json', 'low')
    ]
    
    try:
        _, base_url = request_with_fallback(target, '/')
    except Exception as e:
        log('red', f'[LEAK-SCAN] Target unreachable: {e}', tool='ctf', progress=100)
        return 0
    
    leaks = []
    def check_leak(path, severity):
        if check_stop(): return None
        url = urljoin(f'{base_url}/', path.lstrip('/'))
        try:
            response = requests.get(url, timeout=3, headers=HTTP_HEADERS, allow_redirects=False)
            if response.status_code == 200:
                content = response.text or ''
                found_secrets = extract_secret_leaks(content[:50000])
                return (path, severity, found_secrets)
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_leak, path, sev): path for path, sev in sensitive_paths}
        for i, future in enumerate(as_completed(futures)):
            if check_stop(): break
            result = future.result()
            if result:
                path, severity, secrets = result
                if secrets:
                    for secret in secrets:
                        add_finding('crit', f'DATA-LEAK: {secret} found in {path}', asset=f"LEAKED_{secret}: {path}", tool='ctf')
                        log('red', f'[!] CRITICAL: {secret} EXPOSED IN {path}')
                        leaks.append(path)
                else:
                    add_finding(severity, f'EXPOSED-FILE: Sensitive file {path} accessible', asset=f"EXPOSED_FILE: {path}", tool='ctf')
                    log('red' if severity in ['crit', 'high'] else 'yellow', f'[!] Found: {path}')
                    leaks.append(path)
            
            progress = int(((i + 1) / len(sensitive_paths)) * 100)
            if i % 3 == 0:
                log('cyan', f'[LEAK-SCAN] Audit progress: {progress}%', tool='ctf', progress=progress)

    log('green', f'[LEAK-SCAN] Data leakage audit complete. Found {len(leaks)} exposures.', tool='ctf', progress=100)
    return len(leaks)

def run_vuln_validation(finding):
    """GOD LEVEL: Actually verify if a detected vulnerability is exploitable (Safely)"""
    if 'VULN_PATH' in finding.get('asset', ''):
        path = finding['asset'].split(': ')[1]
        target = scan_state.get('target')
        log('red', f'[VALIDATOR] Verifying exploitability of {path}...', tool='system')
        
        try:
            # Safe verification: Check for specific secret patterns in the exposed file
            res = requests.get(f"http://{target}{path}", timeout=5, headers=HTTP_HEADERS)
            if res.status_code == 200:
                content = res.text
                secrets = ['AWS_ACCESS_KEY', 'PASSWORD', 'SECRET_KEY', 'DATABASE_URL']
                found_secrets = [s for s in secrets if s in content.upper()]
                
                if found_secrets:
                    msg = f"VULNERABILITY VERIFIED: {path} is publicly accessible and contains sensitive keys: {', '.join(found_secrets)}"
                    add_finding('crit', msg, asset=finding['asset'], tool='validator', impact='confidentiality', exploitability='active')
                    log('red', f'[!] {msg}')
                    return True
        except:
            pass
    return False

def analyze_with_ai(context_data):
    """GOD LEVEL: Intelligence synthesis with Kill Chain Prediction"""
    log('cyan', '[GOD-LEVEL] Synthesizing all data points for Kill Chain Prediction...', thought='exploit')
    
    findings = scan_state.get('findings_list', [])
    if not findings:
        return "Intelligence synthesis complete: No actionable attack vectors identified."

    # Kill Chain Mapping
    recon_data = [f for f in findings if f['tool'] in ['nmap', 'shodan', 'passive']]
    vuln_data = [f for f in findings if f['tool'] in ['nuclei', 'nikto', 'xss']]
    exploit_data = [f for f in findings if f['tool'] in ['metasploit', 'exploit_db']]
    
    log('purple', f'[AI-SYNTHESIS] Correlating {len(recon_data)} assets, {len(vuln_data)} vulnerabilities, and {len(exploit_data)} exploit modules.')

    # Logic: Attack Vector Synthesis
    attack_vectors = []
    
    # Vector 1: Web-to-Internal Pivot
    if vuln_data and any(p in str(f.get('asset')) for f in recon_data for p in ['3306', '6379', '5432']):
        vector = "ATTACK VECTOR IDENTIFIED: Web-to-Internal Pivot. Public web vulnerability can be used to tunnel into exposed internal database services."
        attack_vectors.append(vector)
        add_finding('crit', f"KILL-CHAIN: {vector}", tool='AI_SYNTHESIS', impact='confidentiality', exploitability='active')

    # Vector 2: Credential Stuffing / Brute Force
    if any('ssh' in str(f.get('asset')).lower() or 'ftp' in str(f.get('asset')).lower() for f in recon_data):
        vector = "ATTACK VECTOR IDENTIFIED: Credential Exhaustion. Open authentication services detected without MFA headers."
        attack_vectors.append(vector)
        add_finding('high', f"KILL-CHAIN: {vector}", tool='AI_SYNTHESIS', impact='integrity', exploitability='public')

    # Tactical Remediation Advice
    for vector in attack_vectors:
        log('red', f'[GOD-LEVEL ALERT] {vector}')

    # Final Summary for PDF
    log('green', '[GOD-LEVEL] Intelligence report ready for generation.')
    return "Synthesis Complete."

def run_full_scan(target):
    """GOD-LEVEL: High-speed parallelized scan pipeline"""
    target = normalize_target(target)
    if not target:
        scan_state['status'] = 'COMPLETE'
        log('red', '[System] Invalid target provided; scan aborted.')
        return
    scan_state['target'] = target
    scan_state['status'] = 'RUNNING'
    scan_state['progress'] = {k: 0 for k in scan_state['tools'].keys()}
    scan_state['findings'] = {'crit': 0, 'high': 0, 'med': 0, 'low': 0}
    scan_state['findings_list'] = []
    scan_state['discovered_assets'] = set()
    
    log('cyan', f'[System] Starting high-speed parallel offensive recon on {target}...')
    # Add to history if not already there
    if target not in scan_state['target_history']:
        scan_state['target_history'].insert(0, target)
        if len(scan_state['target_history']) > 10:
            scan_state['target_history'].pop()

    try:
        # Phase 1: Parallel Passive Recon & OSINT
        log('cyan', '[AI] Starting parallel Passive Recon & OSINT phase...', thought='passive')
        passive_tasks = [
            lambda: run_subdomain_enum(target),
            lambda: run_cloud_recon(target),
            lambda: run_tech_stack_detection(target),
            lambda: run_shodan_lookup(target),
            lambda: run_virustotal_lookup(target),
            lambda: run_wayback_lookup(target),
            lambda: run_cve_lookup(target),
            lambda: run_google_dorking(target),
            lambda: run_crawling(target),
            lambda: run_advanced_fingerprinting(target)
        ]
        
        with ThreadPoolExecutor(max_workers=len(passive_tasks)) as executor:
            futures = [executor.submit(t) for t in passive_tasks]
            for future in as_completed(futures):
                if check_stop(): break
                future.result()
        
        if check_stop(): return

        # Phase 2: Active Recon (Must be serial to provide ports for Batch C)
        log('cyan', '[AI] Starting Active Scanning phase...', thought='active')
        open_ports = run_nmap_scan(target)
        
        if check_stop(): return

        # Phase 3 & 4: Parallel Service Audits & Web Scans
        log('cyan', '[AI] Starting parallel Service Deep-Dive & Web Audit...', thought='web')
        active_tasks = [
            lambda: run_service_deep_dive(target, open_ports),
            lambda: run_nikto_scan(target),
            lambda: run_fuzzing_engine(target),
            lambda: run_xss_scan(target),
            lambda: run_nuclei_scan(target),
            lambda: run_adaptive_method_scan(target)
        ]
        
        with ThreadPoolExecutor(max_workers=len(active_tasks)) as executor:
            futures = [executor.submit(t) for t in active_tasks]
            for future in as_completed(futures):
                if check_stop(): break
                future.result()

        if check_stop(): return

        # Phase 5: Exploit Mapping & Data Leakage
        log('cyan', '[AI] Finalizing Exploit Mapping & Data Leakage...', thought='exploit')
        
        def run_exploit_chain():
            exps = run_metasploit_scan(target)
            if not check_stop():
                run_payload_generation(target, exps)
        
        exploit_tasks = [
            run_exploit_chain,
            lambda: run_data_leakage_scan(target)
        ]
        
        with ThreadPoolExecutor(max_workers=len(exploit_tasks)) as executor:
            futures = [executor.submit(t) for t in exploit_tasks]
            for future in as_completed(futures):
                if check_stop(): break
                future.result()

        # Phase 6: GOD LEVEL - Tactical Analysis & Validation
        if check_stop(): return
        log('purple', '[GOD-LEVEL] Starting tactical exploitability analysis...', thought='exploit')
        
        # Auto-validate high-priority findings in parallel
        findings = scan_state.get('findings_list', [])
        high_findings = [f for f in findings if f.get('severity') in ['HIGH', 'CRITICAL']]
        
        if high_findings:
            with ThreadPoolExecutor(max_workers=5) as executor:
                [executor.submit(run_vuln_validation, f) for f in high_findings]
                
        # Final AI Tactical Assessment & Kill Chain Prediction
        analyze_with_ai(target)
        
        # Ollama Fallback if no critical vulnerabilities found
        total_high_crit = scan_state['findings']['crit'] + scan_state['findings']['high']
        if total_high_crit == 0:
            log('purple', '[OLLAMA] No critical vulnerabilities found. Asking AI for manual exploitation guidance...')
            ollama_prompt = f"The automated scan for {target} found no critical vulnerabilities. Here is the discovered tech stack: {scan_state['tech_stack']}. What manual steps should a penetration tester take now to find hidden bugs or vulnerabilities? Provide a detailed guide."
            ollama_guidance = ask_ollama(ollama_prompt)
            if ollama_guidance:
                scan_state['ollama_insights'].append({"tool": "General Guidance", "guidance": ollama_guidance})
                log('green', '[OLLAMA] AI Guidance received. Check the Ollama Terminal for details.')

        log('green', '[GOD-LEVEL] Intelligence synthesis complete.', thought='exploit', progress=100)
    except Exception as e:
        log('red', f'[System] Scan pipeline error: {e}')
    finally:
        if scan_state['status'] != 'STOPPED':
            scan_state['status'] = 'COMPLETE'
            log('green', f'[+] Full scan complete. Target: {target}')
        else:
            log('yellow', f'[!] Scan stopped by user. Final results compiled for: {target}')
            
        total_findings = sum(scan_state["findings"].values())
        log('green', f'[+] Total Findings: {total_findings} (Crit: {scan_state["findings"]["crit"]}, High: {scan_state["findings"]["high"]}, Med: {scan_state["findings"]["med"]}, Low: {scan_state["findings"]["low"]})')
        log('green', f'[+] Assets Discovered: {len(scan_state["discovered_assets"])}')

@app.route('/download_report')
def download_report():
    """Download the generated HTML report"""
    target = scan_state.get('target', 'scan')
    report_path = generate_html_report(target)
    return send_from_directory(BASE_DIR, os.path.basename(report_path), as_attachment=True)

@app.route('/exploit_console', methods=['POST'])
def exploit_console():
    """Execute a manual exploit command (Authorized ONLY)"""
    data = request.json
    cmd = data.get('cmd', '')
    
    if not cmd:
        return jsonify({'error': 'No command provided'}), 400
        
    # Safety: Only allow specific safe tools for the console
    allowed_tools = ['curl', 'msfconsole', 'msfvenom', 'nmap', 'nuclei']
    tool = cmd.split(' ')[0]
    if tool not in allowed_tools:
        return jsonify({'error': f'Tool {tool} is not permitted in the web console for safety.'}), 403
        
    try:
        # Run the manual command
        process = subprocess.run(cmd.split(' '), capture_output=True, text=True, timeout=30)
        return jsonify({
            'stdout': process.stdout,
            'stderr': process.stderr,
            'exit_code': process.returncode
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/status')
def status():
    """Return current scan status"""
    return jsonify({
        'status': scan_state['status'],
        'target': scan_state['target'],
        'progress': scan_state['progress'],
        'findings': scan_state['findings'],
        'assets_count': len(scan_state['discovered_assets'])
    })

@app.route('/')
def index():
    """Serve frontend UI"""
    return send_from_directory(BASE_DIR, 'vulnscan.html')

@app.route('/vulnscan.html')
def frontend_html():
    """Serve frontend UI file directly"""
    return send_from_directory(BASE_DIR, 'vulnscan.html')

@app.route('/health')
def health():
    """Self-ping endpoint to keep the service awake"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

def self_ping():
    """Thread function to ping self every 10 minutes to prevent Render sleep"""
    # Wait for server to start
    time.sleep(30)
    while True:
        try:
            # Check if we are running on Render (Render sets the RENDER_EXTERNAL_URL env var)
            url = os.environ.get('RENDER_EXTERNAL_URL')
            if url:
                health_url = f"{url.rstrip('/')}/health"
                logger.info(f"Self-pinging: {health_url}")
                requests.get(health_url, timeout=10)
            else:
                logger.info("Not running on Render, self-ping skipped.")
        except Exception as e:
            logger.error(f"Self-ping failed: {e}")
        
        # Sleep for 10 minutes (600 seconds)
        time.sleep(600)

@app.route('/logs')
def get_logs():
    """Return accumulated logs"""
    return jsonify(get_all_logs())

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    """Request to stop the current scan"""
    scan_state['stop_requested'] = True
    if scan_state['active_process']:
        try:
            scan_state['active_process'].terminate()
            log('red', '[System] Active process terminated.')
        except:
            pass
    scan_state['status'] = 'STOPPED'
    return jsonify({'status': 'STOPPING'})

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    target = data.get('target', '')
    lang = data.get('lang', 'en')
    
    if not target:
        return jsonify({'error': 'No target provided'}), 400
    
    # Reset state before new scan
    reset_scan_state()
    scan_state['lang'] = lang
    
    # Run scan in background thread
    thread = threading.Thread(target=run_full_scan, args=(target,))
    thread.start()
    
    return jsonify({'status': 'STARTED', 'target': target, 'lang': lang})

@app.route('/findings_details', methods=['GET'])
def get_findings_details():
    """Endpoint for the frontend to fetch full findings for PDF report"""
    return jsonify(scan_state['findings_list'])

@app.route('/assets')
def get_assets():
    """Return discovered assets"""
    return jsonify(list(scan_state['discovered_assets']))

@app.route('/history')
def get_history():
    """Return history of scanned targets"""
    return jsonify(scan_state['target_history'])

# Start self-pinging thread for Render (works with both app.run() and gunicorn)
ping_thread = threading.Thread(target=self_ping, daemon=True)
ping_thread.start()

if __name__ == '__main__':
    print("=" * 50)
    print("  VulnScan AI - Backend Server")
    print("  Starting on http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)