VulnScanAI — Simple Project Description (Written)
This is a plain written description of the uploaded VulnScanAI project (from VulnScanAI.zip). It’s based on static inspection of the repo files (no scanning was executed to write this).

What this project is
VulnScanAI is a chat-style “deep recon” web app that lets you enter a target (domain/IP) and then runs a multi-stage scanning pipeline. It combines:

A Flask backend (app.py) that orchestrates recon + vulnerability checks and returns logs/status/findings.
A single-page frontend (vulnscan.html) that looks like a “hacker terminal UI”, polls backend endpoints, and renders progress + results. It also supports PDF export (via jsPDF in the UI).
The backend is designed to use a large external toolchain (Nmap, Nikto, Nuclei, Metasploit, etc.). If those tools are missing, parts of the pipeline fall back to Python-only heuristic scanning.

Files you have in this repo
Core runtime:

app.py: Flask server + scanning engine (majority of logic).
vulnscan.html: frontend UI (CSS-heavy, cyber aesthetic, chat UX).
requirements.txt: Python dependencies.
start.bat: runs app.py on Windows.
Install / tooling:

INSTALL.md: WSL2-based installation guide that installs lots of security tools in Ubuntu.
install_wsl.sh: helper script (WSL side) (present in repo).
Deployment:

Dockerfile: Ubuntu 22.04 container image installing scanners + Python deps, then runs Gunicorn.
render.yaml: Render deployment hints (docker env, free plan, region).
Hardening scripts:

master_patch_final.js: Node script that patches app.py on disk via string replacements (machine-specific path).
pass2_security_fix.js: another patch pass (also machine-specific path).
Editor:

.vscode/settings.json: VSCode environment setting.
Tech stack (what it runs on)
Backend (Python):

Flask 3.x + flask_cors
requests, dnspython
gevent, gunicorn (deployment-focused)
Some parsing libs: beautifulsoup4, lxml
Concurrency: heavy use of ThreadPoolExecutor
Frontend:

Static HTML/CSS/JS (no build system found)
Remote JS libs referenced in vulnscan.html for PDF generation (jspdf, jspdf-autotable)
Uses fetch() calls to talk to the backend
External security tools (expected by design):

nmap, nikto, nuclei
Subdomain / discovery tooling (via WSL/Docker instructions): subfinder, httpx, naabu, katana, amass, gau, waybackurls, etc.
Optional exploit mapping: metasploit / msfconsole, msfvenom
How it works (high-level architecture)
1) Backend model: a single global scan state
The backend keeps a global in-memory dictionary (a single “scan session”) that tracks:

current target
status (IDLE, RUNNING, COMPLETE, STOPPED, etc.)
per-tool progress (progress)
realtime logs (logs)
summarized counts (findings)
detailed items (findings_list)
discovered assets (discovered_assets)
Because it’s global, it’s not multi-tenant by default: if you deploy it publicly, users can conflict with each other unless you add per-user isolation.

2) Scan pipeline orchestration
The main orchestrator is run_full_scan(target):

Normalize target (turn input into a clean host).
Reset scan state.
Run passive recon in parallel:
subdomain enumeration
cloud recon
“tech stack detection”
Shodan / VirusTotal / Wayback / CVE lookup
Run active scanning (serial, because it feeds later steps):
nmap scan (multi-stage)
Run web + service audits in parallel:
Nikto web audit (multi-stage)
fuzzing engine
XSS heuristics
Nuclei template scan
Run exploit mapping + leak scan (parallel):
Metasploit search + msfvenom payload generation (best-effort)
data leakage scan for sensitive endpoints
“God level” synthesis:
validates high-priority findings
generates a “kill-chain style” synthesis output
The pipeline is intentionally loud and “red team style”: lots of logs, pseudo-AI thoughts, and a narrative framing around exploitability.

Backend API endpoints (Flask routes)
Detected routes include:

GET / and GET /vulnscan.html: serves the frontend file.
POST /start_scan: starts a scan thread. Expects JSON like {"target": "...", "lang": "en"}.
POST /stop_scan: sets stop flag and terminates an active subprocess if any.
GET /status: returns status, progress, findings counts, assets count.
GET /logs: returns accumulated logs and clears the server-side log buffer.
GET /assets: returns discovered assets list.
GET /findings_details: returns detailed findings list (used for reporting).
GET /download_report: triggers generation/download of an HTML report (server-side).
POST /exploit_console: runs a whitelisted subset of tools via subprocess (still dangerous without auth).
GET /capabilities: returns a JSON list of “Shannon capabilities” cards.
GET /health: returns a health JSON response (used for self-ping).
Frontend behavior (what the UI expects)
The frontend is a polished cyber UI with:

Landing/hero + sections
Chat-like interaction flow
Polling loops to:
read /status
read /logs
start/stop scans
fetch /assets and /findings_details
Important mismatch: the UI also calls endpoints like:

/history
/manual_tool
/ask_ollama
Those endpoints were not found in the current app.py route list (so either the backend is incomplete or the UI is ahead of backend).

Installation & running
Local (Windows)
The repo includes a start.bat that runs:

cd into the project directory
run py app.py (note: your environment may need python app.py instead)
WSL2 approach (INSTALL.md)
INSTALL.md is basically: enable WSL2, install Ubuntu, then install a large list of tools inside WSL2 (Python, nmap, nikto, masscan, Go tools, sqlmap, commix, metasploit, etc.).

This design implies the project expects access to “real scanners” rather than purely Python-based scanning.

Docker / Render
The Dockerfile builds an Ubuntu container, installs scanning tools, installs Python deps, then starts:

gunicorn --bind 0.0.0.0:5000 ... app:app
render.yaml config suggests deploying that container to Render, with:

RENDER_EXTERNAL_URL env var (user sets manually)
PYTHON_VERSION pinned
The backend also starts a self-ping thread that hits /health periodically when RENDER_EXTERNAL_URL is present, to reduce sleeping on free-tier hosting.

Security notes (important)
1) Hardcoded API keys inside source
The uploaded app.py contains hardcoded third-party API keys (Shodan/VirusTotal/etc.). This is unsafe:

If this code is public, keys will be burned.
Keys should be moved to environment variables + rotated.
I did not reproduce those keys here.

2) Subprocess execution + untrusted input
The scanning engine uses subprocess.Popen / subprocess.run to execute tools. That’s expected in a scanner, but it means:

you need strict input sanitization for targets and commands
you should isolate scanners (separate container/process, minimal privileges)
/exploit_console is especially sensitive: even with a tool whitelist, a public endpoint that runs tools is very abusable unless protected with strong auth + allowlisting.

3) SSRF / internal scanning risk
If deployed publicly, this app can be used to scan internal networks unless you block:

localhost
RFC1918 ranges (10/8, 172.16/12, 192.168/16)
cloud metadata IPs/ranges
4) Global scan state (multi-user collision)
Everything is stored in one global dict (scan_state). If 2 users run scans at once, they can overwrite each other and see each other’s results.

What the “security patch” scripts are
master_patch_final.js and pass2_security_fix.js are Node scripts that:

read app.py from an absolute path (hardcoded to a specific Desktop location)
patch it by string replacement
add things like auth, rate limiting, cookie hardening, CSP headers, and “remove hardcoded secrets” logic
They’re not portable as-is (you need to fix the file path), but they show the intended direction: harden the service before deploying.

Limitations / current gaps
The repo appears to be a “single-folder app” without a build system; frontend is a static file.
The frontend expects endpoints that are not present in the backend (likely missing features).
Tooling installation is heavy; without WSL2/Docker toolchain the scan will degrade to fallbacks.
Security posture is mixed: it is a security tool, but also ships with secrets and potentially dangerous endpoints.
