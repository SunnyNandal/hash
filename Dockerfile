# Use Ubuntu 22.04 (most reliable)
FROM ubuntu:22.04

# Set non-interactive mode
ENV DEBIAN_FRONTEND=noninteractive

# Update & install system dependencies
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    nmap \
    nikto \
    curl \
    git \
    build-essential \
    zlib1g-dev \
    libpq-dev \
    ruby-full \
    wget \
    golang \
    ca-certificates \
    gnupg \
    lsb-release \
    unzip \
    masscan \
    libpcap-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools using pre-built binaries
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip -O /tmp/subfinder.zip && \
    unzip /tmp/subfinder.zip -d /tmp/ && \
    cp /tmp/subfinder /usr/local/bin/ && \
    wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip -O /tmp/httpx.zip && \
    unzip /tmp/httpx.zip -d /tmp/ && \
    cp /tmp/httpx /usr/local/bin/ && \
    wget https://github.com/projectdiscovery/naabu/releases/download/v2.3.0/naabu_2.3.0_linux_amd64.zip -O /tmp/naabu.zip && \
    unzip /tmp/naabu.zip -d /tmp/ && \
    cp /tmp/naabu /usr/local/bin/ && \
    wget https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip -O /tmp/katana.zip && \
    unzip /tmp/katana.zip -d /tmp/ && \
    cp /tmp/katana /usr/local/bin/ && \
    wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.8/nuclei_3.2.8_linux_amd64.zip -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /tmp/ && \
    cp /tmp/nuclei /usr/local/bin/ && \
    wget https://github.com/hahwul/dalfox/releases/download/v2.9.2/dalfox_2.9.2_linux_amd64.tar.gz -O /tmp/dalfox.tar.gz && \
    tar -xzf /tmp/dalfox.tar.gz -C /tmp/ && \
    cp /tmp/dalfox /usr/local/bin/ && \
    wget https://github.com/lc/gau/releases/download/v2.2.3/gau_2.2.3_linux_amd64.tar.gz -O /tmp/gau.tar.gz && \
    tar -xzf /tmp/gau.tar.gz -C /tmp/ && \
    cp /tmp/gau /usr/local/bin/ && \
    wget https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz -O /tmp/waybackurls.tgz && \
    tar -xzf /tmp/waybackurls.tgz -C /tmp/ && \
    cp /tmp/waybackurls /usr/local/bin/ && \
    wget https://github.com/Emoe/kxss/releases/download/v1.0.4/kxss_1.0.4_linux_amd64.tar.gz -O /tmp/kxss.tar.gz && \
    tar -xzf /tmp/kxss.tar.gz -C /tmp/ && \
    cp /tmp/kxss /usr/local/bin/ && \
    wget https://github.com/ThreatUnkown/jsubfinder/releases/download/v1.0.0/jsubfinder_v1.0.0_linux_amd64.tar.gz -O /tmp/jsubfinder.tar.gz && \
    tar -xzf /tmp/jsubfinder.tar.gz -C /tmp/ && \
    cp /tmp/jsubfinder /usr/local/bin/ && \
    rm -rf /tmp/* && \
    nuclei -update-templates || true

# Install amass
RUN wget https://github.com/owasp-amass/amass/releases/download/v3.23.3/amass_Linux_amd64.zip -O /tmp/amass.zip && \
    unzip /tmp/amass.zip -d /tmp/ && \
    cp /tmp/amass_Linux_amd64/amass /usr/local/bin/ && \
    rm -rf /tmp/amass.zip /tmp/amass_Linux_amd64

# Install rustscan
RUN wget https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb -O /tmp/rustscan.deb && \
    dpkg -i /tmp/rustscan.deb && \
    rm /tmp/rustscan.deb

# Install gobuster (precompiled binary)
RUN wget https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz -O /tmp/gobuster.tar.gz && \
    tar -xzf /tmp/gobuster.tar.gz -C /tmp/ && \
    cp /tmp/gobuster /usr/local/bin/ && \
    rm -rf /tmp/gobuster.tar.gz /tmp/gobuster

# Install ffuf
RUN wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -O /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp/ && \
    cp /tmp/ffuf /usr/local/bin/ && \
    rm -rf /tmp/ffuf.tar.gz /tmp/ffuf

# Install Arjun
RUN pip3 install arjun

# Install sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install Commix
RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix && \
    ln -s /opt/commix/commix.py /usr/local/bin/commix

# Install WPScan
RUN gem install wpscan

# Install jsubfinder
RUN go install github.com/ThreatUnkown/jsubfinder@latest && \
    cp /root/go/bin/jsubfinder /usr/local/bin/

# Install trufflehog
RUN wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.84.0/trufflehog_3.84.0_linux_amd64.tar.gz -O /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /tmp/ && \
    cp /tmp/trufflehog /usr/local/bin/ && \
    rm -rf /tmp/trufflehog.tar.gz /tmp/trufflehog

# Install a basic wordlist for gobuster/ffuf
RUN mkdir -p /usr/share/wordlists && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O /usr/share/wordlists/common.txt

# Install Metasploit (using official method)
RUN curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | gpg --dearmor -o /usr/share/keyrings/metasploit-framework-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/metasploit-framework-archive-keyring.gpg] https://apt.metasploit.com/ lucid main" | tee /etc/apt/sources.list.d/metasploit-framework.list && \
    apt-get update -y && \
    apt-get install -y metasploit-framework || true

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the port Flask runs on
EXPOSE 5000

# Command to run the application with better gunicorn settings
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--timeout", "120", "--preload", "app:app"]