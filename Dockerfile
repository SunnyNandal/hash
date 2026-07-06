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
    lsb-release && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    cp /root/go/bin/nuclei /usr/local/bin/ && \
    nuclei -update-templates || true

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

# Command to run the application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]