# Use Python 3.11 slim image
FROM python:3.11-slim

# Fix Debian repositories & install system dependencies
RUN sed -i 's/deb.debian.org/ftp.us.debian.org/g' /etc/apt/sources.list.d/debian.sources || true && \
    apt-get update -y --fix-missing && \
    apt-get install -y --no-install-recommends \
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
    ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    cp /root/go/bin/nuclei /usr/local/bin/ && \
    nuclei -update-templates || true

# Install Metasploit
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && \
    chmod +x /tmp/msfinstall && \
    /tmp/msfinstall || true

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the port Flask runs on
EXPOSE 5000

# Command to run the application
# We use gunicorn for a production-ready server on Render
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]