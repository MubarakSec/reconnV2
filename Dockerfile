# ╔═══════════════════════════════════════════════════════════╗
# ║              ReconnV2 Docker Image                        ║
# ╚═══════════════════════════════════════════════════════════╝

FROM kalilinux/kali-rolling:latest

LABEL maintainer="ReconnV2 Team"
LABEL description="Advanced Reconnaissance Pipeline"
LABEL version="0.1.0"

# Avoid prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin:/usr/local/go/bin

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    golang-go \
    git \
    curl \
    wget \
    dnsutils \
    whois \
    nmap \
    chromium \
    subfinder \
    amass \
    nuclei \
    httpx-toolkit \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Go tools
RUN go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Create app directory
WORKDIR /app

# Copy requirements first for caching
COPY pyproject.toml .

# Create venv and install dependencies
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --upgrade pip && \
    /app/.venv/bin/pip install typer rich requests numpy scikit-learn

# Copy application
COPY . .

# Install the package
RUN /app/.venv/bin/pip install -e .

# Create directories
RUN mkdir -p jobs/{queued,running,finished,failed} config archive

# Set environment
ENV PATH="/app/.venv/bin:$PATH"
ENV RECON_HOME=/app

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -m recon_cli doctor || exit 1

# Entry point
ENTRYPOINT ["python", "-m", "recon_cli"]
CMD ["--help"]
