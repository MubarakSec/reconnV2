# ╔═══════════════════════════════════════════════════════════╗
# ║              ReconnV2 Docker Image                        ║
# ║     One-command installation with all tools included!     ║
# ╚═══════════════════════════════════════════════════════════╝

FROM kalilinux/kali-rolling:latest

LABEL maintainer="ReconnV2 Team"
LABEL description="Advanced Reconnaissance Pipeline"
LABEL version="0.2.0"

# Avoid prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin:/usr/local/go/bin

# Install system dependencies + ALL recon tools
RUN apt-get update && apt-get install -y \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    # Go
    golang-go \
    # System tools
    git \
    curl \
    wget \
    dnsutils \
    whois \
    nmap \
    chromium \
    jq \
    # Recon tools from Kali repos
    subfinder \
    amass \
    nuclei \
    httpx-toolkit \
    naabu \
    dalfox \
    sqlmap \
    wpscan \
    whatweb \
    wafw00f \
    # For PDF reports
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install additional Go tools
RUN go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/uncover/cmd/uncover@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest

# Create app directory
WORKDIR /app

# Copy requirements first for caching
COPY pyproject.toml .

# Create venv and install dependencies (including optional ones)
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --upgrade pip && \
    /app/.venv/bin/pip install \
    typer rich requests numpy scikit-learn \
    fastapi uvicorn pydantic pydantic-settings \
    aiohttp psutil pyyaml jinja2 \
    weasyprint reportlab

# Copy application
COPY . .

# Install the package
RUN /app/.venv/bin/pip install -e .

# Create directories
RUN mkdir -p jobs/{queued,running,finished,failed} config archive

# Set environment
ENV PATH="/app/.venv/bin:$PATH"
ENV RECON_HOME=/app

# Expose web dashboard port
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import recon_cli; print('OK')" || exit 1

# Entry point
ENTRYPOINT ["python", "-m", "recon_cli"]
CMD ["--help"]
