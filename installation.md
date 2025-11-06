# Installation on Ubuntu VPS

The following guide walks through provisioning a fresh Ubuntu VPS, installing dependencies, and deploying `recon-cli` for inline and worker usage.

## 1. Connect to the VPS
1. Update SSH access with your provider.
2. From your local machine:
   ```bash
   ssh ubuntu@YOUR_VPS_IP
   ```
   Replace `ubuntu` or `YOUR_VPS_IP` as appropriate.

## 2. Update the system and install base packages
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git build-essential python3 python3-venv python3-pip unzip jq
```

## 3. Create a dedicated directory for recon-cli
```bash
mkdir -p ~/apps && cd ~/apps
```

## 4. Clone the repository
```bash
git clone https://github.com/YOUR_ORG/recon-cli.git
cd recon-cli
```
(Adjust the repository URL if you are using a private remote; for scp/ssh remotes configure SSH keys first.)

## 5. Set up Python environment
Create a virtual environment so the tool stays isolated from system Python:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```
The editable install exposes the `recon-cli` command inside the virtual environment (`.venv/bin/recon-cli`).

## 6. Install external reconnaissance tools (optional but recommended)
The CLI gracefully skips stages if these tools are missing, but for full functionality install:

```bash
# Subfinder
GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
GO111MODULE=on go install github.com/owasp-amass/amass/v4/...@latest

# Massdns
sudo apt install -y make clang
cd /tmp && git clone https://github.com/blechschmidt/massdns.git
cd massdns && make && sudo cp bin/massdns /usr/local/bin/

# httpx
GO111MODULE=on go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# ffuf
GO111MODULE=on go install github.com/ffuf/ffuf/v2@latest

# waybackurls (or gau)
GO111MODULE=on go install github.com/tomnomnom/waybackurls@latest
# optional alternative
GO111MODULE=on go install github.com/lc/gau/v2/cmd/gau@latest
```

Add `~/go/bin` to your PATH so Go-installed binaries are visible:
```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.profile
source ~/.profile
```

### Playwright dependencies (for screenshots/HARs)
```bash
sudo apt install -y wget ca-certificates gnupg
python -m pip install playwright
playwright install chromium
```

### SecLists wordlists
```bash
sudo mkdir -p /opt/recon-tools
cd /opt/recon-tools
sudo git clone https://github.com/danielmiessler/SecLists.git seclists
sudo chown -R ubuntu:ubuntu seclists
```
(Replace `ubuntu:ubuntu` with your VPS user and group if different.)

## 7. Configure environment variables
Optionally export overrides in `~/.profile` or a dedicated `.env` file:
```bash
echo 'export RECON_HOME="$HOME/recon-data"' >> ~/.profile
# Example: limit concurrency and point to SecLists
cat <<'EOF' >> ~/.profile
export RECON_MAX_GLOBAL_CONCURRENCY=50
export RECON_HTTPX_THREADS=40
export SECLISTS_ROOT=/opt/recon-tools/seclists
EOF
source ~/.profile
```
Create the recon data directory:
```bash
mkdir -p "$RECON_HOME"
```

## 8. Quick smoke test
```bash
source ~/apps/recon-cli/.venv/bin/activate
recon-cli scan example.com --profile passive --inline
```
The command should finish quickly and produce a `jobs/finished/<job_id>/` folder with `results.jsonl`, `results.txt`, and logs.

## 9. Running the worker continuously (optional)
Create a systemd service to poll queued jobs:
```bash
sudo tee /etc/systemd/system/recon-worker.service > /dev/null <<'EOF'
[Unit]
Description=Recon CLI worker
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/apps/recon-cli
Environment="PATH=/home/ubuntu/apps/recon-cli/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/home/ubuntu/apps/recon-cli/.venv/bin/recon-cli worker-run --poll-interval 10
Restart=always

[Install]
WantedBy=multi-user.target
EOF
```
Reload systemd and enable the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now recon-worker.service
sudo systemctl status recon-worker.service
```

## 10. Keeping dependencies updated
- Pull code updates with `git pull` inside `~/apps/recon-cli`.
- Upgrade Python deps: `source .venv/bin/activate && python -m pip install -U -r requirements.txt` (or reinstall `-e .`).
- Refresh external tools periodically (`go install ...@latest`).

Your Ubuntu VPS is now ready to accept scans. Queue jobs with `recon-cli scan target.com` and monitor using the provided management commands.
