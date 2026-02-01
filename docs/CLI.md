# ReconnV2 CLI Reference | مرجع أوامر CLI

<div dir="rtl">

## 📋 نظرة عامة

دليل شامل لجميع أوامر واجهة سطر الأوامر (CLI) في ReconnV2.

</div>

---

## 🔍 Scanning Commands

### recon scan

Start a new reconnaissance scan.

```bash
recon scan TARGET [OPTIONS]
```

**Arguments:**
| Argument | Description |
|----------|-------------|
| `TARGET` | Domain or hostname to scan |

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--profile` | `-p` | Scan profile to use | `passive` |
| `--quickstart` | | Use quick minimal profile | `false` |
| `--project` | | Project name for grouping | |
| `--notify` | `-n` | Send notification on completion | `false` |
| `--output` | `-o` | Custom output directory | |

**Examples:**
```bash
# Basic passive scan
recon scan example.com

# Full scan
recon scan example.com --profile full

# Bug bounty profile with notification
recon scan hackerone.com --profile bugbounty --notify

# Scan with project grouping
recon scan example.com --project "Client ABC"
```

**Available Profiles:**
| Profile | Description |
|---------|-------------|
| `passive` | Passive reconnaissance only (fast) |
| `full` | All scanning stages (comprehensive) |
| `bugbounty` | Optimized for bug bounty hunting |
| `stealth` | Low detection scanning |
| `wordpress` | WordPress-specific scanning |
| `fuzz-only` | Fuzzing and directory discovery |

---

## 📋 Job Management

### Job ID Format

Job IDs are meaningful and human-readable:

```
{target}_{date}_{time}_{suffix}
```

**Examples:**
| Target | Job ID |
|--------|--------|
| `example.com` | `example.com_20260201_143052_a1b2` |
| `*.target.org` | `target.org_20260201_143052_c3d4` |
| `https://api.site.com` | `api.site.com_20260201_143052_e5f6` |

This makes it easy to identify jobs at a glance!

---

### recon jobs list

List all jobs.

```bash
recon jobs list [OPTIONS]
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--status` | `-s` | Filter by status |
| `--limit` | `-l` | Max jobs to show |
| `--project` | | Filter by project |

**Examples:**
```bash
recon jobs list
recon jobs list --status running
recon jobs list --status finished --limit 10
```

---

### recon jobs status

Show job status.

```bash
recon jobs status JOB_ID
```

**Example:**
```bash
recon jobs status example.com_20260201_143052_a1b2
```

---

### recon jobs results

Show job results.

```bash
recon jobs results JOB_ID [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--type` | Filter by result type (host/url/vuln/secret) |
| `--severity` | Filter vulnerabilities by severity |
| `--format` | Output format (table/json) |

**Examples:**
```bash
recon jobs results abc123
recon jobs results abc123 --type vulnerability
recon jobs results abc123 --severity high
recon jobs results abc123 --format json
```

---

### recon jobs cancel

Cancel a running job.

```bash
recon jobs cancel JOB_ID
```

---

### recon jobs delete

Delete a job and its results.

```bash
recon jobs delete JOB_ID [--force]
```

---

### recon jobs retry

Retry a failed job.

```bash
recon jobs retry JOB_ID
```

---

## 📄 Reports

### recon report

Generate job report.

```bash
recon report JOB_ID [OPTIONS]
```

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--format` | `-f` | Report format | `html` |
| `--output` | `-o` | Output file path | |

**Formats:**
- `html` - Interactive HTML report
- `json` - JSON data export
- `txt` - Plain text summary

**Examples:**
```bash
recon report abc123
recon report abc123 --format html --output report.html
recon report abc123 --format json > results.json
```

---

### recon pdf

Generate PDF report.

```bash
recon pdf JOB_ID [OPTIONS]
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--output` | `-o` | Output file path |
| `--title` | | Custom report title |

**Examples:**
```bash
recon pdf abc123
recon pdf abc123 --output security_report.pdf
recon pdf abc123 --title "Security Assessment Report"
```

**Requirements:**
- WeasyPrint or ReportLab must be installed:
```bash
pip install weasyprint
# or
pip install reportlab
```

---

## 🌐 Web Interface

### recon dashboard

Start web dashboard.

```bash
recon dashboard [OPTIONS]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--port` | Port number | `8080` |
| `--host` | Host address | `127.0.0.1` |
| `--no-browser` | Don't open browser | `false` |

**Example:**
```bash
recon dashboard
recon dashboard --port 9000
recon dashboard --host 0.0.0.0 --port 8080
```

---

### recon serve

Start REST API server.

```bash
recon serve [OPTIONS]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--port` | Port number | `8000` |
| `--host` | Host address | `127.0.0.1` |
| `--reload` | Auto-reload on changes | `false` |

**Example:**
```bash
recon serve
recon serve --port 5000 --reload
```

---

## 💾 Database Commands

### recon db-init

Initialize SQLite database.

```bash
recon db-init
```

---

### recon db-stats

Show database statistics.

```bash
recon db-stats
```

**Output:**
```
📊 Database Statistics

Jobs:
  finished: 140
  running: 2
  failed: 8

Vulnerabilities:
  critical: 5
  high: 20
  medium: 35
```

---

## 📦 Cache Management

### recon cache-stats

Show cache statistics.

```bash
recon cache-stats
```

**Output:**
```
📊 Cache Statistics

Memory Cache:
  Entries: 156
  Hit Rate: 78.5%
  Size: 2.4 MB

Disk Cache:
  Entries: 1,240
  Size: 45.2 MB
```

---

### recon cache-clear

Clear cache.

```bash
recon cache-clear [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--memory` | Clear memory cache only |
| `--disk` | Clear disk cache only |
| `--all` | Clear all caches |

---

## 📢 Notifications

### recon notify

Send notification message.

```bash
recon notify MESSAGE [OPTIONS]
```

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--channel` | `-c` | Channel to use | `telegram` |

**Channels:**
- `telegram` - Telegram bot
- `slack` - Slack webhook
- `discord` - Discord webhook
- `email` - Email (SMTP)

**Examples:**
```bash
recon notify "Scan completed!" 
recon notify "Found 5 vulnerabilities" --channel slack
recon notify "Critical finding" --channel discord
```

**Environment Variables:**
```bash
# Telegram
export TELEGRAM_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"

# Slack
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."

# Discord  
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."

# Email
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your@email.com"
export SMTP_PASS="your_password"
```

---

## 🔧 Performance

### recon optimize

Run performance optimizations.

```bash
recon optimize
```

**Actions:**
- Cleans up unused resources
- Optimizes memory usage
- Closes idle connections

---

## 🔌 Plugins

### recon plugins

List available plugins.

```bash
recon plugins [OPTIONS]
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--type` | `-t` | Filter by type |

**Types:**
- `scanner` - Scanning plugins
- `enricher` - Data enrichment
- `reporter` - Report formats
- `notifier` - Notification channels

**Example:**
```bash
recon plugins
recon plugins --type scanner
```

---

### recon run-plugin

Execute a plugin.

```bash
recon run-plugin PLUGIN_NAME [OPTIONS]
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--target` | `-t` | Target for scanner plugins |
| `--message` | `-m` | Message for notifier plugins |

**Examples:**
```bash
recon run-plugin ExampleScanner --target example.com
recon run-plugin WebhookNotifier --message "Test"
```

---

## 🔄 Active Modules

### recon active

Run active security modules.

```bash
recon active JOB_ID MODULE [OPTIONS]
```

**Available Modules:**
| Module | Description |
|--------|-------------|
| `portscan` | Port scanning |
| `screenshot` | Take screenshots |
| `tech-detect` | Technology detection |

---

## ⚙️ Configuration

### recon config

Manage configuration.

```bash
recon config [COMMAND]
```

**Commands:**
- `show` - Display current config
- `set KEY VALUE` - Set config value
- `get KEY` - Get config value
- `reset` - Reset to defaults

**Examples:**
```bash
recon config show
recon config set threads 50
recon config get telegram_token
```

---

## 📁 Projects

### recon projects

Manage projects.

```bash
recon projects [COMMAND]
```

**Commands:**
- `list` - List all projects
- `create NAME` - Create new project
- `delete NAME` - Delete project
- `stats NAME` - Show project stats

---

## 🧪 Testing

### recon test

Run self-tests.

```bash
recon test [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--tools` | Test external tools |
| `--api` | Test API endpoints |
| `--all` | Run all tests |

---

## 📊 Global Options

These options work with all commands:

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Increase verbosity (-v, -vv, -vvv) |
| `--quiet` | `-q` | Suppress output |
| `--help` | `-h` | Show help message |
| `--version` | | Show version |

**Examples:**
```bash
recon -v scan example.com
recon -vv jobs list
recon --help
recon scan --help
```

---

## 🎯 Quick Reference

```bash
# Scanning
recon scan TARGET [-p PROFILE] [--notify]

# Jobs
recon jobs list|status|results|cancel|delete|retry

# Reports
recon report JOB_ID [-f FORMAT]
recon pdf JOB_ID [-o FILE]

# Web
recon dashboard [--port PORT]
recon serve [--port PORT]

# Database
recon db-init
recon db-stats

# Cache
recon cache-stats
recon cache-clear

# Notifications
recon notify MESSAGE [-c CHANNEL]

# Plugins
recon plugins [-t TYPE]
recon run-plugin NAME

# Performance
recon optimize
```

---

## 🆕 New Commands (2026)

### Interactive Mode & Wizards

```bash
# Start interactive mode (recommended for beginners)
recon interactive

# Step-by-step scan wizard
recon wizard

# Show quick start guide
recon quickstart
```

### Shell Completions

```bash
# Generate completion script (auto-detect shell)
recon completions

# Install completions automatically
recon completions --install

# Generate for specific shell
recon completions --shell bash
recon completions --shell zsh
recon completions --shell fish
recon completions --shell powershell

# Show script without installing
recon completions --show
```

### Report Generation

```bash
# Generate HTML report
recon report JOB_ID --format html --output report.html

# Generate executive summary only
recon report JOB_ID --executive

# Available formats: html, json, csv, markdown, xml, pdf
recon report JOB_ID --format markdown --output report.md

# Custom title
recon report JOB_ID --format html --title "Security Assessment Q1"
```

### Web Dashboard

```bash
# Start web dashboard (default port 8080)
recon web

# Custom host and port
recon web --host 0.0.0.0 --port 9000

# Development mode with auto-reload
recon web --reload
```

---

## 🌐 Web Dashboard Features

The web dashboard at `http://localhost:8080` provides:

| Feature | URL | Description |
|---------|-----|-------------|
| Dashboard | `/` | Overview with stats and charts |
| Jobs List | `/jobs` | All jobs with filtering |
| Job Detail | `/jobs/{id}` | Full job results |
| Search | `/api/search?q=...` | Full-text search |
| Charts | `/api/charts/severity` | Severity distribution |
| WebSocket | `/ws/updates` | Real-time updates |
| Reports | `/api/jobs/{id}/report` | Generate reports |

---

## 🧙 Interactive Mode Commands

When in interactive mode (`recon interactive`):

| Command | Description |
|---------|-------------|
| `scan` | Start scan wizard |
| `profile` | Create/edit profile |
| `jobs` | List jobs |
| `results <id>` | View job results |
| `report <id>` | Generate report |
| `help` | Show commands |
| `quit` | Exit interactive mode |

---

<div align="center">

Made with ❤️ for Security Researchers

</div>
