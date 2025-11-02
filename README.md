# Service Vulnerability Scanner

A professional web-based security platform that automatically scans your infrastructure for known CVE vulnerabilities using NIST's National Vulnerability Database.

![Platform](https://img.shields.io/badge/Platform-Security-blue)
![Database](https://img.shields.io/badge/Database-PostgreSQL%20%2B%20SQLite-green)
![API](https://img.shields.io/badge/API-NIST%20NVD%202.0-orange)

## Overview

This scanner provides real-time vulnerability assessment for your entire infrastructure by:
- Matching services to known CVEs using CPE (Common Platform Enumeration)
- Calculating risk scores based on CVSS severity ratings
- Grouping services by host with collapsible UI
- Filtering by client, risk level, and severity
- Exporting reports in CSV and JSON formats

## Features

### 🔍 Vulnerability Detection
- **Automatic CVE Matching** - Maps services to vulnerabilities using NIST CPE data
- **CVSS Scoring** - Displays v2, v3, and v4 scores with severity ratings
- **Risk Scoring** - Calculates host-level risk: Critical×10 + High×5 + Medium×2 + Low×1
- **Version-Aware** - Respects version range constraints from CVE data

### 🎯 Multi-Client Support
- **Client Selector** - Filter dashboard by specific client
- **Searchable Client Modal** - Find clients quickly in large lists
- **Per-Client Statistics** - Host and service counts per client

### 📊 Dashboard & Visualization
- **Host Grouping** - Services organized by IP/hostname
- **Collapsible Accordion** - Expand/collapse hosts (collapsed by default)
- **Risk-Based Sorting** - Highest risk hosts shown first
- **Color-Coded Indicators** - Visual risk assessment at a glance

### 🔎 Advanced Filtering & Search
- **Search** - By IP, hostname, product name, or port number
- **Risk Level Filter** - Critical, High, Medium, Low
- **Severity Filter** - Critical only, High & Critical
- **Minimum CVE Count** - Show only heavily vulnerable hosts
- **EOL Filter** - Products that reached end-of-life

### 📥 Export & API
- **CSV Export** - Download spreadsheet with all vulnerability data
- **JSON Export** - Structured data for automation
- **REST API** - Integration endpoints for other tools
- **Filter Preservation** - Exports respect current filters

## Quick Start

### 1. Download Vulnerability Data

Download CVE/CPE data from NIST (one-time setup):

```bash
# Initialize database
python3 vuln_database.py init

# Download CPE dictionary (~118k items, 1-2 minutes)
VERIFY_SSL=false python3 vuln_database.py update-cpe

# Download recent CVEs (10k items, ~30 seconds)
VERIFY_SSL=false python3 vuln_database.py update-cve

# OR download more CVEs for better coverage (50k items, ~3 minutes)
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000

# OR download ALL CVEs (316k items, ~15-20 minutes)
VERIFY_SSL=false python3 vuln_database.py update-cve --all
```

### 2. Run the Scanner

**Option A: Docker (Recommended)**
```bash
docker-compose up --build
```

**Option B: Local Python**
```bash
pip install -r requirements.txt
export VULN_DB_PATH=./vuln.db
python app.py
```

### 3. Access Dashboard

Open your browser to: **http://localhost:5000**

## Architecture

### Components

```
┌─────────────────────────────────────────┐
│     Flask Web Application               │
│  ┌──────────────┐  ┌─────────────────┐ │
│  │ PostgreSQL   │  │ SQLite (vuln.db)│ │
│  │ (Services)   │  │ (CVE/CPE Data)  │ │
│  └──────────────┘  └─────────────────┘ │
│      port table         Downloaded      │
│      ip_address         from NIST       │
│      domain            NVD API 2.0      │
│      client                             │
└─────────────────────────────────────────┘
```

### Data Sources

**PostgreSQL Database:**
- `port` - Service inventory with product/version info
- `ip_address` - IP information
- `domain` - Domain names
- `client` - Client/tenant data

**SQLite Vulnerability Database (vuln.db):**
- `cpe_items` - 118,000+ Common Platform Enumerations
- `cve_items` - 50,000+ (or 316,000) CVE records
- `cve_configurations` - CVE to CPE mappings
- `cve_metrics` - CVSS scores and vectors
- `cve_descriptions` - Vulnerability descriptions

**NIST NVD API:**
- CPE Dictionary: `https://services.nvd.nist.gov/rest/json/cpes/2.0`
- CVE Data: `https://services.nvd.nist.gov/rest/json/cves/2.0`

## Features in Detail

### Dashboard View

**Overview Statistics:**
- Total hosts scanned
- Total services discovered
- Critical/High CVE counts
- Total vulnerabilities
- EOL products

**Host Cards (Collapsible):**
- Risk score (calculated value)
- Risk level badge (CRITICAL/HIGH/MEDIUM/LOW)
- IP address and hostname
- Service count
- Vulnerability breakdown by severity
- Click to expand and view services

**Service Details:**
- Port number and protocol
- Product name and version
- Vulnerability counts with color-coded badges
- Live status indicator
- Link to detailed CVE view

### Risk Scoring

**Formula:**
```
Risk Score = (Critical × 10) + (High × 5) + (Medium × 2) + (Low × 1) + Bonuses

Bonuses:
- In-the-Wild CVEs: +20
- EOL Product: +10
```

**Risk Levels:**
- 🔴 **CRITICAL** - Has critical CVEs or score ≥ 50
- 🟠 **HIGH** - Has high CVEs or score ≥ 20
- 🟡 **MEDIUM** - Has medium CVEs or score ≥ 5
- 🟢 **LOW** - Has low CVEs or score < 5
- ⚪ **SECURE** - No known vulnerabilities

### Client Selector

Click the client button in navbar to:
- View all clients with service counts
- Search clients by name
- Filter dashboard to specific client
- See per-client host/service statistics

## API Endpoints

### Web Interface
- `GET /` - Main dashboard with host grouping
- `GET /service/<id>` - Detailed service vulnerability report
- `GET /export/csv` - Download CSV report
- `GET /export/json` - Download JSON report

### REST API
- `GET /api/services` - List all services with vulnerability summaries
- `GET /api/service/<id>/vulnerabilities` - Detailed CVE data for service
- `GET /health` - Health check with database stats
- `GET /cache/clear` - Clear vulnerability lookup cache

### Query Parameters

**Filtering:**
```
?client_id=123           # Filter by client
?severity=critical       # Show only critical CVEs
?risk_level=high         # Show only high-risk hosts
?min_cve=10             # Minimum CVE count
?eol_only=true          # EOL products only
?search=nginx           # Search query
```

**Examples:**
```bash
# Critical vulnerabilities only
http://localhost:5000/?severity=critical

# High-risk hosts for specific client
http://localhost:5000/?client_id=5&risk_level=high

# Search for MySQL servers
http://localhost:5000/?search=mysql

# Export critical vulnerabilities as CSV
http://localhost:5000/export/csv?severity=critical
```

## Database Management

### Update Vulnerability Data

```bash
# Check current stats
python3 vuln_database.py stats

# Update CPE dictionary
VERIFY_SSL=false python3 vuln_database.py update-cpe

# Update CVEs (recent 10k)
VERIFY_SSL=false python3 vuln_database.py update-cve

# Update CVEs (specific amount)
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000

# Update all CVEs (complete database)
VERIFY_SSL=false python3 vuln_database.py update-cve --all
```

### Database Size & Performance

| Dataset | Size | Download Time | Coverage |
|---------|------|---------------|----------|
| CPE Dictionary | ~50MB | 1-2 min | 118,000 products |
| CVE Recent (10k) | ~50MB | 30 sec | Good for testing |
| CVE Medium (50k) | ~250MB | 3 min | Common server software |
| CVE Complete (316k) | ~1.5GB | 15-20 min | Complete coverage |

**Recommendation:** Start with 50k CVEs, update to full database for production.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `host.docker.internal` | PostgreSQL host |
| `DB_PORT` | `4432` | PostgreSQL port |
| `DB_NAME` | `novaapi` | Database name |
| `DB_USER` | `postgres` | Database user |
| `DB_PASSWORD` | `postgres` | Database password |
| `VULN_DB_PATH` | `/data/vuln.db` | Path to vulnerability database |
| `VERIFY_SSL` | `true` | SSL verification for NIST API |

## Performance

### Caching
- **In-memory cache** for vulnerability lookups
- First page load: 2-5 seconds
- Subsequent loads/filters: <1 second
- Cache persists across requests
- Clear cache: Visit `/cache/clear`

### Optimization
- Product:version lookups cached
- Same product/version reuses cached results
- Dramatically faster filtering and searching
- No repeated database queries

## Production Deployment

### Docker (Recommended)

```bash
# 1. Download vulnerability data
python3 vuln_database.py init
VERIFY_SSL=false python3 vuln_database.py update-cpe
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000

# 2. Start container
docker-compose up -d

# 3. Check health
curl http://localhost:5000/health
```

### Configuration

The `docker-compose.yml` uses bind mount for `vuln.db`:
- Database persists on host machine
- Survives container rebuilds
- Update from host or container
- Easy backups (copy `vuln.db`)

### Updating

```bash
# Update vulnerability data (weekly recommended)
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000

# Restart container to clear cache
docker-compose restart web
```

## Usage Examples

### Finding Critical Hosts

1. Click **"All Clients"** in navbar → Select your client
2. Set **Risk Level** filter to "Critical"
3. Click **"Apply"**
4. Critical hosts appear first, sorted by risk score

### Searching for Specific Products

1. Click **"Search"** button in navbar
2. Enter product name (e.g., "openssh", "mysql")
3. Click **"Search"**
4. View matching services across all hosts

### Exporting Vulnerability Report

1. Apply desired filters (client, severity, risk level)
2. Click **"Export"** dropdown
3. Choose **CSV** or **JSON** format
4. File downloads automatically with timestamp

### Viewing Service Details

1. Expand any host (click on host card)
2. Click **"View Details"** on any service
3. See complete CVE list with:
   - CVE IDs (linked to NIST)
   - CVSS scores
   - Descriptions
   - Matched CPE identifiers
   - Affected version ranges

## Troubleshooting

### No Vulnerabilities Showing

**Check database has data:**
```bash
python3 vuln_database.py stats
```

Should show CPE and CVE counts > 0. If not, run:
```bash
VERIFY_SSL=false python3 vuln_database.py update-cpe
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000
```

**Check product names match CPE naming:**
- `port.product` should be lowercase (e.g., "nginx" not "Nginx")
- Common products: nginx, openssh, mysql, postgresql, tomcat

### Slow Performance

**First load is normal** (builds cache). If subsequent loads are slow:

1. Clear cache and reload:
```bash
curl http://localhost:5000/cache/clear
```

2. Check database size:
```bash
ls -lh vuln.db
```

3. Limit services displayed:
```bash
# Modify LIMIT in app.py query (default 200)
```

### Docker Database Not Found

If container shows database errors:

1. Check bind mount:
```bash
docker exec $(docker-compose ps -q web) ls -lh /data/vuln.db
```

2. Should show ~300-500MB file. If 0 bytes:
```bash
docker-compose down
# Re-download data
python3 vuln_database.py init
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000
docker-compose up -d
```

### SSL Certificate Errors

If you get SSL errors downloading from NIST:

```bash
# Use VERIFY_SSL=false
VERIFY_SSL=false python3 vuln_database.py update-cve
```

Or install certificates:
```bash
# macOS
/Applications/Python\ 3.x/Install\ Certificates.command
```

## File Structure

```
asset-inventory-scanner/
├── app.py                    # Flask application
├── vuln_database.py          # Database manager for NIST data
├── requirements.txt          # Python dependencies
├── docker-compose.yml        # Docker configuration
├── Dockerfile               # Container image
├── setup_vuln_db.sh         # Setup script
├── vuln.db                  # Vulnerability database (SQLite)
├── templates/
│   ├── index.html          # Main dashboard
│   ├── service_detail.html # Service detail view
│   └── error.html          # Error page
└── README.md               # This file
```

## Technology Stack

- **Backend:** Python 3.9+, Flask
- **Databases:** PostgreSQL (services), SQLite (vulnerabilities)
- **Frontend:** Bootstrap 5, JavaScript
- **Data Source:** NIST NVD API 2.0
- **Containerization:** Docker, Docker Compose

## Security Considerations

### Data Handling
- Read-only access to PostgreSQL service data
- Local SQLite database for vulnerability data
- No modification of source databases
- Query parameterization prevents SQL injection

### API Rate Limiting
- NIST API: 5 requests/30 seconds (without key)
- Get free API key: https://nvd.nist.gov/developers/request-an-api-key
- With key: 50 requests/30 seconds
- Set via `NVD_API_KEY` environment variable

### Production Recommendations
- Use production WSGI server (Gunicorn, uWSGI)
- Enable HTTPS/TLS
- Implement authentication
- Set up monitoring and logging
- Regular vulnerability data updates

## Maintenance

### Weekly Updates
```bash
# Update recent CVE data
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000
docker-compose restart web
```

### Monthly Updates
```bash
# Update CPE dictionary
VERIFY_SSL=false python3 vuln_database.py update-cpe

# Update complete CVE database
VERIFY_SSL=false python3 vuln_database.py update-cve --all
```

### Database Backup
```bash
# Backup vulnerability database
cp vuln.db vuln_backup_$(date +%Y%m%d).db

# Restore if needed
cp vuln_backup_YYYYMMDD.db vuln.db
docker-compose restart web
```

## Performance Metrics

### Response Times (with caching)
- Dashboard first load: 2-5 seconds
- Dashboard filtered: <1 second
- Service detail page: <1 second
- Export CSV: 3-5 seconds
- Export JSON: 2-3 seconds

### Resource Usage
- Memory: ~200-500MB (depending on data size)
- Disk: ~500MB-2GB (vulnerability database)
- CPU: Low (except during initial data download)

## License

MIT License - See project for details

## Support & Documentation

### API Documentation
Visit `/api/services` for JSON endpoint

### Health Check
```bash
curl http://localhost:5000/health
```

Returns:
```json
{
  "status": "healthy",
  "database": "connected",
  "vulnerability_db": "connected",
  "cve_count": 50000,
  "cpe_count": 118000,
  "cache_entries": 45
}
```

### Useful Commands

```bash
# View logs
docker-compose logs -f web

# Check database stats
python3 vuln_database.py stats

# Clear cache
curl http://localhost:5000/cache/clear

# Restart container
docker-compose restart web

# Rebuild container
docker-compose up --build -d
```

## Credits

- **NIST NVD** - National Vulnerability Database
- **CVE Program** - Common Vulnerabilities and Exposures
- **MITRE** - CPE Dictionary

---

**Built for enterprise security teams** 🛡️
