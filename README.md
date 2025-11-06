# Asset Inventory Scanner

A professional web-based security platform that automatically scans your infrastructure for known CVE vulnerabilities using NIST's National Vulnerability Database. Maps services from your PostgreSQL asset inventory to CVE vulnerabilities using CPE (Common Platform Enumeration) matching.

![Platform](https://img.shields.io/badge/Platform-Security-blue)
![Database](https://img.shields.io/badge/Database-PostgreSQL%20%2B%20SQLite-green)
![API](https://img.shields.io/badge/API-NIST%20NVD%202.0-orange)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)

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

### Prerequisites

- **Python 3.9+** (tested with 3.9, 3.10, 3.11, 3.12)
- **PostgreSQL database** with asset inventory (tables: `port`, `ip_address`, `domain`, `client`)
- **Internet connection** to download NIST NVD data
- **Docker** (optional, for containerized deployment)

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `flask>=3.0.0` - Web framework
- `psycopg2-binary>=2.9.9` - PostgreSQL adapter
- `requests>=2.31.0` - HTTP library for NIST API

### 2. Download Vulnerability Data

**Option A: Automated Setup (Recommended)**
```bash
chmod +x setup_vuln_db.sh
./setup_vuln_db.sh
```

**Option B: Manual Setup**

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

**Note:** If you encounter SSL certificate errors, use `VERIFY_SSL=false` before the command.

### 3. Configure Database Connection

**For Docker:**
Edit `docker-compose.yml` to set your PostgreSQL connection details:
```yaml
environment:
  - DB_HOST=host.docker.internal
  - DB_PORT=4432
  - DB_NAME=novaapi
  - DB_USER=postgres
  - DB_PASSWORD=postgres
```

**For Local Development:**
Set environment variables or edit `app.py` defaults:
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=novaapi
export DB_USER=postgres
export DB_PASSWORD=your_password
export VULN_DB_PATH=./vuln.db
```

### 4. Run the Scanner

**Option A: Docker (Recommended)**
```bash
docker-compose up --build
```

**Option B: Local Python**
```bash
python app.py
```

The application will start on port 5000 by default.

### 5. Access Dashboard

Open your browser to: **http://localhost:5000**

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────┐
│              Flask Web Application (app.py)             │
│                                                         │
│  ┌──────────────────────┐  ┌───────────────────────┐  │
│  │   PostgreSQL         │  │ SQLite (vuln.db)      │  │
│  │   (Asset Inventory)  │  │ (CVE/CPE Data)        │  │
│  ├──────────────────────┤  ├───────────────────────┤  │
│  │ • port               │  │ • cpe_items (118k)    │  │
│  │ • ip_address         │  │ • cve_items (316k)    │  │
│  │ • domain             │  │ • cve_configurations  │  │
│  │ • client             │  │ • cve_metrics         │  │
│  │                      │  │ • cve_descriptions    │  │
│  └──────────────────────┘  └───────────────────────┘  │
│         ↑                          ↑                   │
│         │                          │                   │
│    Your existing              Downloaded via          │
│    asset database             vuln_database.py        │
└─────────────────────────────────────────────────────────┘
                                     ↓
                          NIST NVD API 2.0
                   https://services.nvd.nist.gov/
```

### Data Flow

1. **Asset Inventory (PostgreSQL)** - Your existing database with network assets
2. **Vulnerability Database (SQLite)** - Local copy of NIST CVE/CPE data
3. **Scanner Logic** - Matches services to CVEs using CPE patterns
4. **Web Dashboard** - Displays results with filtering, search, and export

### PostgreSQL Schema Requirements

The scanner expects the following tables in your PostgreSQL database:

**`port` table** (required fields):
- `id` - Primary key
- `port_number` - Port number
- `protocol` - Protocol (tcp/udp)
- `product` - Product name (e.g., "nginx", "openssh")
- `product_version` - Product version
- `ip_address_id` - Foreign key to ip_address table
- `domain_id` - Foreign key to domain table (optional)
- `client_id` - Foreign key to client table (optional)
- `is_deleted` - Soft delete flag
- `is_live` - Service status
- `name`, `service_type`, `banner` - Additional metadata

**`ip_address` table:**
- `id` - Primary key
- `address` - IP address string

**`domain` table** (optional):
- `id` - Primary key
- `name` - Domain name

**`client` table** (optional):
- `id` - Primary key
- `name` - Client/tenant name
- `is_deleted` - Soft delete flag

### SQLite Vulnerability Database Schema

**`cpe_items`** - Common Platform Enumerations
- `name`, `cpe23_name` - CPE identifiers
- `title` - Human-readable product name
- `deprecated` - Deprecation status

**`cve_items`** - CVE vulnerability records
- `cve_id` - CVE identifier (e.g., CVE-2024-1234)
- `published`, `last_modified` - Timestamps
- `vuln_status` - Status (Analyzed, Modified, etc.)

**`cve_configurations`** - CPE to CVE mappings
- `criteria` - CPE match pattern
- `version_start_including/excluding` - Version ranges
- `version_end_including/excluding` - Version ranges
- `vulnerable` - Vulnerability flag

**`cve_metrics`** - CVSS scoring data
- `cvss_version` - CVSS version (v2.0, v3.0, v3.1, v4.0)
- `base_score` - Severity score (0.0-10.0)
- `base_severity` - Severity label (LOW/MEDIUM/HIGH/CRITICAL)
- `vector_string` - CVSS vector

**`cve_descriptions`** - Vulnerability descriptions
- `lang` - Language code
- `value` - Description text

### Data Sources

**NIST NVD API 2.0:**
- CPE Dictionary: `https://services.nvd.nist.gov/rest/json/cpes/2.0`
- CVE Data: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Rate Limits: 5 req/30s (without API key), 50 req/30s (with API key)
- API Key: Get free at https://nvd.nist.gov/developers/request-an-api-key

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

| Variable | Default (app.py) | Docker Default | Description |
|----------|------------------|----------------|-------------|
| `DB_HOST` | `db` | `host.docker.internal` | PostgreSQL host |
| `DB_PORT` | `5432` | `4432` | PostgreSQL port |
| `DB_NAME` | `novaapi` | `novaapi` | Database name |
| `DB_USER` | `postgres` | `postgres` | Database user |
| `DB_PASSWORD` | `postgres` | `postgres` | Database password |
| `VULN_DB_PATH` | `/app/vuln.db` | `/data/vuln.db` | Path to vulnerability database |
| `VERIFY_SSL` | `true` | `true` | SSL verification for NIST API |
| `NVD_API_KEY` | `None` | `None` | NIST NVD API key (optional, increases rate limit) |

**Note:** When running with Docker, use the values from the `docker-compose.yml` file. For local development, you can override these with environment variables or modify the defaults in `app.py`.

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

### PostgreSQL Connection Issues

**Cannot connect to PostgreSQL database:**

1. **Check PostgreSQL is running:**
```bash
# On macOS/Linux
pg_isready -h localhost -p 5432

# Check with psql
psql -h localhost -p 5432 -U postgres -d novaapi
```

2. **Verify connection settings:**
```bash
# Check environment variables
echo $DB_HOST $DB_PORT $DB_NAME $DB_USER

# Test connection from Python
python3 -c "import psycopg2; conn = psycopg2.connect(
    host='localhost', port=5432, database='novaapi', 
    user='postgres', password='postgres'); print('✓ Connected')"
```

3. **Docker-specific issues:**
- If running scanner in Docker connecting to host PostgreSQL, use `host.docker.internal` as DB_HOST
- If PostgreSQL is also in Docker, ensure both containers are on the same network
- Check `docker-compose.yml` has correct `extra_hosts` configuration

4. **Common fixes:**
```bash
# Update docker-compose.yml environment variables
DB_HOST=host.docker.internal  # For Mac/Windows Docker Desktop
DB_HOST=172.17.0.1           # For Linux Docker

# Or set in shell before running locally
export DB_HOST=localhost
export DB_PORT=5432
```

### No Vulnerabilities Showing

**Check vulnerability database has data:**
```bash
python3 vuln_database.py stats
```

Should show:
```
📊 Database Statistics:
  CPE Items: 118,000+
  CVE Items: 10,000+ (or more)
  Last CPE Update: 2024-XX-XX...
```

If counts are 0, download data:
```bash
VERIFY_SSL=false python3 vuln_database.py update-cpe
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000
```

**Check product names match CPE naming:**
- `port.product` field should be lowercase (e.g., "nginx" not "Nginx")
- Use common product names: nginx, openssh, mysql, postgresql, apache, tomcat
- Check `PRODUCT_MAPPINGS` dict in `app.py` for supported products
- Try exact product names from CPE dictionary

**Check services exist in PostgreSQL:**
```sql
-- Connect to PostgreSQL
psql -h localhost -d novaapi -U postgres

-- Check if services exist
SELECT COUNT(*) FROM port WHERE is_deleted = FALSE AND protocol IS NOT NULL;

-- Check product names
SELECT DISTINCT product, COUNT(*) 
FROM port 
WHERE is_deleted = FALSE AND product IS NOT NULL 
GROUP BY product;
```

### Slow Performance

**First load is normal** (builds cache for ~200 services, takes 2-5 seconds). 

If subsequent loads are slow:

1. **Clear cache and reload:**
```bash
curl http://localhost:5000/cache/clear
```

2. **Check database size:**
```bash
ls -lh vuln.db
# Should be 300MB-2GB depending on CVE count
```

3. **Reduce LIMIT in queries:**
Edit `app.py` line 353:
```python
query += " ORDER BY ip.address, p.port_number LIMIT 200"  # Reduce this number
```

4. **Check PostgreSQL performance:**
```bash
# Check query performance
psql -d novaapi -U postgres -c "EXPLAIN ANALYZE SELECT * FROM port LIMIT 200"
```

### Docker Database Not Found

**Error: "unable to open database file" or "no such table"**

1. **Check bind mount:**
```bash
# Check file exists and has data
ls -lh vuln.db

# If using Docker, check inside container
docker-compose exec web ls -lh /data/vuln.db
```

2. **Should show ~300MB-2GB file. If missing or 0 bytes:**
```bash
# Stop containers
docker-compose down

# Re-download vulnerability data
python3 vuln_database.py init
VERIFY_SSL=false python3 vuln_database.py update-cpe
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000

# Restart
docker-compose up -d
```

3. **Check docker-compose.yml volumes:**
```yaml
volumes:
  - ./:/data:rw  # Current directory mounted to /data in container
```

Ensure `vuln.db` is in the same directory as `docker-compose.yml`.

### SSL Certificate Errors

**Error downloading from NIST: "SSL: CERTIFICATE_VERIFY_FAILED"**

**Option 1: Disable SSL verification (quick fix)**
```bash
VERIFY_SSL=false python3 vuln_database.py update-cve
```

**Option 2: Install certificates (permanent fix)**
```bash
# macOS with Python from python.org
/Applications/Python\ 3.x/Install\ Certificates.command

# macOS with Homebrew Python
brew install openssl
export SSL_CERT_FILE=$(brew --prefix)/etc/openssl/cert.pem

# Linux (Ubuntu/Debian)
sudo apt-get install ca-certificates
sudo update-ca-certificates

# Linux (CentOS/RHEL)
sudo yum install ca-certificates
sudo update-ca-trust
```

**Option 3: Use API key (recommended)**
```bash
# Get free API key from https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=your-api-key-here
python3 vuln_database.py update-cve
```

### Rate Limiting Errors

**Error: "429 Too Many Requests" from NIST API**

NIST NVD API has rate limits:
- **Without API key:** 5 requests per 30 seconds
- **With API key:** 50 requests per 30 seconds

**Solution:**
1. Get free API key: https://nvd.nist.gov/developers/request-an-api-key
2. Set environment variable:
```bash
export NVD_API_KEY=your-api-key-here
python3 vuln_database.py update-cve
```

3. Or wait and retry - the script has built-in delays

### Empty Dashboard

**Dashboard loads but shows no hosts:**

1. **Check client filter** - Click "All Clients" button to see if a client is selected
2. **Check filters** - Clear all filters (severity, risk level, search)
3. **Verify services in database:**
```sql
SELECT COUNT(*) FROM port WHERE is_deleted = FALSE AND protocol IS NOT NULL;
```
4. **Check service limit** - Default is 200 services, increase if needed

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

## How It Works

### Vulnerability Matching Process

1. **Service Discovery**: Scanner queries PostgreSQL for services from the `port` table
2. **Product Mapping**: Maps product names to CPE naming conventions (e.g., "apache" → "http_server")
3. **CPE Lookup**: Searches `cpe_items` table for matching product and version
4. **CVE Matching**: Queries `cve_configurations` table for CVEs affecting the matched CPE
5. **Version Validation**: Respects version ranges (start/end including/excluding)
6. **Risk Calculation**: Computes risk score based on severity counts
7. **Result Caching**: Caches lookups in memory for performance

### Product Name Mappings

The scanner includes built-in mappings for common products:

| Your Product Name | CPE Product Name | Examples |
|------------------|------------------|----------|
| apache, apache2, httpd | http_server | Apache web server |
| ssh, openssh | openssh | OpenSSH |
| mysql | mysql | MySQL database |
| postgres, postgresql | postgresql | PostgreSQL database |
| nginx | nginx | Nginx web server |
| node.js, nodejs | node.js | Node.js runtime |
| mongo, mongodb | mongodb | MongoDB database |
| docker | docker | Docker container runtime |
| k8s, kubernetes | kubernetes | Kubernetes |

**Note:** Product names in your PostgreSQL `port.product` field should be lowercase for best matching.

### Risk Scoring Formula

```
Risk Score = (Critical × 10) + (High × 5) + (Medium × 2) + (Low × 1) + Bonuses

Bonuses:
- CVEs exploited in the wild: +20
- End-of-life product: +10
```

**Risk Levels:**
- **CRITICAL** - Has critical CVEs OR risk score ≥ 50
- **HIGH** - Has high CVEs OR risk score ≥ 20
- **MEDIUM** - Has medium CVEs OR risk score ≥ 5
- **LOW** - Has low CVEs OR risk score < 5
- **NONE** - No known vulnerabilities

## Technology Stack

- **Backend:** Python 3.9+, Flask 3.0
- **Databases:** PostgreSQL (asset inventory), SQLite 3 (vulnerabilities)
- **Frontend:** HTML5, Bootstrap 5, JavaScript (vanilla)
- **Data Source:** NIST NVD API 2.0
- **HTTP Client:** Requests library
- **Containerization:** Docker, Docker Compose
- **Deployment:** Standalone or containerized

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

## Known Limitations & Future Enhancements

### Current Limitations

1. **EOL (End-of-Life) Data Not Available**
   - The current implementation shows EOL flags but doesn't have EOL date data
   - EOL information requires additional data source integration
   - Workaround: Manually track EOL products or integrate external EOL API

2. **In-the-Wild Exploit Data**
   - Currently not tracked in the database
   - NIST NVD 2.0 API provides some CISA KEV (Known Exploited Vulnerabilities) data
   - Future enhancement: Integrate CISA KEV catalog

3. **Product Name Matching**
   - Relies on exact or mapped product names
   - May miss vulnerabilities if product names don't match CPE naming
   - Enhancement: Fuzzy matching or extended product aliases

4. **Service Limit**
   - Default limit of 200 services per query for performance
   - Large environments may require pagination or increased limits
   - Consider implementing lazy loading for large datasets

5. **No Authentication**
   - Scanner has no built-in authentication or access control
   - Recommendation: Deploy behind reverse proxy with authentication (e.g., Nginx + Basic Auth, OAuth)
   - Or add Flask-Login/Flask-Security for user authentication

6. **Single-Threaded Vulnerability Lookups**
   - Vulnerability lookups are synchronous and single-threaded
   - Enhancement: Implement async/parallel lookups for faster initial load

### Potential Enhancements

**High Priority:**
- [ ] User authentication and role-based access control
- [ ] CISA KEV (Known Exploited Vulnerabilities) integration
- [ ] Pagination for large service lists
- [ ] Background job for pre-computing vulnerability data
- [ ] EOL product database integration
- [ ] Export to PDF reports

**Medium Priority:**
- [ ] Vulnerability trend analysis over time
- [ ] Email/Slack notifications for new critical vulnerabilities
- [ ] Scheduled scans and reporting
- [ ] CVE detail pages with remediation guidance
- [ ] Integration with ticketing systems (Jira, ServiceNow)
- [ ] API authentication with tokens

**Low Priority:**
- [ ] Dark mode UI theme
- [ ] Custom risk scoring formulas
- [ ] Vulnerability acceptance/false positive marking
- [ ] Historical vulnerability tracking
- [ ] Compliance framework mapping (PCI-DSS, HIPAA, etc.)

### Contributing

This is a security tool designed for internal use. If you find issues or have suggestions:
1. Document the issue with steps to reproduce
2. Provide sample data (sanitized) if applicable
3. Suggest improvements with use cases

## Security Best Practices

### Production Deployment Checklist

- [ ] Deploy behind HTTPS/TLS reverse proxy
- [ ] Implement authentication (Nginx basic auth, OAuth, SAML)
- [ ] Use read-only PostgreSQL credentials
- [ ] Run container as non-root user
- [ ] Keep vulnerability database updated (weekly)
- [ ] Monitor logs for suspicious activity
- [ ] Limit network access to trusted IPs
- [ ] Regular backups of vuln.db
- [ ] Set strong database passwords
- [ ] Use environment variables for secrets (never hardcode)

### Data Privacy

- Scanner has **read-only access** to your asset database
- Vulnerability data is stored **locally** (not sent externally)
- No data is transmitted to third parties
- NIST API calls only during database updates
- Consider data retention policies for vulnerability history

### Network Security

- PostgreSQL should not be exposed to public internet
- Use private networks or VPNs for database access
- Scanner should run in trusted network segment
- Consider firewall rules to restrict access

## Credits & Attribution

- **NIST NVD** - National Vulnerability Database (https://nvd.nist.gov/)
- **CVE Program** - Common Vulnerabilities and Exposures (https://cve.mitre.org/)
- **MITRE** - CPE Dictionary (https://cpe.mitre.org/)
- **CISA** - Cybersecurity and Infrastructure Security Agency
- **Bootstrap** - Frontend framework (https://getbootstrap.com/)
- **Flask** - Python web framework (https://flask.palletsprojects.com/)

### Legal & License

This tool uses publicly available data from NIST NVD. 

**NIST Disclaimer:** This tool is not affiliated with or endorsed by NIST. Vulnerability data is provided by NIST under their terms of use.

**Use Responsibly:** This scanner is designed for authorized security assessments of your own infrastructure. Ensure you have proper authorization before scanning any systems.

## Version History

### v0.1.0 (Current)
- Initial release
- PostgreSQL asset inventory integration
- NIST NVD CVE/CPE matching
- Host-grouped vulnerability dashboard
- Risk-based sorting and filtering
- Multi-client support with filtering
- CSV/JSON export functionality
- REST API endpoints
- In-memory caching for performance
- Docker containerization support

---

**Built for enterprise security teams** 🛡️

**Need help?** Check the [Troubleshooting](#troubleshooting) section or review the logs in `docker-compose logs -f web`
