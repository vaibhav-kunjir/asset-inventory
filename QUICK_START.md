# Asset Inventory Scanner - Quick Start Guide

> **TL;DR:** Scan your PostgreSQL asset inventory for CVE vulnerabilities in 5 minutes

---

## Prerequisites Checklist

- [ ] Python 3.9 or higher
- [ ] PostgreSQL database with asset inventory
- [ ] Internet connection (for downloading CVE data)
- [ ] ~2GB disk space (for vulnerability database)

---

## 5-Minute Setup

### Step 1: Install Dependencies (30 seconds)
```bash
cd asset-inventory-scanner
pip install -r requirements.txt
```

### Step 2: Configure Database Connection (1 minute)
```bash
# Copy environment template
cp env.example .env

# Edit .env with your database details
# At minimum, set: DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
nano .env  # or use your favorite editor
```

### Step 3: Download Vulnerability Data (3 minutes)
```bash
# Option A: Quick setup (recommended for first time)
./setup_vuln_db.sh

# Option B: Manual setup
python3 vuln_database.py init
VERIFY_SSL=false python3 vuln_database.py update-cpe
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000
```

### Step 4: Run the Scanner (5 seconds)
```bash
python3 app.py
```

### Step 5: Open Dashboard
```
http://localhost:5000
```

---

## Docker Quick Start (Alternative)

### Prerequisites
- Docker & Docker Compose installed
- PostgreSQL accessible from Docker container

### Steps
```bash
# 1. Download vulnerability data first (on host)
python3 vuln_database.py init
VERIFY_SSL=false python3 vuln_database.py update-cpe
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000

# 2. Edit docker-compose.yml with your DB settings
nano docker-compose.yml

# 3. Start container
docker-compose up --build -d

# 4. Check status
docker-compose logs -f web

# 5. Open browser
open http://localhost:5000
```

---

## Common Issues & Quick Fixes

### ❌ "No module named 'requests'"
**Fix:**
```bash
pip install -r requirements.txt
```

### ❌ "Cannot connect to PostgreSQL"
**Fix:**
```bash
# Check PostgreSQL is running
pg_isready -h localhost -p 5432

# Update .env with correct host
# For Docker: DB_HOST=host.docker.internal
# For local: DB_HOST=localhost
```

### ❌ "No such table: cpe_items"
**Fix:**
```bash
# Download vulnerability data
python3 vuln_database.py init
VERIFY_SSL=false python3 vuln_database.py update-cpe
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000
```

### ❌ "SSL: CERTIFICATE_VERIFY_FAILED"
**Fix:**
```bash
# Use VERIFY_SSL=false environment variable
VERIFY_SSL=false python3 vuln_database.py update-cve
```

### ❌ "Dashboard is empty"
**Fix:**
1. Click "All Clients" button (top left)
2. Clear all filters
3. Check PostgreSQL has services: `SELECT COUNT(*) FROM port WHERE is_deleted=FALSE;`

---

## Key Features at a Glance

### Dashboard Features
- **Host Grouping** - Services organized by IP/hostname
- **Risk Scoring** - Automatic risk calculation per host
- **Filtering** - By severity, risk level, client, search
- **Export** - CSV and JSON formats
- **Real-time** - No cron jobs needed

### What Gets Scanned?
```sql
SELECT * FROM port 
WHERE is_deleted = FALSE 
  AND protocol IS NOT NULL
  AND product IS NOT NULL;
```

### Supported Products
- Web servers: nginx, apache, tomcat
- SSH: openssh
- Databases: mysql, postgresql, mongodb, redis
- Runtime: node.js, php, python
- Containers: docker, kubernetes
- And many more...

---

## Important Notes

### Product Names Must Match
Your PostgreSQL `port.product` field should use lowercase names:
- ✅ `nginx` not `Nginx`
- ✅ `openssh` not `OpenSSH`
- ✅ `mysql` not `MySQL`

### Vulnerability Database Size
- **10k CVEs** (testing): ~50MB, 30 seconds download
- **50k CVEs** (recommended): ~250MB, 3 minutes download
- **316k CVEs** (complete): ~1.5GB, 15-20 minutes download

### Rate Limits
- **Without API key:** 5 requests per 30 seconds
- **With API key:** 50 requests per 30 seconds
- Get free key: https://nvd.nist.gov/developers/request-an-api-key

---

## First-Time Workflow

```
1. Install Python dependencies
   ↓
2. Configure PostgreSQL connection
   ↓
3. Download CVE/CPE data from NIST
   ↓
4. Run Flask application
   ↓
5. Open browser to localhost:5000
   ↓
6. Select your client (if multi-tenant)
   ↓
7. View vulnerability report
   ↓
8. Filter, search, export as needed
```

---

## Daily Usage

### Checking Vulnerabilities
1. Open http://localhost:5000
2. Select client (if applicable)
3. Use filters to focus on critical/high severity
4. Export reports for remediation teams

### Updating Vulnerability Data
```bash
# Weekly recommended
VERIFY_SSL=false python3 vuln_database.py update-cve --limit 50000

# Restart app to clear cache
docker-compose restart web  # if using Docker
# or just restart the Python process
```

### Clearing Cache
```bash
# If results seem stale
curl http://localhost:5000/cache/clear
```

---

## Getting Help

### Check System Health
```bash
curl http://localhost:5000/health
```

Should return:
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

### View Logs
```bash
# Docker
docker-compose logs -f web

# Local
# Check terminal where app.py is running
```

### Database Statistics
```bash
python3 vuln_database.py stats
```

### Full Documentation
See [README.md](README.md) for complete documentation.

---

## Security Reminder

⚠️ **This scanner is for authorized use only**
- Only scan systems you own or have permission to scan
- Use read-only PostgreSQL credentials
- Deploy behind authentication in production
- Don't expose to public internet

---

## Performance Tips

1. **First load is slow** (2-5 seconds) - this is normal, building cache
2. **Use filters** - Reduce load by filtering to specific clients/severity
3. **Increase service limit** - Edit `app.py` line 353 if needed
4. **Pre-warm cache** - Visit dashboard before showing to stakeholders

---

## Success Criteria

✅ You're successfully running when:
- Dashboard loads without errors
- Services are displayed grouped by host
- Vulnerability counts show next to products
- Export buttons work (CSV/JSON)
- Health endpoint returns "healthy"

---

**Need more details?** Check the [README.md](README.md) or [CHANGELOG.md](CHANGELOG.md)

**Found a bug?** Document it with steps to reproduce and sample data

---

**Happy scanning!** 🛡️

