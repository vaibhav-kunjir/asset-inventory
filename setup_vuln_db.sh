#!/bin/bash

echo "🔐 Service Vulnerability Scanner - Database Setup"
echo "=================================================="
echo ""
echo "This script will download CVE/CPE data from NIST and create a local"
echo "vulnerability database. This may take some time and bandwidth."
echo ""

# Check if vuln.db already exists
if [ -f "vuln.db" ]; then
    read -p "vuln.db already exists. Recreate it? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
    rm -f vuln.db
fi

echo ""
echo "Step 1/3: Initializing database schema..."
python3 vuln_database.py init

if [ $? -ne 0 ]; then
    echo "❌ Failed to initialize database"
    exit 1
fi

echo ""
echo "Step 2/3: Downloading CPE dictionary from NIST..."
echo "  Source: https://nvd.nist.gov/feeds/xml/cpe/dictionary/"
python3 vuln_database.py update-cpe

if [ $? -ne 0 ]; then
    echo "❌ Failed to download CPE data"
    exit 1
fi

echo ""
echo "Step 3/3: Downloading CVE data from NIST..."
echo "  Source: https://nvd.nist.gov/feeds/json/cve/2.0/"
echo ""
read -p "Download all years (2002-present)? This will take 10-30 minutes. (Y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    read -p "Enter year to download (e.g. 2024): " year
    python3 vuln_database.py update-cve-year $year
else
    echo "  This will download ~2GB of data and take 10-30 minutes..."
    python3 vuln_database.py update-cve
fi

if [ $? -ne 0 ]; then
    echo "❌ Failed to download CVE data"
    exit 1
fi

echo ""
echo "=================================================="
echo "✅ Setup Complete!"
echo ""
python3 vuln_database.py stats

echo ""
echo "📦 Database file created: vuln.db"
echo "   Size: $(du -h vuln.db | cut -f1)"
echo ""
echo "🚀 Next steps:"
echo "   1. Run the scanner: python app.py"
echo "   2. Or with Docker: docker-compose up --build"
echo "   3. Visit: http://localhost:5000"
echo ""
echo "💡 To update the database later:"
echo "   python3 vuln_database.py update-cpe"
echo "   python3 vuln_database.py update-cve"

