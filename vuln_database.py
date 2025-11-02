#!/usr/bin/env python3
"""
Vulnerability Database Manager
Downloads and maintains CVE/CPE data from NIST using NVD API 2.0
"""
import sqlite3
import requests
import zipfile
import gzip
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
import tempfile
import os

class VulnDatabase:
    def __init__(self, db_path='vuln.db', api_key=None):
        self.db_path = Path(db_path)
        # Modern NVD API 2.0 endpoints (old feeds deprecated Sept 2023)
        self.nist_cpe_api = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        self.nist_cve_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # NOTE: API format is /cves/2.0 not /cves/2.0/
        self.api_key = api_key or os.getenv('NVD_API_KEY')
        # Rate limits: 5 req/30s without key, 50 req/30s with key
        self.rate_limit_delay = 6 if not self.api_key else 0.6
        # SSL verification (set to False if having certificate issues)
        self.verify_ssl = os.getenv('VERIFY_SSL', 'true').lower() != 'false'
        
    def initialize_database(self):
        """Create database tables for NIST CVE/CPE data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # CPE tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cpe_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                cpe23_name TEXT,
                title TEXT,
                deprecated BOOLEAN DEFAULT FALSE,
                deprecation_date TEXT,
                deprecated_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cpe_references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cpe_item_id INTEGER NOT NULL,
                href TEXT NOT NULL,
                type TEXT,
                FOREIGN KEY (cpe_item_id) REFERENCES cpe_items (id)
            )
        """)
        
        # CVE tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE NOT NULL,
                source_identifier TEXT,
                vuln_status TEXT,
                published TIMESTAMP,
                last_modified TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_descriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_item_id INTEGER NOT NULL,
                lang TEXT NOT NULL DEFAULT 'en',
                value TEXT NOT NULL,
                FOREIGN KEY (cve_item_id) REFERENCES cve_items (id) ON DELETE CASCADE
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_item_id INTEGER NOT NULL,
                source TEXT,
                type TEXT,
                cvss_version TEXT,
                vector_string TEXT,
                base_score REAL,
                base_severity TEXT,
                exploitability_score REAL,
                impact_score REAL,
                FOREIGN KEY (cve_item_id) REFERENCES cve_items (id) ON DELETE CASCADE
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_configurations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_item_id INTEGER NOT NULL,
                operator TEXT,
                negate INTEGER DEFAULT 0,
                criteria TEXT,
                match_criteria_id TEXT,
                vulnerable INTEGER DEFAULT 1,
                version_start_including TEXT,
                version_start_excluding TEXT,
                version_end_including TEXT,
                version_end_excluding TEXT,
                FOREIGN KEY (cve_item_id) REFERENCES cve_items (id) ON DELETE CASCADE
            )
        """)
        
        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe_items_name ON cpe_items (name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe_items_cpe23 ON cpe_items (cpe23_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_items_cve_id ON cve_items (cve_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_configs_criteria ON cve_configurations (criteria)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_configs_item ON cve_configurations (cve_item_id)")
        
        # Materialized view for best metrics
        cursor.execute("""
            CREATE VIEW IF NOT EXISTS cve_best_metrics AS
            WITH ranked_metrics AS (
                SELECT cve_item_id, source, type, cvss_version, vector_string, 
                       base_score, base_severity, exploitability_score, impact_score,
                       ROW_NUMBER() OVER (
                           PARTITION BY cve_item_id 
                           ORDER BY 
                               CASE type WHEN 'Primary' THEN 1 ELSE 2 END,
                               CASE cvss_version 
                                   WHEN 'v4.0' THEN 4
                                   WHEN 'v3.1' THEN 3  
                                   WHEN 'v3.0' THEN 2
                                   WHEN 'v2.0' THEN 1
                                   ELSE 0
                               END DESC,
                               base_score DESC
                       ) as rank
                FROM cve_metrics
            )
            SELECT cve_item_id, source, type, cvss_version, vector_string,
                   base_score, base_severity, exploitability_score, impact_score
            FROM ranked_metrics 
            WHERE rank = 1
        """)
        
        # Metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        print("✓ Database initialized")
    
    def download_cpe_dictionary(self):
        """Download CPE data using NVD API 2.0"""
        import time
        
        print("📥 Downloading CPE dictionary from NIST API 2.0...")
        print("  This uses the modern API with rate limiting")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
            print("  ✓ Using API key (faster rate limit)")
        else:
            print("  ⚠️  No API key - slower rate limit (5 req/30s)")
            print("  Get free API key at: https://nvd.nist.gov/developers/request-an-api-key")
        
        start_index = 0
        results_per_page = 2000
        total_downloaded = 0
        
        while True:
            try:
                # Request CPE data
                params = {
                    'resultsPerPage': results_per_page,
                    'startIndex': start_index
                }
                
                response = requests.get(self.nist_cpe_api, params=params, headers=headers, verify=self.verify_ssl, timeout=30)
                response.raise_for_status()
                data = response.json()
                
                products = data.get('products', [])
                if not products:
                    break
                
                # Insert CPE items
                for product_data in products:
                    cpe_item = product_data.get('cpe', {})
                    cpe23 = cpe_item.get('cpeName')
                    title = cpe_item.get('titles', [{}])[0].get('title') if cpe_item.get('titles') else None
                    deprecated = cpe_item.get('deprecated', False)
                    
                    if cpe23:
                        cursor.execute("""
                            INSERT OR REPLACE INTO cpe_items 
                            (name, cpe23_name, title, deprecated)
                            VALUES (?, ?, ?, ?)
                        """, (cpe23, cpe23, title, deprecated))
                        total_downloaded += 1
                
                conn.commit()
                print(f"  Downloaded {total_downloaded:,} CPE items...")
                
                # Check if more results available
                total_results = data.get('totalResults', 0)
                if start_index + results_per_page >= total_results:
                    break
                
                start_index += results_per_page
                
                # Rate limiting
                time.sleep(self.rate_limit_delay)
                
            except Exception as e:
                print(f"  ✗ Error at index {start_index}: {e}")
                break
        
        cursor.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('cpe_last_updated', ?)", 
                      (datetime.now().isoformat(),))
        conn.commit()
        conn.close()
        
        print(f"✓ CPE dictionary updated: {total_downloaded:,} items")
    
    
    def download_cve_data(self, limit=10000):
        """Download recent CVE data using NVD API 2.0 (most recently modified first)
        
        Args:
            limit: Number of CVEs to download (default 10000)
                   - 10000 = ~5 requests, ~30 seconds
                   - 20000 = ~10 requests, ~60 seconds
                   - 'all' = all ~316k CVEs, ~160 requests, ~16 minutes
        """
        import time
        
        if limit == 'all':
            limit = None
            print(f"📥 Downloading ALL CVE data (~316,000 CVEs)")
            print("  This will take ~15-20 minutes with rate limiting...")
        else:
            print(f"📥 Downloading recent {limit:,} CVEs (most recently modified)")
            print("  To download all CVEs, use: update-cve --all")
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
            print("  ✓ Using API key (faster rate limit)")
        else:
            print("  ⚠️  No API key - slower rate limit (5 req/30s)")
            print("  Get free key: https://nvd.nist.gov/developers/request-an-api-key")
        
        print()
        self._download_cves_api(headers, limit)
        
        print("\n✓ CVE data updated")
    
    def _download_cves_api(self, headers, limit=None):
        """Download CVEs using NVD API 2.0 (paginated, most recent first)"""
        import time
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        start_index = 0
        results_per_page = 2000  # Max allowed by API
        total_downloaded = 0
        
        print(f"  Starting download...")
        
        while True:
            try:
                params = {
                    'resultsPerPage': results_per_page,
                    'startIndex': start_index
                }
                
                response = requests.get(self.nist_cve_api, params=params, headers=headers, verify=self.verify_ssl, timeout=30)
                response.raise_for_status()
                data = response.json()
                
                vulnerabilities = data.get('vulnerabilities', [])
                if not vulnerabilities:
                    break
                
                total_results = data.get('totalResults', 0)
                
                # Process each CVE
                for vuln_wrapper in vulnerabilities:
                    cve_data = vuln_wrapper.get('cve', {})
                    self._insert_cve(cursor, cve_data)
                    total_downloaded += 1
                
                conn.commit()
                progress = (total_downloaded / total_results * 100) if total_results > 0 else 0
                print(f"  Downloaded {total_downloaded:,} / {total_results:,} CVEs ({progress:.1f}%)...")
                
                # Apply limit if specified
                if limit and total_downloaded >= limit:
                    print(f"  Reached limit of {limit:,} CVEs")
                    break
                
                # Check if more results available
                if start_index + results_per_page >= total_results:
                    break
                
                start_index += results_per_page
                
                # Rate limiting (critical to avoid being blocked)
                print(f"  Waiting {self.rate_limit_delay}s (rate limit)...")
                time.sleep(self.rate_limit_delay)
                
            except requests.exceptions.RequestException as e:
                print(f"  ✗ Network error: {e}")
                print(f"  Downloaded {total_downloaded:,} CVEs before error")
                break
            except Exception as e:
                print(f"  ✗ Error: {e}")
                break
        
        cursor.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)", 
                      ('cve_last_updated', datetime.now().isoformat()))
        conn.commit()
        conn.close()
        print(f"\n  Total downloaded: {total_downloaded:,} CVEs")
    
    def _insert_cve(self, cursor, cve_data):
        """Insert a single CVE into database"""
        cve_id = cve_data.get('id')
        if not cve_id:
            return
        
        # Insert CVE item
        cursor.execute("""
            INSERT OR REPLACE INTO cve_items
            (cve_id, source_identifier, vuln_status, published, last_modified)
            VALUES (?, ?, ?, ?, ?)
        """, (
            cve_id,
            cve_data.get('sourceIdentifier'),
            cve_data.get('vulnStatus'),
            cve_data.get('published'),
            cve_data.get('lastModified')
        ))
        
        cve_item_id = cursor.lastrowid or cursor.execute(
            "SELECT id FROM cve_items WHERE cve_id = ?", (cve_id,)
        ).fetchone()[0]
        
        # Descriptions
        for desc in cve_data.get('descriptions', []):
            cursor.execute("""
                INSERT OR IGNORE INTO cve_descriptions (cve_item_id, lang, value)
                VALUES (?, ?, ?)
            """, (cve_item_id, desc.get('lang', 'en'), desc.get('value', '')))
        
        # Metrics
        for version, metrics_list in cve_data.get('metrics', {}).items():
            if isinstance(metrics_list, list):
                for metric in metrics_list:
                    cvss_data = metric.get('cvssData', {})
                    cursor.execute("""
                        INSERT OR IGNORE INTO cve_metrics
                        (cve_item_id, source, type, cvss_version, vector_string, 
                         base_score, base_severity, exploitability_score, impact_score)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_item_id,
                        metric.get('source'),
                        metric.get('type'),
                        version,
                        cvss_data.get('vectorString'),
                        cvss_data.get('baseScore'),
                        cvss_data.get('baseSeverity'),
                        metric.get('exploitabilityScore'),
                        metric.get('impactScore')
                    ))
        
        # Configurations
        for config in cve_data.get('configurations', []):
            for node in config.get('nodes', []):
                operator = node.get('operator', 'OR')
                negate = 1 if node.get('negate', False) else 0
                
                for cpe_match in node.get('cpeMatch', []):
                    cursor.execute("""
                        INSERT OR IGNORE INTO cve_configurations
                        (cve_item_id, operator, negate, criteria, match_criteria_id, vulnerable,
                         version_start_including, version_start_excluding,
                         version_end_including, version_end_excluding)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_item_id,
                        operator,
                        negate,
                        cpe_match.get('criteria'),
                        cpe_match.get('matchCriteriaId'),
                        1 if cpe_match.get('vulnerable', True) else 0,
                        cpe_match.get('versionStartIncluding'),
                        cpe_match.get('versionStartExcluding'),
                        cpe_match.get('versionEndIncluding'),
                        cpe_match.get('versionEndExcluding')
                    ))
    
    
    def get_stats(self):
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM cpe_items")
        cpe_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cve_items")
        cve_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT value FROM metadata WHERE key = 'cpe_last_updated'")
        cpe_updated = cursor.fetchone()
        cpe_updated = cpe_updated[0] if cpe_updated else 'Never'
        
        conn.close()
        
        return {
            'cpe_count': cpe_count,
            'cve_count': cve_count,
            'cpe_last_updated': cpe_updated
        }


if __name__ == '__main__':
    import sys
    
    db = VulnDatabase('vuln.db')
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python vuln_database.py init           - Initialize database")
        print("  python vuln_database.py update-cpe     - Download CPE dictionary")
        print("  python vuln_database.py update-cve     - Download recent 10k CVEs (~30 seconds)")
        print("  python vuln_database.py update-cve --all  - Download ALL CVEs (~15-20 minutes)")
        print("  python vuln_database.py update-cve --limit 20000  - Download 20k CVEs")
        print("  python vuln_database.py stats          - Show database statistics")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'init':
        db.initialize_database()
    elif command == 'update-cpe':
        db.download_cpe_dictionary()
    elif command == 'update-cve':
        if len(sys.argv) > 2:
            if sys.argv[2] == '--all':
                db.download_cve_data(limit='all')
            elif sys.argv[2] == '--limit' and len(sys.argv) > 3:
                db.download_cve_data(limit=int(sys.argv[3]))
            else:
                print(f"Unknown option: {sys.argv[2]}")
                sys.exit(1)
        else:
            db.download_cve_data(limit=10000)  # Default: 10k recent CVEs
    elif command == 'stats':
        stats = db.get_stats()
        print(f"\n📊 Database Statistics:")
        print(f"  CPE Items: {stats['cpe_count']:,}")
        print(f"  CVE Items: {stats['cve_count']:,}")
        print(f"  Last CPE Update: {stats['cpe_last_updated']}")
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

