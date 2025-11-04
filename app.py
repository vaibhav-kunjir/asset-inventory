"""Service Listing Application with CVE/CPE Vulnerability Information"""
from flask import Flask, render_template, jsonify, request
import psycopg2
from psycopg2.extras import RealDictCursor
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

app = Flask(__name__)

# PostgreSQL Database connection settings (for service data)
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'db'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'novaapi'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}

# Local Vulnerability Database path (CVE/CPE data from NIST)
VULN_DB_PATH = os.getenv('VULN_DB_PATH', '/app/vuln.db')

# Cache for vulnerability lookups (product:version -> vuln_info)
VULN_CACHE = {}

# Common product name mappings to CPE naming (extracted for reuse)
PRODUCT_MAPPINGS = {
    'httpd': 'http_server',  # Apache httpd
    'apache': 'http_server',
    'apache2': 'http_server',
    'openssh': 'openssh',
    'ssh': 'openssh',
    'mysql': 'mysql',
    'mariadb': 'mariadb',
    'postgres': 'postgresql',
    'postgresql': 'postgresql',
    'redis': 'redis',
    'nginx': 'nginx',
    'tomcat': 'tomcat',
    'node.js': 'node.js',
    'nodejs': 'node.js',
    'php': 'php',
    'mongodb': 'mongodb',
    'mongo': 'mongodb',
    'elasticsearch': 'elasticsearch',
    'jenkins': 'jenkins',
    'docker': 'docker',
    'kubernetes': 'kubernetes',
    'k8s': 'kubernetes',
    'openssl': 'openssl',
}


def get_db_connection():
    """Create PostgreSQL database connection for service data"""
    return psycopg2.connect(**DB_CONFIG)


def get_vuln_db_connection():
    """Create SQLite connection to vulnerability database for CVE/CPE data"""
    conn = sqlite3.connect(VULN_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def build_cpe_pattern(product, version=None):
    """Build CPE pattern for searching CVE database"""
    if not product:
        return None
    
    # Normalize product name (lowercase, handle common variations)
    product = product.lower().strip()
    
    # Map product name if we have a mapping
    mapped_product = PRODUCT_MAPPINGS.get(product, product)
    
    if version and version.strip() and version.lower() not in ['n/a', 'unknown', '-']:
        version = version.strip()
        # Build specific version pattern - search both with exact vendor and wildcard
        return f"cpe:2.3:a:%:{mapped_product}:{version}:%"
    else:
        # Build wildcard pattern for any version
        return f"cpe:2.3:a:%:{mapped_product}:%"


def get_vulnerabilities_for_service(product, version=None):
    """Get CVE information from NIST vulnerability database"""
    if not product or product.lower() in ['n/a', 'unknown', '-', '']:
        return {
            'cve_count': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'cves': [],
            'cpe_matches': [],
            'eol_date': None,
            'in_wild_count': 0
        }
    
    # Check cache first
    cache_key = f"{product.lower()}:{version or '*'}"
    if cache_key in VULN_CACHE:
        return VULN_CACHE[cache_key]
    
    try:
        conn = get_vuln_db_connection()
        cursor = conn.cursor()
        
        # Build CPE search pattern
        mapped_product = PRODUCT_MAPPINGS.get(product.lower(), product)
        
        # Search for CPE items - use broader LIKE patterns
        if version and version.strip() and version.lower() not in ['n/a', 'unknown', '-']:
            # Specific version search - match vendor:product:version pattern
            version_pattern = f"%:{mapped_product}:{version}:%"
            cursor.execute("""
                SELECT id, name, cpe23_name, title, deprecated, deprecation_date, deprecated_by
                FROM cpe_items
                WHERE (cpe23_name LIKE ? OR name LIKE ?)
                LIMIT 20
            """, (version_pattern, version_pattern))
        else:
            # Wildcard version search - match vendor:product with any version
            product_pattern = f"%:{mapped_product}:%"
            cursor.execute("""
                SELECT id, name, cpe23_name, title, deprecated, deprecation_date, deprecated_by
                FROM cpe_items
                WHERE (cpe23_name LIKE ? OR name LIKE ?)
                LIMIT 20
            """, (product_pattern, product_pattern))
        
        cpe_matches = [dict(row) for row in cursor.fetchall()]
        
        if not cpe_matches:
            cursor.close()
            conn.close()
            return {
                'cve_count': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'cves': [],
                'cpe_matches': [],
                'eol_date': None,
                'in_wild_count': 0
            }
        
        # Build search patterns for CVE configurations
        # We need to search for both exact CPE matches AND wildcard versions
        # e.g., openssh:7.4 should match openssh:7.4:* AND openssh:*
        search_patterns = []
        
        for cpe in cpe_matches:
            cpe_name = cpe.get('cpe23_name') or cpe.get('name')
            if cpe_name:
                # Add exact CPE
                search_patterns.append(cpe_name)
                
                # Also search for wildcard version patterns
                # e.g., cpe:2.3:a:openbsd:openssh:7.4:* should also match cpe:2.3:a:openbsd:openssh:*
                if ':' in cpe_name:
                    parts = cpe_name.split(':')
                    if len(parts) >= 6:
                        # Create wildcard version pattern: vendor:product:*
                        wildcard_pattern = ':'.join(parts[:5]) + ':*:*:*:*:*:*:*:*'
                        search_patterns.append(wildcard_pattern)
        
        if not search_patterns:
            cursor.close()
            conn.close()
            return {
                'cve_count': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'cves': [],
                'cpe_matches': cpe_matches,
                'eol_date': None,
                'in_wild_count': 0
            }
        
        # Search for CVEs - use LIKE patterns to match wildcards in criteria
        # Build OR conditions for LIKE matching
        like_conditions = ' OR '.join(['cc.criteria LIKE ?' for _ in search_patterns])
        like_patterns = [f'%{pattern}%' if '*' in pattern else pattern for pattern in search_patterns]
        
        query = f"""
            SELECT DISTINCT
                ci.cve_id,
                cd.value as description,
                cbm.base_score,
                cbm.base_severity,
                cbm.cvss_version,
                cbm.vector_string,
                ci.published,
                ci.last_modified,
                cc.criteria,
                cc.version_start_including,
                cc.version_start_excluding,
                cc.version_end_including,
                cc.version_end_excluding
            FROM cve_items ci
            JOIN cve_configurations cc ON ci.id = cc.cve_item_id
            LEFT JOIN cve_descriptions cd ON ci.id = cd.cve_item_id AND cd.lang = 'en'
            LEFT JOIN cve_best_metrics cbm ON ci.id = cbm.cve_item_id
            WHERE cc.vulnerable = 1
              AND ({like_conditions})
            ORDER BY cbm.base_score DESC NULLS LAST, ci.published DESC
            LIMIT 100
        """
        
        cursor.execute(query, like_patterns)
        
        # Deduplicate CVEs by cve_id (a CVE can have multiple configurations)
        cves_raw = cursor.fetchall()
        seen_cves = {}
        for row in cves_raw:
            cve_dict = dict(row)
            cve_id = cve_dict.get('cve_id')
            if cve_id and cve_id not in seen_cves:
                seen_cves[cve_id] = cve_dict
        
        cves = list(seen_cves.values())
        
        # Calculate severity counts based on CVSS scores
        critical_count = sum(1 for cve in cves if cve.get('base_score') and cve['base_score'] >= 9.0)
        high_count = sum(1 for cve in cves if cve.get('base_score') and 7.0 <= cve['base_score'] < 9.0)
        medium_count = sum(1 for cve in cves if cve.get('base_score') and 4.0 <= cve['base_score'] < 7.0)
        low_count = sum(1 for cve in cves if cve.get('base_score') and cve['base_score'] < 4.0)
        
        # Note: 'in_wild' data not available in current database
        in_wild_count = 0
        
        cursor.close()
        conn.close()
        
        result = {
            'cve_count': len(cves),
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'cves': cves[:50],  # Limit to top 50 for display
            'cpe_matches': [{'cpe23': c.get('cpe23_name') or c.get('name'), 
                           'vendor': 'N/A', 
                           'product': mapped_product,
                           'cpe_source': 'nist'} for c in cpe_matches],
            'eol_date': None,  # EOL data not tracked in current database
            'in_wild_count': in_wild_count
        }
        
        # Cache the result for future requests
        VULN_CACHE[cache_key] = result
        
        return result
    
    except Exception as e:
        print(f"[ERROR] Exception in get_vulnerabilities_for_service: {e}")
        import traceback
        traceback.print_exc()
        return {
            'cve_count': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'cves': [],
            'cpe_matches': [],
            'eol_date': None,
            'in_wild_count': 0,
            'error': str(e)
        }


@app.route('/')
def index():
    """Home page showing hosts grouped with their services"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get filter and search parameters
        severity_filter = request.args.get('severity', 'all')
        eol_only = request.args.get('eol_only', 'false') == 'true'
        in_wild_only = request.args.get('in_wild_only', 'false') == 'true'
        risk_level_filter = request.args.get('risk_level', 'all')
        min_cve_count = request.args.get('min_cve', '0')
        search_query = request.args.get('search', '').strip()
        selected_client_id = request.args.get('client_id', 'all')
        
        # Convert min_cve to int
        try:
            min_cve_count = int(min_cve_count)
        except:
            min_cve_count = 0
        
        # Get list of clients for dropdown with service and host counts
        cursor.execute("""
            SELECT 
                c.id, 
                c.name, 
                COUNT(DISTINCT p.id) as service_count,
                COUNT(DISTINCT ip.address) as host_count
            FROM client c
            LEFT JOIN port p ON c.id = p.client_id 
                AND p.is_deleted = FALSE 
                AND p.protocol IS NOT NULL
            LEFT JOIN ip_address ip ON p.ip_address_id = ip.id
            WHERE c.is_deleted = FALSE
            GROUP BY c.id, c.name
            HAVING COUNT(DISTINCT p.id) > 0
            ORDER BY c.name
            LIMIT 100
        """)
        clients = cursor.fetchall()
        
        # Build query with optional client filter
        query = """
            SELECT 
                p.id,
                p.port_number,
                p.protocol,
                p.name,
                p.product,
                p.product_version,
                p.service_type,
                p.banner,
                p.is_monitored,
                p.is_live,
                p.created_at,
                p.client_id,
                ip.address as ip_address,
                d.name as domain_name,
                c.name as client_name
            FROM port p
            LEFT JOIN ip_address ip ON p.ip_address_id = ip.id
            LEFT JOIN domain d ON p.domain_id = d.id
            LEFT JOIN client c ON p.client_id = c.id
            WHERE p.is_deleted = FALSE
              AND p.protocol IS NOT NULL
        """
        
        params = []
        if selected_client_id and selected_client_id != 'all':
            query += " AND p.client_id = %s"
            params.append(int(selected_client_id))
        
        query += " ORDER BY ip.address, p.port_number LIMIT 200"
        
        cursor.execute(query, params if params else None)
        services = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        # Group services by host (IP address or domain)
        hosts = {}
        total_vulnerabilities = 0
        total_critical = 0
        total_high = 0
        total_eol = 0
        total_in_wild = 0
        
        for service in services:
            # Enrich service with vulnerability information
            vuln_info = get_vulnerabilities_for_service(
                service.get('product'),
                service.get('product_version')
            )
            
            enriched_service = dict(service)
            enriched_service['vuln_info'] = vuln_info
            
            # Apply filters at service level
            should_include = True
            
            if severity_filter == 'critical' and vuln_info['critical_count'] == 0:
                should_include = False
            elif severity_filter == 'high' and (vuln_info['critical_count'] + vuln_info['high_count']) == 0:
                should_include = False
            
            if eol_only and not vuln_info.get('eol_date'):
                should_include = False
            
            if in_wild_only and vuln_info['in_wild_count'] == 0:
                should_include = False
            
            if not should_include:
                continue
            
            # Group by host
            host_key = service.get('ip_address') or service.get('domain_name') or 'Unknown'
            
            if host_key not in hosts:
                hosts[host_key] = {
                    'ip_address': service.get('ip_address'),
                    'domain_name': service.get('domain_name'),
                    'services': [],
                    'total_services': 0,
                    'total_cves': 0,
                    'critical_count': 0,
                    'high_count': 0,
                    'medium_count': 0,
                    'low_count': 0,
                    'in_wild_count': 0,
                    'has_eol': False,
                    'risk_score': 0,
                    'risk_level': 'LOW'
                }
            
            # Add service to host
            hosts[host_key]['services'].append(enriched_service)
            hosts[host_key]['total_services'] += 1
            hosts[host_key]['total_cves'] += vuln_info['cve_count']
            hosts[host_key]['critical_count'] += vuln_info['critical_count']
            hosts[host_key]['high_count'] += vuln_info['high_count']
            hosts[host_key]['medium_count'] += vuln_info['medium_count']
            hosts[host_key]['low_count'] += vuln_info['low_count']
            hosts[host_key]['in_wild_count'] += vuln_info['in_wild_count']
            if vuln_info.get('eol_date'):
                hosts[host_key]['has_eol'] = True
            
            # Update totals
            total_vulnerabilities += vuln_info['cve_count']
            total_critical += vuln_info['critical_count']
            total_high += vuln_info['high_count']
            if vuln_info.get('eol_date'):
                total_eol += 1
            total_in_wild += vuln_info['in_wild_count']
        
        # Calculate risk score and level for each host
        for host in hosts.values():
            # Risk Score Calculation:
            # Critical CVEs: 10 points each
            # High CVEs: 5 points each
            # Medium CVEs: 2 points each
            # Low CVEs: 1 point each
            # In-the-wild: +20 bonus
            # EOL product: +10 bonus
            risk_score = (
                host['critical_count'] * 10 +
                host['high_count'] * 5 +
                host['medium_count'] * 2 +
                host['low_count'] * 1 +
                (20 if host['in_wild_count'] > 0 else 0) +
                (10 if host['has_eol'] else 0)
            )
            
            host['risk_score'] = risk_score
            
            # Determine risk level
            if host['critical_count'] > 0 or risk_score >= 50:
                host['risk_level'] = 'CRITICAL'
            elif host['high_count'] > 0 or risk_score >= 20:
                host['risk_level'] = 'HIGH'
            elif host['medium_count'] > 0 or risk_score >= 5:
                host['risk_level'] = 'MEDIUM'
            elif host['total_cves'] > 0:
                host['risk_level'] = 'LOW'
            else:
                host['risk_level'] = 'NONE'
        
        # Apply additional filters based on risk level and CVE count
        filtered_hosts = {}
        for host_key, host in hosts.items():
            should_include_host = True
            
            # Apply search filter
            if search_query:
                search_lower = search_query.lower()
                # Search in IP, domain, or any service product
                search_match = (
                    (host['ip_address'] and search_lower in host['ip_address'].lower()) or
                    (host['domain_name'] and search_lower in host['domain_name'].lower()) or
                    any(search_lower in (s.get('product') or '').lower() or 
                        search_lower in (s.get('name') or '').lower() or
                        str(s.get('port_number', '')) == search_query
                        for s in host['services'])
                )
                if not search_match:
                    should_include_host = False
            
            # Apply risk level filter
            if risk_level_filter != 'all' and host['risk_level'] != risk_level_filter.upper():
                should_include_host = False
            
            # Apply minimum CVE count filter
            if host['total_cves'] < min_cve_count:
                should_include_host = False
            
            if should_include_host:
                filtered_hosts[host_key] = host
        
        # Convert to list and sort by risk score (highest risk first)
        hosts_list = list(filtered_hosts.values())
        hosts_list.sort(key=lambda h: (
            -h['risk_score'],       # Highest risk score first
            -h['critical_count'],   # Then most critical
            -h['high_count'],       # Then most high
            h['ip_address'] or ''   # Then by IP
        ))
        
        # Calculate total services across all hosts
        total_services = sum(h['total_services'] for h in hosts_list)
        
        summary_stats = {
            'total_hosts': len(hosts_list),
            'total_services': total_services,
            'total_vulnerabilities': total_vulnerabilities,
            'total_critical': total_critical,
            'total_high': total_high,
            'total_eol': total_eol,
            'total_in_wild': total_in_wild
        }
        
        return render_template('index.html', 
                             hosts=hosts_list,
                             host_count=len(hosts_list),
                             stats=summary_stats,
                             severity_filter=severity_filter,
                             eol_only=eol_only,
                             in_wild_only=in_wild_only,
                             risk_level_filter=risk_level_filter,
                             min_cve_count=min_cve_count,
                             search_query=search_query,
                             clients=clients,
                             selected_client_id=selected_client_id)
    
    except Exception as e:
        return render_template('error.html', error=str(e)), 500


@app.route('/service/<int:service_id>')
def service_detail(service_id):
    """Detailed view of a specific service with all CVE information"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get service details
        cursor.execute("""
            SELECT 
                p.id,
                p.port_number,
                p.protocol,
                p.name,
                p.product,
                p.product_version,
                p.service_type,
                p.banner,
                p.is_monitored,
                p.is_live,
                p.created_at,
                ip.address as ip_address,
                d.name as domain_name
            FROM port p
            LEFT JOIN ip_address ip ON p.ip_address_id = ip.id
            LEFT JOIN domain d ON p.domain_id = d.id
            WHERE p.id = %s AND p.is_deleted = FALSE
        """, (service_id,))
        
        service = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not service:
            return render_template('error.html', error='Service not found'), 404
        
        # Get comprehensive vulnerability information
        vuln_info = get_vulnerabilities_for_service(
            service.get('product'),
            service.get('product_version')
        )
        
        return render_template('service_detail.html', 
                             service=service, 
                             vuln_info=vuln_info)
    
    except Exception as e:
        return render_template('error.html', error=str(e)), 500


@app.route('/api/services')
def api_services():
    """API endpoint to get all services with vulnerability summary as JSON"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        query = """
            SELECT 
                p.id,
                p.port_number,
                p.protocol,
                p.name,
                p.product,
                p.product_version,
                p.service_type,
                p.banner,
                p.is_monitored,
                p.is_live,
                p.created_at,
                ip.address as ip_address,
                d.name as domain_name
            FROM port p
            LEFT JOIN ip_address ip ON p.ip_address_id = ip.id
            LEFT JOIN domain d ON p.domain_id = d.id
            WHERE p.is_deleted = FALSE
              AND p.protocol IS NOT NULL
            ORDER BY p.created_at DESC
            LIMIT 100
        """
        
        cursor.execute(query)
        services = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        # Add vulnerability summary to each service
        enriched_services = []
        for service in services:
            vuln_info = get_vulnerabilities_for_service(
                service.get('product'),
                service.get('product_version')
            )
            enriched_service = dict(service)
            enriched_service['vulnerability_summary'] = {
                'cve_count': vuln_info['cve_count'],
                'critical_count': vuln_info['critical_count'],
                'high_count': vuln_info['high_count'],
                'medium_count': vuln_info['medium_count'],
                'low_count': vuln_info['low_count'],
                'eol_date': vuln_info.get('eol_date'),
                'in_wild_count': vuln_info['in_wild_count']
            }
            enriched_services.append(enriched_service)
        
        return jsonify({
            'services': enriched_services,
            'count': len(enriched_services)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/service/<int:service_id>/vulnerabilities')
def api_service_vulnerabilities(service_id):
    """API endpoint to get detailed vulnerability information for a service"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT product, product_version
            FROM port
            WHERE id = %s AND is_deleted = FALSE
        """, (service_id,))
        
        service = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not service:
            return jsonify({'error': 'Service not found'}), 404
        
        vuln_info = get_vulnerabilities_for_service(
            service.get('product'),
            service.get('product_version')
        )
        
        return jsonify(vuln_info)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/export/csv')
def export_csv():
    """Export current view as CSV"""
    import csv
    from io import StringIO
    from flask import Response
    
    # Get same filters as main page
    severity_filter = request.args.get('severity', 'all')
    eol_only = request.args.get('eol_only', 'false') == 'true'
    risk_level_filter = request.args.get('risk_level', 'all')
    search_query = request.args.get('search', '').strip()
    
    try:
        # Fetch data (reuse same logic as index route but simplified)
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT 
                p.id, p.port_number, p.protocol, p.name, p.product, p.product_version,
                p.service_type, ip.address as ip_address, d.name as domain_name
            FROM port p
            LEFT JOIN ip_address ip ON p.ip_address_id = ip.id
            LEFT JOIN domain d ON p.domain_id = d.id
            WHERE p.is_deleted = FALSE
              AND p.protocol IS NOT NULL
            ORDER BY ip.address, p.port_number
            LIMIT 500
        """)
        
        services = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Create CSV
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'IP Address', 'Domain', 'Port', 'Protocol', 'Service', 
            'Product', 'Version', 'Total CVEs', 'Critical', 'High', 
            'Medium', 'Low', 'Risk Score', 'Risk Level'
        ])
        
        # Data rows
        for service in services:
            vuln_info = get_vulnerabilities_for_service(
                service.get('product'),
                service.get('product_version')
            )
            
            # Calculate risk score for service
            risk_score = (
                vuln_info['critical_count'] * 10 +
                vuln_info['high_count'] * 5 +
                vuln_info['medium_count'] * 2 +
                vuln_info['low_count'] * 1
            )
            
            if vuln_info['critical_count'] > 0:
                risk_level = 'CRITICAL'
            elif vuln_info['high_count'] > 0:
                risk_level = 'HIGH'
            elif vuln_info['medium_count'] > 0:
                risk_level = 'MEDIUM'
            elif vuln_info['cve_count'] > 0:
                risk_level = 'LOW'
            else:
                risk_level = 'NONE'
            
            writer.writerow([
                service.get('ip_address') or 'N/A',
                service.get('domain_name') or 'N/A',
                service.get('port_number') or 'N/A',
                service.get('protocol') or 'N/A',
                service.get('name') or 'N/A',
                service.get('product') or 'N/A',
                service.get('product_version') or 'N/A',
                vuln_info['cve_count'],
                vuln_info['critical_count'],
                vuln_info['high_count'],
                vuln_info['medium_count'],
                vuln_info['low_count'],
                risk_score,
                risk_level
            ])
        
        # Return CSV file
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=vulnerability_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/export/json')
def export_json():
    """Export current view as JSON"""
    # Reuse the API services endpoint logic
    try:
        result = api_services()
        if isinstance(result, tuple):
            return result
        
        # Add timestamp and export metadata
        data = result.get_json() if hasattr(result, 'get_json') else result
        export_data = {
            'exported_at': datetime.now().isoformat(),
            'total_services': data.get('count', 0),
            'services': data.get('services', [])
        }
        
        from flask import Response
        return Response(
            json.dumps(export_data, indent=2, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=vulnerability_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'}
        )
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/cache/clear')
def clear_cache():
    """Clear the vulnerability cache"""
    global VULN_CACHE
    cache_size = len(VULN_CACHE)
    VULN_CACHE = {}
    return jsonify({
        'status': 'success',
        'message': f'Cache cleared - {cache_size} entries removed',
        'cache_size': 0
    })


@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        conn = get_db_connection()
        conn.close()
        
        # Also check vuln database
        vuln_conn = get_vuln_db_connection()
        vuln_cursor = vuln_conn.cursor()
        vuln_cursor.execute("SELECT COUNT(*) FROM cve_items")
        cve_count = vuln_cursor.fetchone()[0]
        vuln_cursor.execute("SELECT COUNT(*) FROM cpe_items")
        cpe_count = vuln_cursor.fetchone()[0]
        vuln_conn.close()
        
        return jsonify({
            'status': 'healthy', 
            'database': 'connected',
            'vulnerability_db': 'connected',
            'cve_count': cve_count,
            'cpe_count': cpe_count,
            'cache_entries': len(VULN_CACHE)
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'database': 'disconnected', 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

