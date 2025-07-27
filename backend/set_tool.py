import subprocess
import json
import os
import tempfile
import threading
import time
import re
import shutil
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import uuid
import requests
from pathlib import Path

class SETTool:
    def __init__(self):
        self.sessions = {}
        self.active_attacks = {}
        self.set_path = self._find_set()
        self.logger = logging.getLogger(__name__)
        self.set_config = {
            'web_attack': {
                'enabled': True,
                'port': 80,
                'ssl': False
            },
            'payload_generation': {
                'enabled': True,
                'output_dir': '/tmp/set_payloads'
            },
            'credential_harvester': {
                'enabled': True,
                'port': 80
            },
            'spear_phishing': {
                'enabled': True,
                'smtp_server': 'localhost',
                'smtp_port': 25
            }
        }
        
    def _find_set(self) -> str:
        """Find the SET executable"""
        possible_paths = [
            '/usr/share/setoolkit/setoolkit',
            '/opt/set/setoolkit',
            '/usr/local/bin/setoolkit',
            'setoolkit',
            'se-toolkit'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '--version'], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        return 'setoolkit'  # Default fallback
    
    def check_installation(self) -> Dict[str, Any]:
        """Check if SET is installed and accessible"""
        try:
            result = subprocess.run([self.set_path, '--version'], 
                                 capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                version_match = re.search(r'SEToolkit (\d+\.\d+\.\d+)', result.stdout)
                version = version_match.group(1) if version_match else 'Unknown'
                
                return {
                    'installed': True,
                    'version': version,
                    'path': self.set_path,
                    'message': 'Social Engineer Toolkit is ready to use'
                }
            else:
                return {
                    'installed': False,
                    'error': 'SET not found or not accessible',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
        except Exception as e:
            return {
                'installed': False,
                'error': f'Error checking SET installation: {str(e)}'
            }
    
    def get_available_attacks(self) -> List[Dict[str, str]]:
        """Get available social engineering attacks"""
        return [
            {
                'id': 'spear_phishing',
                'name': 'Spear-Phishing Attack Vector',
                'description': 'Send targeted phishing emails with malicious payloads',
                'category': 'Email Attacks'
            },
            {
                'id': 'web_attack',
                'name': 'Web Attack Vector',
                'description': 'Create malicious websites for credential harvesting',
                'category': 'Web Attacks'
            },
            {
                'id': 'infectious_media',
                'name': 'Infectious Media Generator',
                'description': 'Create malicious USB drives and media',
                'category': 'Physical Attacks'
            },
            {
                'id': 'harvester',
                'name': 'Harvester Attack',
                'description': 'Harvest credentials from web forms',
                'category': 'Web Attacks'
            },
            {
                'id': 'mass_mailer',
                'name': 'Mass Mailer Attack',
                'description': 'Send mass phishing emails',
                'category': 'Email Attacks'
            },
            {
                'id': 'arduino',
                'name': 'Arduino-Based Attack Vector',
                'description': 'Create malicious Arduino payloads',
                'category': 'Hardware Attacks'
            },
            {
                'id': 'wireless',
                'name': 'Wireless Access Point Attack',
                'description': 'Create rogue access points',
                'category': 'Network Attacks'
            },
            {
                'id': 'qr_code',
                'name': 'QR Code Generator Attack',
                'description': 'Create malicious QR codes',
                'category': 'Physical Attacks'
            },
            {
                'id': 'powershell',
                'name': 'PowerShell Attack Vector',
                'description': 'Create PowerShell-based payloads',
                'category': 'Payload Generation'
            },
            {
                'id': 'macro',
                'name': 'Macro Attack Vector',
                'description': 'Create malicious Office macros',
                'category': 'Document Attacks'
            }
        ]
    
    def start_spear_phishing_attack(self, session_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Start a spear-phishing attack"""
        try:
            attack_session = {
                'session_id': session_id,
                'attack_type': 'spear_phishing',
                'config': config,
                'status': 'running',
                'start_time': datetime.now().isoformat(),
                'results': [],
                'emails_sent': 0,
                'emails_opened': 0,
                'payloads_delivered': 0
            }
            
            self.active_attacks[session_id] = attack_session
            
            # Start attack in background thread
            threading.Thread(target=self._run_spear_phishing, args=(session_id,), daemon=True).start()
            
            return {
                'session_id': session_id,
                'status': 'started',
                'attack_type': 'spear_phishing',
                'message': 'Spear-phishing attack initiated'
            }
            
        except Exception as e:
            self.logger.error(f"Error starting spear-phishing attack: {e}")
            return {'error': f'Failed to start attack: {str(e)}'}
    
    def _run_spear_phishing(self, session_id: str):
        """Run the spear-phishing attack"""
        if session_id not in self.active_attacks:
            return
        
        session = self.active_attacks[session_id]
        config = session['config']
        
        try:
            # Create email template
            email_template = self._create_email_template(config)
            
            # Generate payload
            payload = self._generate_payload(config.get('payload_type', 'windows'))
            
            # Send emails
            targets = config.get('targets', [])
            for target in targets:
                self._send_phishing_email(target, email_template, payload, session_id)
                session['emails_sent'] += 1
                time.sleep(1)  # Rate limiting
            
            session['status'] = 'completed'
            session['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            self.logger.error(f"Error in spear-phishing attack {session_id}: {e}")
            session['status'] = 'failed'
            session['error'] = str(e)
            session['end_time'] = datetime.now().isoformat()
    
    def start_web_attack(self, session_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Start a web attack (credential harvester)"""
        try:
            attack_session = {
                'session_id': session_id,
                'attack_type': 'web_attack',
                'config': config,
                'status': 'running',
                'start_time': datetime.now().isoformat(),
                'results': [],
                'credentials_harvested': 0,
                'visitors': 0
            }
            
            self.active_attacks[session_id] = attack_session
            
            # Start attack in background thread
            threading.Thread(target=self._run_web_attack, args=(session_id,), daemon=True).start()
            
            return {
                'session_id': session_id,
                'status': 'started',
                'attack_type': 'web_attack',
                'message': 'Web attack initiated'
            }
            
        except Exception as e:
            self.logger.error(f"Error starting web attack: {e}")
            return {'error': f'Failed to start attack: {str(e)}'}
    
    def _run_web_attack(self, session_id: str):
        """Run the web attack"""
        if session_id not in self.active_attacks:
            return
        
        session = self.active_attacks[session_id]
        config = session['config']
        
        try:
            # Create malicious website
            website_path = self._create_malicious_website(config)
            
            # Start web server
            port = config.get('port', 80)
            self._start_web_server(website_path, port, session_id)
            
            # Monitor for credentials
            self._monitor_credentials(session_id)
            
        except Exception as e:
            self.logger.error(f"Error in web attack {session_id}: {e}")
            session['status'] = 'failed'
            session['error'] = str(e)
            session['end_time'] = datetime.now().isoformat()
    
    def start_payload_generation(self, session_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate malicious payloads"""
        try:
            attack_session = {
                'session_id': session_id,
                'attack_type': 'payload_generation',
                'config': config,
                'status': 'running',
                'start_time': datetime.now().isoformat(),
                'results': [],
                'payloads_created': 0
            }
            
            self.active_attacks[session_id] = attack_session
            
            # Start payload generation in background thread
            threading.Thread(target=self._run_payload_generation, args=(session_id,), daemon=True).start()
            
            return {
                'session_id': session_id,
                'status': 'started',
                'attack_type': 'payload_generation',
                'message': 'Payload generation initiated'
            }
            
        except Exception as e:
            self.logger.error(f"Error starting payload generation: {e}")
            return {'error': f'Failed to start payload generation: {str(e)}'}
    
    def _run_payload_generation(self, session_id: str):
        """Run payload generation"""
        if session_id not in self.active_attacks:
            return
        
        session = self.active_attacks[session_id]
        config = session['config']
        
        try:
            payload_type = config.get('payload_type', 'windows')
            output_dir = config.get('output_dir', '/tmp/set_payloads')
            
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate payloads based on type
            if payload_type == 'windows':
                payloads = self._generate_windows_payloads(config, output_dir)
            elif payload_type == 'linux':
                payloads = self._generate_linux_payloads(config, output_dir)
            elif payload_type == 'mac':
                payloads = self._generate_mac_payloads(config, output_dir)
            elif payload_type == 'android':
                payloads = self._generate_android_payloads(config, output_dir)
            else:
                payloads = self._generate_generic_payloads(config, output_dir)
            
            session['results'] = payloads
            session['payloads_created'] = len(payloads)
            session['status'] = 'completed'
            session['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            self.logger.error(f"Error in payload generation {session_id}: {e}")
            session['status'] = 'failed'
            session['error'] = str(e)
            session['end_time'] = datetime.now().isoformat()
    
    def _create_email_template(self, config: Dict[str, Any]) -> str:
        """Create phishing email template"""
        template = config.get('email_template', 'default')
        
        if template == 'default':
            return """
            Subject: Important Security Update Required
            
            Dear {recipient_name},
            
            We have detected a critical security vulnerability in your account that requires immediate attention.
            Please click the link below to verify your identity and update your security settings.
            
            {phishing_url}
            
            This is urgent and must be completed within 24 hours to prevent account suspension.
            
            Best regards,
            IT Security Team
            """
        else:
            return config.get('custom_template', '')
    
    def _generate_payload(self, payload_type: str) -> Dict[str, Any]:
        """Generate malicious payload"""
        payloads = {
            'windows': {
                'type': 'exe',
                'description': 'Windows executable payload',
                'filename': 'update.exe',
                'command': f'{self.set_path} --payload windows/meterpreter/reverse_tcp'
            },
            'linux': {
                'type': 'elf',
                'description': 'Linux binary payload',
                'filename': 'update',
                'command': f'{self.set_path} --payload linux/x86/meterpreter/reverse_tcp'
            },
            'mac': {
                'type': 'macho',
                'description': 'macOS application payload',
                'filename': 'update.app',
                'command': f'{self.set_path} --payload osx/x86/shell_reverse_tcp'
            },
            'android': {
                'type': 'apk',
                'description': 'Android application payload',
                'filename': 'update.apk',
                'command': f'{self.set_path} --payload android/meterpreter/reverse_tcp'
            }
        }
        
        return payloads.get(payload_type, payloads['windows'])
    
    def _create_malicious_website(self, config: Dict[str, Any]) -> str:
        """Create malicious website for credential harvesting"""
        website_path = f"/tmp/set_website_{uuid.uuid4().hex[:8]}"
        os.makedirs(website_path, exist_ok=True)
        
        # Create index.html
        index_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Required</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .login-form { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ccc; }
                input { width: 100%; padding: 10px; margin: 10px 0; }
                button { width: 100%; padding: 10px; background: #007cba; color: white; border: none; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <h2>Security Verification Required</h2>
                <form action="/harvest" method="post">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Verify</button>
                </form>
            </div>
        </body>
        </html>
        """
        
        with open(f"{website_path}/index.html", "w") as f:
            f.write(index_html)
        
        return website_path
    
    def _start_web_server(self, website_path: str, port: int, session_id: str):
        """Start web server for credential harvesting"""
        # This would typically use a Python HTTP server or similar
        # For now, we'll simulate the server
        self.logger.info(f"Starting web server on port {port} for session {session_id}")
    
    def _monitor_credentials(self, session_id: str):
        """Monitor for harvested credentials"""
        if session_id not in self.active_attacks:
            return
        
        session = self.active_attacks[session_id]
        
        # Simulate credential monitoring
        while session['status'] == 'running':
            time.sleep(5)
            # Check for new credentials
            # This would typically read from a log file or database
    
    def _generate_windows_payloads(self, config: Dict[str, Any], output_dir: str) -> List[Dict[str, Any]]:
        """Generate Windows payloads"""
        payloads = []
        
        # Generate different types of Windows payloads
        payload_types = [
            {'name': 'reverse_shell.exe', 'type': 'meterpreter', 'description': 'Reverse shell payload'},
            {'name': 'keylogger.exe', 'type': 'keylogger', 'description': 'Keylogger payload'},
            {'name': 'screenshot.exe', 'type': 'screenshot', 'description': 'Screenshot capture payload'},
            {'name': 'file_stealer.exe', 'type': 'file_stealer', 'description': 'File exfiltration payload'}
        ]
        
        for payload in payload_types:
            payload_path = os.path.join(output_dir, payload['name'])
            # Simulate payload creation
            with open(payload_path, 'w') as f:
                f.write(f"# Generated {payload['name']} at {datetime.now()}")
            
            payloads.append({
                'name': payload['name'],
                'path': payload_path,
                'type': payload['type'],
                'description': payload['description'],
                'size': os.path.getsize(payload_path)
            })
        
        return payloads
    
    def _generate_linux_payloads(self, config: Dict[str, Any], output_dir: str) -> List[Dict[str, Any]]:
        """Generate Linux payloads"""
        payloads = []
        
        payload_types = [
            {'name': 'reverse_shell', 'type': 'meterpreter', 'description': 'Reverse shell payload'},
            {'name': 'backdoor', 'type': 'backdoor', 'description': 'Backdoor payload'},
            {'name': 'rootkit', 'type': 'rootkit', 'description': 'Rootkit payload'}
        ]
        
        for payload in payload_types:
            payload_path = os.path.join(output_dir, payload['name'])
            with open(payload_path, 'w') as f:
                f.write(f"#!/bin/bash\n# Generated {payload['name']} at {datetime.now()}")
            os.chmod(payload_path, 0o755)
            
            payloads.append({
                'name': payload['name'],
                'path': payload_path,
                'type': payload['type'],
                'description': payload['description'],
                'size': os.path.getsize(payload_path)
            })
        
        return payloads
    
    def _generate_mac_payloads(self, config: Dict[str, Any], output_dir: str) -> List[Dict[str, Any]]:
        """Generate macOS payloads"""
        payloads = []
        
        payload_types = [
            {'name': 'reverse_shell.app', 'type': 'meterpreter', 'description': 'Reverse shell payload'},
            {'name': 'keylogger.app', 'type': 'keylogger', 'description': 'Keylogger payload'}
        ]
        
        for payload in payload_types:
            payload_path = os.path.join(output_dir, payload['name'])
            os.makedirs(payload_path, exist_ok=True)
            
            # Create app bundle structure
            contents_path = os.path.join(payload_path, 'Contents')
            os.makedirs(contents_path, exist_ok=True)
            
            with open(os.path.join(contents_path, 'Info.plist'), 'w') as f:
                f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>{payload['name']}</string>
    <key>CFBundleIdentifier</key>
    <string>com.set.{payload['name']}</string>
    <key>CFBundleName</key>
    <string>{payload['name']}</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>""")
            
            payloads.append({
                'name': payload['name'],
                'path': payload_path,
                'type': payload['type'],
                'description': payload['description'],
                'size': 0  # Directory
            })
        
        return payloads
    
    def _generate_android_payloads(self, config: Dict[str, Any], output_dir: str) -> List[Dict[str, Any]]:
        """Generate Android payloads"""
        payloads = []
        
        payload_types = [
            {'name': 'malicious.apk', 'type': 'meterpreter', 'description': 'Android meterpreter payload'},
            {'name': 'spyware.apk', 'type': 'spyware', 'description': 'Android spyware payload'}
        ]
        
        for payload in payload_types:
            payload_path = os.path.join(output_dir, payload['name'])
            with open(payload_path, 'w') as f:
                f.write(f"# Generated {payload['name']} at {datetime.now()}")
            
            payloads.append({
                'name': payload['name'],
                'path': payload_path,
                'type': payload['type'],
                'description': payload['description'],
                'size': os.path.getsize(payload_path)
            })
        
        return payloads
    
    def _generate_generic_payloads(self, config: Dict[str, Any], output_dir: str) -> List[Dict[str, Any]]:
        """Generate generic payloads"""
        return self._generate_windows_payloads(config, output_dir)
    
    def _send_phishing_email(self, target: Dict[str, str], template: str, payload: Dict[str, Any], session_id: str):
        """Send phishing email to target"""
        # Simulate email sending
        self.logger.info(f"Sending phishing email to {target.get('email', 'unknown')} for session {session_id}")
        
        # Update session statistics
        if session_id in self.active_attacks:
            session = self.active_attacks[session_id]
            session['emails_sent'] += 1
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get status of an attack session"""
        if session_id not in self.active_attacks:
            return {'error': 'Session not found'}
        
        session = self.active_attacks[session_id]
        
        return {
            'session_id': session_id,
            'status': session['status'],
            'attack_type': session['attack_type'],
            'start_time': session['start_time'],
            'end_time': session.get('end_time'),
            'results': session.get('results', []),
            'statistics': {
                'emails_sent': session.get('emails_sent', 0),
                'emails_opened': session.get('emails_opened', 0),
                'payloads_delivered': session.get('payloads_delivered', 0),
                'credentials_harvested': session.get('credentials_harvested', 0),
                'visitors': session.get('visitors', 0),
                'payloads_created': session.get('payloads_created', 0)
            },
            'error': session.get('error')
        }
    
    def stop_session(self, session_id: str) -> Dict[str, Any]:
        """Stop an active attack session"""
        if session_id not in self.active_attacks:
            return {'error': 'Session not found'}
        
        session = self.active_attacks[session_id]
        
        try:
            session['status'] = 'stopped'
            session['end_time'] = datetime.now().isoformat()
            
            return {'status': 'stopped', 'session_id': session_id}
            
        except Exception as e:
            self.logger.error(f"Error stopping session {session_id}: {e}")
            return {'error': f'Failed to stop session: {str(e)}'}
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Get all active and completed sessions"""
        sessions = []
        
        for session_id, session in self.active_attacks.items():
            sessions.append({
                'session_id': session_id,
                'status': session['status'],
                'attack_type': session['attack_type'],
                'start_time': session['start_time'],
                'end_time': session.get('end_time'),
                'statistics': {
                    'emails_sent': session.get('emails_sent', 0),
                    'emails_opened': session.get('emails_opened', 0),
                    'payloads_delivered': session.get('payloads_delivered', 0),
                    'credentials_harvested': session.get('credentials_harvested', 0),
                    'visitors': session.get('visitors', 0),
                    'payloads_created': session.get('payloads_created', 0)
                },
                'error': session.get('error')
            })
        
        return sessions
    
    def get_attack_templates(self) -> List[Dict[str, Any]]:
        """Get available attack templates"""
        return [
            {
                'id': 'gmail_phishing',
                'name': 'Gmail Phishing',
                'description': 'Phishing template mimicking Gmail login',
                'category': 'Email Attacks',
                'template': {
                    'subject': 'Gmail Security Alert',
                    'sender': 'noreply@gmail.com',
                    'body': 'Your Gmail account has been compromised...'
                }
            },
            {
                'id': 'linkedin_phishing',
                'name': 'LinkedIn Phishing',
                'description': 'Phishing template mimicking LinkedIn',
                'category': 'Email Attacks',
                'template': {
                    'subject': 'LinkedIn Security Update',
                    'sender': 'security@linkedin.com',
                    'body': 'Your LinkedIn account needs verification...'
                }
            },
            {
                'id': 'bank_phishing',
                'name': 'Bank Phishing',
                'description': 'Phishing template mimicking bank login',
                'category': 'Email Attacks',
                'template': {
                    'subject': 'Bank Account Security Alert',
                    'sender': 'security@bank.com',
                    'body': 'Your bank account has been locked...'
                }
            },
            {
                'id': 'facebook_phishing',
                'name': 'Facebook Phishing',
                'description': 'Phishing template mimicking Facebook',
                'category': 'Email Attacks',
                'template': {
                    'subject': 'Facebook Account Suspended',
                    'sender': 'security@facebook.com',
                    'body': 'Your Facebook account has been suspended...'
                }
            }
        ]
    
    def generate_report(self, session_id: str, report_format: str = 'html') -> Dict[str, Any]:
        """Generate a report for an attack session"""
        if session_id not in self.active_attacks:
            return {'error': 'Session not found'}
        
        session = self.active_attacks[session_id]
        
        try:
            # Generate report content
            report_content = self._create_report_content(session, report_format)
            
            # Save report to file
            report_filename = f"set_report_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{report_format}"
            report_path = f"/tmp/{report_filename}"
            
            with open(report_path, 'w') as f:
                f.write(report_content)
            
            return {
                'session_id': session_id,
                'report_path': report_path,
                'report_filename': report_filename,
                'format': report_format
            }
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return {'error': f'Failed to generate report: {str(e)}'}
    
    def _create_report_content(self, session: Dict[str, Any], format_type: str) -> str:
        """Create report content"""
        if format_type == 'html':
            return f"""
            <html>
            <head>
                <title>SET Attack Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    .header {{ background: #f0f0f0; padding: 20px; }}
                    .section {{ margin: 20px 0; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Social Engineer Toolkit Attack Report</h1>
                    <p>Session ID: {session['session_id']}</p>
                    <p>Attack Type: {session['attack_type']}</p>
                    <p>Start Time: {session['start_time']}</p>
                    <p>End Time: {session.get('end_time', 'N/A')}</p>
                    <p>Status: {session['status']}</p>
                </div>
                
                <div class="section">
                    <h2>Statistics</h2>
                    <table>
                        <tr><th>Metric</th><th>Value</th></tr>
                        <tr><td>Emails Sent</td><td>{session.get('emails_sent', 0)}</td></tr>
                        <tr><td>Emails Opened</td><td>{session.get('emails_opened', 0)}</td></tr>
                        <tr><td>Payloads Delivered</td><td>{session.get('payloads_delivered', 0)}</td></tr>
                        <tr><td>Credentials Harvested</td><td>{session.get('credentials_harvested', 0)}</td></tr>
                        <tr><td>Visitors</td><td>{session.get('visitors', 0)}</td></tr>
                        <tr><td>Payloads Created</td><td>{session.get('payloads_created', 0)}</td></tr>
                    </table>
                </div>
                
                <div class="section">
                    <h2>Results</h2>
                    <pre>{json.dumps(session.get('results', []), indent=2)}</pre>
                </div>
            </body>
            </html>
            """
        else:
            return json.dumps(session, indent=2)

# Global instance
set_tool = SETTool() 