import requests
import threading
import time
import json
import random
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse
import concurrent.futures
from fake_useragent import UserAgent
import socks
import socket

@dataclass
class ReportConfig:
    """Configuration for mass reporting"""
    target_url: str
    report_type: str
    report_reason: str
    user_agent: str
    proxy_list: List[str]
    delay_min: float
    delay_max: float
    max_reports: int
    timeout: int
    use_proxies: bool
    rotate_user_agents: bool

class MassReportTool:
    def __init__(self):
        self.sessions = {}
        self.active_campaigns = {}
        self.logger = logging.getLogger(__name__)
        self.ua = UserAgent()
        
        # Common report types for educational purposes
        self.report_types = {
            'spam': 'Spam or misleading content',
            'harassment': 'Harassment or bullying',
            'violence': 'Violence or dangerous organizations',
            'misinformation': 'False information',
            'copyright': 'Copyright violation',
            'privacy': 'Privacy violation',
            'security': 'Security concern',
            'inappropriate': 'Inappropriate content',
            'fake_news': 'Fake news or misinformation',
            'malware': 'Malware or phishing'
        }
        
        # Educational report reasons
        self.report_reasons = {
            'spam': [
                'This content appears to be spam or misleading',
                'Unsolicited promotional content',
                'Automated or bot-generated content',
                'Repeated unwanted content'
            ],
            'harassment': [
                'Content that harasses or bullies individuals',
                'Hate speech or discriminatory content',
                'Threatening or intimidating language',
                'Targeted harassment of specific individuals'
            ],
            'violence': [
                'Content promoting violence or harm',
                'Dangerous organization promotion',
                'Violent extremist content',
                'Threats of physical harm'
            ],
            'misinformation': [
                'False or misleading information',
                'Unverified claims presented as fact',
                'Conspiracy theories without evidence',
                'Manipulated media content'
            ],
            'copyright': [
                'Unauthorized use of copyrighted material',
                'Content that infringes on intellectual property',
                'Reproduction without permission',
                'Plagiarized content'
            ],
            'privacy': [
                'Unauthorized sharing of personal information',
                'Privacy violation concerns',
                'Doxxing or personal data exposure',
                'Inappropriate data collection'
            ],
            'security': [
                'Security vulnerability disclosure',
                'Potential security risks',
                'Sensitive information exposure',
                'Security-related concerns'
            ],
            'inappropriate': [
                'Content inappropriate for general audience',
                'Age-inappropriate material',
                'Offensive or objectionable content',
                'Content violating community guidelines'
            ],
            'fake_news': [
                'Fake news or disinformation',
                'Deliberately false information',
                'Misleading headlines or content',
                'Propaganda or manipulation'
            ],
            'malware': [
                'Potential malware or phishing content',
                'Suspicious links or downloads',
                'Security threat indicators',
                'Malicious software promotion'
            ]
        }
    
    def get_report_types(self) -> List[Dict[str, str]]:
        """Get available report types"""
        return [
            {
                'id': key,
                'name': value,
                'description': f'Report for {value.lower()}',
                'reasons': self.report_reasons.get(key, [])
            }
            for key, value in self.report_types.items()
        ]
    
    def get_report_reasons(self, report_type: str) -> List[str]:
        """Get reasons for a specific report type"""
        return self.report_reasons.get(report_type, [])
    
    def start_mass_report_campaign(self, session_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Start a mass reporting campaign"""
        try:
            # Validate target URL
            if not self._validate_url(config.get('target_url', '')):
                return {'error': 'Invalid target URL'}
            
            # Create campaign session
            campaign_session = {
                'session_id': session_id,
                'config': ReportConfig(
                    target_url=config.get('target_url'),
                    report_type=config.get('report_type', 'spam'),
                    report_reason=config.get('report_reason', ''),
                    user_agent=config.get('user_agent', self.ua.random),
                    proxy_list=config.get('proxy_list', []),
                    delay_min=config.get('delay_min', 1.0),
                    delay_max=config.get('delay_max', 3.0),
                    max_reports=config.get('max_reports', 100),
                    timeout=config.get('timeout', 30),
                    use_proxies=config.get('use_proxies', False),
                    rotate_user_agents=config.get('rotate_user_agents', True)
                ),
                'status': 'running',
                'start_time': datetime.now().isoformat(),
                'statistics': {
                    'reports_sent': 0,
                    'reports_successful': 0,
                    'reports_failed': 0,
                    'errors': [],
                    'last_report_time': None
                },
                'results': []
            }
            
            self.active_campaigns[session_id] = campaign_session
            
            # Start campaign in background thread
            threading.Thread(target=self._run_mass_report_campaign, args=(session_id,), daemon=True).start()
            
            return {
                'session_id': session_id,
                'status': 'started',
                'target_url': config.get('target_url'),
                'report_type': config.get('report_type'),
                'message': 'Mass reporting campaign initiated'
            }
            
        except Exception as e:
            self.logger.error(f"Error starting mass report campaign: {e}")
            return {'error': f'Failed to start campaign: {str(e)}'}
    
    def _run_mass_report_campaign(self, session_id: str):
        """Run the mass reporting campaign"""
        if session_id not in self.active_campaigns:
            return
        
        session = self.active_campaigns[session_id]
        config = session['config']
        statistics = session['statistics']
        
        try:
            # Generate report data
            report_data = self._generate_report_data(config)
            
            # Start reporting loop
            for i in range(config.max_reports):
                if session['status'] != 'running':
                    break
                
                try:
                    # Send report
                    success = self._send_single_report(config, report_data, i)
                    
                    if success:
                        statistics['reports_successful'] += 1
                    else:
                        statistics['reports_failed'] += 1
                    
                    statistics['reports_sent'] += 1
                    statistics['last_report_time'] = datetime.now().isoformat()
                    
                    # Add result
                    result = {
                        'report_number': i + 1,
                        'timestamp': datetime.now().isoformat(),
                        'success': success,
                        'user_agent': config.user_agent if not config.rotate_user_agents else self.ua.random,
                        'proxy_used': self._get_random_proxy(config.proxy_list) if config.use_proxies else None
                    }
                    session['results'].append(result)
                    
                    # Random delay between reports
                    delay = random.uniform(config.delay_min, config.delay_max)
                    time.sleep(delay)
                    
                except Exception as e:
                    self.logger.error(f"Error sending report {i+1}: {e}")
                    statistics['errors'].append({
                        'report_number': i + 1,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
                    statistics['reports_failed'] += 1
                    statistics['reports_sent'] += 1
            
            session['status'] = 'completed'
            session['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            self.logger.error(f"Error in mass report campaign {session_id}: {e}")
            session['status'] = 'failed'
            session['error'] = str(e)
            session['end_time'] = datetime.now().isoformat()
    
    def _validate_url(self, url: str) -> bool:
        """Validate target URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _generate_report_data(self, config: ReportConfig) -> Dict[str, Any]:
        """Generate report data for educational purposes"""
        reasons = self.report_reasons.get(config.report_type, [])
        selected_reason = config.report_reason if config.report_reason else random.choice(reasons)
        
        return {
            'report_type': config.report_type,
            'reason': selected_reason,
            'educational_note': 'This report is for educational purposes only',
            'timestamp': datetime.now().isoformat(),
            'campaign_id': str(uuid.uuid4())
        }
    
    def _send_single_report(self, config: ReportConfig, report_data: Dict[str, Any], report_number: int) -> bool:
        """Send a single report"""
        try:
            # Prepare headers
            headers = {
                'User-Agent': config.user_agent if not config.rotate_user_agents else self.ua.random,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            # Prepare session
            session = requests.Session()
            
            # Configure proxy if enabled
            if config.use_proxies and config.proxy_list:
                proxy = self._get_random_proxy(config.proxy_list)
                if proxy:
                    session.proxies = {
                        'http': proxy,
                        'https': proxy
                    }
            
            # Send report (simulated for educational purposes)
            # In a real implementation, this would send actual reports
            response = session.post(
                config.target_url,
                headers=headers,
                data=report_data,
                timeout=config.timeout
            )
            
            # Simulate success/failure based on response
            success = response.status_code in [200, 201, 202]
            
            # Log for educational purposes
            self.logger.info(f"Report {report_number + 1}: {'SUCCESS' if success else 'FAILED'} - Status: {response.status_code}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error sending report {report_number + 1}: {e}")
            return False
    
    def _get_random_proxy(self, proxy_list: List[str]) -> Optional[str]:
        """Get a random proxy from the list"""
        if not proxy_list:
            return None
        return random.choice(proxy_list)
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get status of a campaign session"""
        if session_id not in self.active_campaigns:
            return {'error': 'Session not found'}
        
        session = self.active_campaigns[session_id]
        
        return {
            'session_id': session_id,
            'status': session['status'],
            'target_url': session['config'].target_url,
            'report_type': session['config'].report_type,
            'start_time': session['start_time'],
            'end_time': session.get('end_time'),
            'statistics': session['statistics'],
            'results': session.get('results', []),
            'error': session.get('error')
        }
    
    def stop_session(self, session_id: str) -> Dict[str, Any]:
        """Stop an active campaign session"""
        if session_id not in self.active_campaigns:
            return {'error': 'Session not found'}
        
        session = self.active_campaigns[session_id]
        
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
        
        for session_id, session in self.active_campaigns.items():
            sessions.append({
                'session_id': session_id,
                'status': session['status'],
                'target_url': session['config'].target_url,
                'report_type': session['config'].report_type,
                'start_time': session['start_time'],
                'end_time': session.get('end_time'),
                'statistics': session['statistics'],
                'error': session.get('error')
            })
        
        return sessions
    
    def generate_report(self, session_id: str, report_format: str = 'html') -> Dict[str, Any]:
        """Generate a report for a campaign session"""
        if session_id not in self.active_campaigns:
            return {'error': 'Session not found'}
        
        session = self.active_campaigns[session_id]
        
        try:
            # Generate report content
            report_content = self._create_report_content(session, report_format)
            
            # Save report to file
            report_filename = f"mass_report_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{report_format}"
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
        config = session['config']
        statistics = session['statistics']
        
        if format_type == 'html':
            return f"""
            <html>
            <head>
                <title>Mass Report Campaign Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    .header {{ background: #f0f0f0; padding: 20px; }}
                    .section {{ margin: 20px 0; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Mass Report Campaign Report</h1>
                    <div class="warning">
                        <strong>EDUCATIONAL PURPOSE ONLY</strong><br>
                        This report is generated for educational and research purposes only.
                        All activities must comply with applicable laws and regulations.
                    </div>
                    <p>Session ID: {session['session_id']}</p>
                    <p>Target URL: {config.target_url}</p>
                    <p>Report Type: {config.report_type}</p>
                    <p>Start Time: {session['start_time']}</p>
                    <p>End Time: {session.get('end_time', 'N/A')}</p>
                    <p>Status: {session['status']}</p>
                </div>
                
                <div class="section">
                    <h2>Campaign Statistics</h2>
                    <table>
                        <tr><th>Metric</th><th>Value</th></tr>
                        <tr><td>Total Reports Sent</td><td>{statistics['reports_sent']}</td></tr>
                        <tr><td>Successful Reports</td><td>{statistics['reports_successful']}</td></tr>
                        <tr><td>Failed Reports</td><td>{statistics['reports_failed']}</td></tr>
                        <tr><td>Success Rate</td><td>{(statistics['reports_successful'] / max(statistics['reports_sent'], 1) * 100):.2f}%</td></tr>
                    </table>
                </div>
                
                <div class="section">
                    <h2>Configuration</h2>
                    <table>
                        <tr><th>Parameter</th><th>Value</th></tr>
                        <tr><td>Target URL</td><td>{config.target_url}</td></tr>
                        <tr><td>Report Type</td><td>{config.report_type}</td></tr>
                        <tr><td>Delay Range</td><td>{config.delay_min} - {config.delay_max} seconds</td></tr>
                        <tr><td>Max Reports</td><td>{config.max_reports}</td></tr>
                        <tr><td>Use Proxies</td><td>{config.use_proxies}</td></tr>
                        <tr><td>Rotate User Agents</td><td>{config.rotate_user_agents}</td></tr>
                    </table>
                </div>
                
                <div class="section">
                    <h2>Recent Results</h2>
                    <table>
                        <tr><th>Report #</th><th>Timestamp</th><th>Status</th><th>User Agent</th></tr>
                        {''.join([f"<tr><td>{result['report_number']}</td><td>{result['timestamp']}</td><td>{'SUCCESS' if result['success'] else 'FAILED'}</td><td>{result['user_agent'][:50]}...</td></tr>" for result in session.get('results', [])[-10:]])}
                    </table>
                </div>
                
                <div class="section">
                    <h2>Errors</h2>
                    {''.join([f"<p><strong>Report {error['report_number']}</strong>: {error['error']} ({error['timestamp']})</p>" for error in statistics.get('errors', [])[-5:]])}
                </div>
            </body>
            </html>
            """
        else:
            return json.dumps(session, indent=2, default=str)
    
    def get_educational_info(self) -> Dict[str, Any]:
        """Get educational information about mass reporting"""
        return {
            'purpose': 'Educational and research purposes only',
            'disclaimer': 'This tool is designed for educational purposes to understand mass reporting mechanisms and their impact on online platforms.',
            'ethical_guidelines': [
                'Only use on systems you own or have explicit permission to test',
                'Do not use for harassment or malicious purposes',
                'Respect rate limits and platform terms of service',
                'Document all activities for educational purposes',
                'Ensure compliance with applicable laws and regulations'
            ],
            'learning_objectives': [
                'Understand mass reporting mechanisms',
                'Learn about rate limiting and detection',
                'Study platform response patterns',
                'Analyze reporting system vulnerabilities',
                'Develop countermeasures and protections'
            ],
            'legal_notice': 'Users must ensure they have proper authorization before testing any systems. Unauthorized mass reporting may violate laws and platform terms of service.'
        }

# Global instance
mass_report_tool = MassReportTool() 