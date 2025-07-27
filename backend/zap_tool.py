import subprocess
import json
import os
import tempfile
import threading
import time
import re
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import xml.etree.ElementTree as ET

class ZAPTool:
    def __init__(self):
        self.sessions = {}
        self.active_scans = {}
        self.zap_path = self._find_zap()
        self.zap_api_url = "http://localhost:8080"
        self.zap_api_key = None
        self.logger = logging.getLogger(__name__)
        
    def _find_zap(self) -> str:
        """Find the ZAP executable"""
        possible_paths = [
            '/usr/bin/zap.sh',
            '/usr/local/bin/zap.sh',
            '/opt/zap/zap.sh',
            'zap.sh',
            'zap-baseline.py',
            'zap-cli'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '--version'], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        return 'zap.sh'  # Default fallback
    
    def check_installation(self) -> Dict[str, Any]:
        """Check if OWASP ZAP is installed and accessible"""
        try:
            result = subprocess.run([self.zap_path, '--version'], 
                                 capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                version_match = re.search(r'ZAP (\d+\.\d+\.\d+)', result.stdout)
                version = version_match.group(1) if version_match else 'Unknown'
                
                return {
                    'installed': True,
                    'version': version,
                    'path': self.zap_path,
                    'message': 'OWASP ZAP is ready to use'
                }
            else:
                return {
                    'installed': False,
                    'error': 'OWASP ZAP not found or not accessible',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
        except Exception as e:
            return {
                'installed': False,
                'error': f'Error checking ZAP installation: {str(e)}'
            }
    
    def start_zap_daemon(self) -> Dict[str, Any]:
        """Start ZAP daemon mode"""
        try:
            # Check if ZAP is already running
            try:
                response = requests.get(f"{self.zap_api_url}/JSON/core/view/version/", timeout=5)
                if response.status_code == 200:
                    return {
                        'running': True,
                        'message': 'ZAP daemon is already running'
                    }
            except:
                pass
            
            # Start ZAP daemon
            cmd = [
                self.zap_path,
                '-daemon',
                '-port', '8080',
                '-config', 'api.key=',
                '-config', 'api.addrs.addr.name=.*',
                '-config', 'api.addrs.addr.regex=true'
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a bit for ZAP to start
            time.sleep(10)
            
            # Check if it's running
            try:
                response = requests.get(f"{self.zap_api_url}/JSON/core/view/version/", timeout=5)
                if response.status_code == 200:
                    return {
                        'running': True,
                        'message': 'ZAP daemon started successfully',
                        'process': process
                    }
                else:
                    return {
                        'running': False,
                        'error': 'Failed to start ZAP daemon'
                    }
            except Exception as e:
                return {
                    'running': False,
                    'error': f'Failed to connect to ZAP daemon: {str(e)}'
                }
                
        except Exception as e:
            self.logger.error(f"Error starting ZAP daemon: {e}")
            return {
                'running': False,
                'error': f'Failed to start ZAP daemon: {str(e)}'
            }
    
    def start_scan(self, session_id: str, target_url: str, scan_type: str = 'spider', 
                  options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Start a new ZAP scan"""
        try:
            if session_id in self.active_scans:
                return {'error': 'Session already exists'}
            
            # Start ZAP daemon if not running
            daemon_status = self.start_zap_daemon()
            if not daemon_status['running']:
                return {'error': 'Failed to start ZAP daemon'}
            
            # Create scan session
            scan_session = {
                'session_id': session_id,
                'target_url': target_url,
                'scan_type': scan_type,
                'options': options or {},
                'start_time': datetime.now().isoformat(),
                'status': 'running',
                'progress': 0,
                'results': [],
                'alerts': []
            }
            
            self.active_scans[session_id] = scan_session
            
            # Start scan in background thread
            threading.Thread(target=self._run_scan, args=(session_id,), daemon=True).start()
            
            return {
                'session_id': session_id,
                'status': 'started',
                'target_url': target_url,
                'scan_type': scan_type
            }
            
        except Exception as e:
            self.logger.error(f"Error starting ZAP scan: {e}")
            return {'error': f'Failed to start scan: {str(e)}'}
    
    def _run_scan(self, session_id: str):
        """Run the actual ZAP scan"""
        if session_id not in self.active_scans:
            return
        
        session = self.active_scans[session_id]
        target_url = session['target_url']
        scan_type = session['scan_type']
        
        try:
            # Step 1: Access the target URL
            self._zap_api_call('core/action/accessUrl/', {'url': target_url})
            session['progress'] = 10
            
            # Step 2: Spider scan (if requested)
            if scan_type in ['spider', 'full']:
                spider_id = self._zap_api_call('spider/action/scan/', {'url': target_url})
                if spider_id and 'scan' in spider_id:
                    self._wait_for_spider_completion(spider_id['scan'])
                session['progress'] = 40
            
            # Step 3: Active scan (if requested)
            if scan_type in ['active', 'full']:
                active_scan_id = self._zap_api_call('ascan/action/scan/', {'url': target_url})
                if active_scan_id and 'scan' in active_scan_id:
                    self._wait_for_active_scan_completion(active_scan_id['scan'])
                session['progress'] = 80
            
            # Step 4: Get results
            session['alerts'] = self._get_alerts()
            session['results'] = self._get_scan_results()
            session['progress'] = 100
            session['status'] = 'completed'
            session['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            self.logger.error(f"Error in ZAP scan {session_id}: {e}")
            session['status'] = 'failed'
            session['error'] = str(e)
            session['end_time'] = datetime.now().isoformat()
    
    def _zap_api_call(self, endpoint: str, params: Dict[str, Any] = None) -> Any:
        """Make a call to ZAP API"""
        try:
            url = f"{self.zap_api_url}/JSON/{endpoint}"
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"ZAP API error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            self.logger.error(f"Error calling ZAP API: {e}")
            return None
    
    def _wait_for_spider_completion(self, scan_id: str):
        """Wait for spider scan to complete"""
        while True:
            status = self._zap_api_call('spider/view/status/', {'scanId': scan_id})
            if status and 'status' in status:
                if status['status'] == '100':
                    break
            time.sleep(2)
    
    def _wait_for_active_scan_completion(self, scan_id: str):
        """Wait for active scan to complete"""
        while True:
            status = self._zap_api_call('ascan/view/status/', {'scanId': scan_id})
            if status and 'status' in status:
                if status['status'] == '100':
                    break
            time.sleep(2)
    
    def _get_alerts(self) -> List[Dict[str, Any]]:
        """Get alerts from ZAP"""
        try:
            alerts = self._zap_api_call('core/view/alerts/')
            if alerts and 'alerts' in alerts:
                return alerts['alerts']
            return []
        except Exception as e:
            self.logger.error(f"Error getting alerts: {e}")
            return []
    
    def _get_scan_results(self) -> Dict[str, Any]:
        """Get comprehensive scan results"""
        try:
            results = {
                'urls': self._zap_api_call('core/view/urls/'),
                'sites': self._zap_api_call('core/view/sites/'),
                'spider_results': self._zap_api_call('spider/view/results/'),
                'ascan_results': self._zap_api_call('ascan/view/scans/')
            }
            return results
        except Exception as e:
            self.logger.error(f"Error getting scan results: {e}")
            return {}
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get status of a scan session"""
        if session_id not in self.active_scans:
            return {'error': 'Session not found'}
        
        session = self.active_scans[session_id]
        
        return {
            'session_id': session_id,
            'status': session['status'],
            'target_url': session['target_url'],
            'scan_type': session['scan_type'],
            'progress': session['progress'],
            'start_time': session['start_time'],
            'end_time': session.get('end_time'),
            'alerts': session.get('alerts', []),
            'results': session.get('results', {}),
            'error': session.get('error')
        }
    
    def stop_session(self, session_id: str) -> Dict[str, Any]:
        """Stop an active scan session"""
        if session_id not in self.active_scans:
            return {'error': 'Session not found'}
        
        session = self.active_scans[session_id]
        
        try:
            # Stop any active scans
            if session['scan_type'] in ['active', 'full']:
                self._zap_api_call('ascan/action/stopAllScans/')
            
            if session['scan_type'] in ['spider', 'full']:
                self._zap_api_call('spider/action/stopAllScans/')
            
            session['status'] = 'stopped'
            session['end_time'] = datetime.now().isoformat()
            
            return {'status': 'stopped', 'session_id': session_id}
            
        except Exception as e:
            self.logger.error(f"Error stopping session {session_id}: {e}")
            return {'error': f'Failed to stop session: {str(e)}'}
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Get all active and completed sessions"""
        sessions = []
        
        for session_id, session in self.active_scans.items():
            sessions.append({
                'session_id': session_id,
                'status': session['status'],
                'target_url': session['target_url'],
                'scan_type': session['scan_type'],
                'progress': session['progress'],
                'start_time': session['start_time'],
                'end_time': session.get('end_time'),
                'error': session.get('error')
            })
        
        return sessions
    
    def generate_report(self, session_id: str, report_format: str = 'html') -> Dict[str, Any]:
        """Generate a report for a scan session"""
        if session_id not in self.active_scans:
            return {'error': 'Session not found'}
        
        session = self.active_scans[session_id]
        
        try:
            # Generate report using ZAP API
            report_params = {
                'title': f'ZAP Scan Report - {session["target_url"]}',
                'template': report_format,
                'theme': 'traditional-html'
            }
            
            report = self._zap_api_call('reports/action/generate/', report_params)
            
            if report and 'report' in report:
                return {
                    'session_id': session_id,
                    'report_url': report['report'],
                    'format': report_format
                }
            else:
                return {'error': 'Failed to generate report'}
                
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return {'error': f'Failed to generate report: {str(e)}'}
    
    def get_scan_types(self) -> List[Dict[str, str]]:
        """Get available scan types"""
        return [
            {
                'id': 'spider',
                'name': 'Spider Scan',
                'description': 'Crawl the website to discover pages and resources'
            },
            {
                'id': 'active',
                'name': 'Active Scan',
                'description': 'Actively test for vulnerabilities by sending malicious requests'
            },
            {
                'id': 'full',
                'name': 'Full Scan',
                'description': 'Complete spider and active scan combination'
            },
            {
                'id': 'baseline',
                'name': 'Baseline Scan',
                'description': 'Quick passive scan for common vulnerabilities'
            }
        ]
    
    def get_vulnerability_summary(self, session_id: str) -> Dict[str, Any]:
        """Get vulnerability summary for a session"""
        if session_id not in self.active_scans:
            return {'error': 'Session not found'}
        
        session = self.active_scans[session_id]
        alerts = session.get('alerts', [])
        
        # Count alerts by risk level
        risk_counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }
        
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            if risk in risk_counts:
                risk_counts[risk] += 1
        
        return {
            'session_id': session_id,
            'total_alerts': len(alerts),
            'risk_breakdown': risk_counts,
            'high_risk_alerts': [a for a in alerts if a.get('risk') == 'High'],
            'medium_risk_alerts': [a for a in alerts if a.get('risk') == 'Medium']
        }

# Global instance
zap_tool = ZAPTool() 