import subprocess
import json
import os
import tempfile
import threading
import time
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

class MetasploitTool:
    def __init__(self):
        self.sessions = {}
        self.active_exploits = {}
        self.msfconsole_path = self._find_msfconsole()
        self.logger = logging.getLogger(__name__)
        
    def _find_msfconsole(self) -> str:
        """Find the msfconsole executable"""
        possible_paths = [
            '/usr/bin/msfconsole',
            '/opt/metasploit-framework/bin/msfconsole',
            '/usr/local/bin/msfconsole',
            'msfconsole'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '--version'], 
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        return 'msfconsole'  # Default fallback
    
    def check_installation(self) -> Dict[str, Any]:
        """Check if Metasploit Framework is installed and accessible"""
        try:
            result = subprocess.run([self.msfconsole_path, '--version'], 
                                 capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                version_match = re.search(r'Framework Version: (\d+\.\d+\.\d+)', result.stdout)
                version = version_match.group(1) if version_match else 'Unknown'
                
                return {
                    'installed': True,
                    'version': version,
                    'path': self.msfconsole_path,
                    'message': 'Metasploit Framework is ready to use'
                }
            else:
                return {
                    'installed': False,
                    'error': 'Metasploit Framework not found or not accessible',
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
        except Exception as e:
            return {
                'installed': False,
                'error': f'Error checking Metasploit installation: {str(e)}'
            }
    
    def get_available_exploits(self) -> List[Dict[str, Any]]:
        """Get list of available exploits"""
        try:
            # Use msfconsole to search for exploits
            cmd = f'{self.msfconsole_path} -q -x "search type:exploit; exit"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            exploits = []
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('[*]') and not line.startswith('msf'):
                        parts = line.split()
                        if len(parts) >= 4:
                            exploits.append({
                                'name': parts[0],
                                'disclosure_date': parts[1],
                                'rank': parts[2],
                                'check': parts[3],
                                'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
                            })
            
            return exploits[:50]  # Limit to first 50 for performance
        except Exception as e:
            self.logger.error(f"Error getting exploits: {e}")
            return []
    
    def get_available_payloads(self) -> List[Dict[str, Any]]:
        """Get list of available payloads"""
        try:
            cmd = f'{self.msfconsole_path} -q -x "search type:payload; exit"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            payloads = []
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('[*]') and not line.startswith('msf'):
                        parts = line.split()
                        if len(parts) >= 4:
                            payloads.append({
                                'name': parts[0],
                                'disclosure_date': parts[1],
                                'rank': parts[2],
                                'check': parts[3],
                                'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
                            })
            
            return payloads[:30]  # Limit to first 30
        except Exception as e:
            self.logger.error(f"Error getting payloads: {e}")
            return []
    
    def start_exploit_session(self, session_id: str, target: str, exploit: str, 
                            payload: str, options: Dict[str, str] = None) -> Dict[str, Any]:
        """Start a new exploit session"""
        try:
            if session_id in self.active_exploits:
                return {'error': 'Session already exists'}
            
            # Create temporary resource file
            resource_file = tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False)
            
            # Build msfconsole commands
            commands = [
                f'use {exploit}',
                f'set RHOSTS {target}',
                f'set PAYLOAD {payload}'
            ]
            
            # Add custom options
            if options:
                for key, value in options.items():
                    commands.append(f'set {key} {value}')
            
            commands.extend([
                'exploit -j',  # Run in background
                'exit'
            ])
            
            # Write commands to resource file
            resource_file.write('\n'.join(commands))
            resource_file.close()
            
            # Start msfconsole with resource file
            cmd = f'{self.msfconsole_path} -r {resource_file.name}'
            
            # Start the process
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, text=True)
            
            # Store session info
            self.active_exploits[session_id] = {
                'process': process,
                'target': target,
                'exploit': exploit,
                'payload': payload,
                'options': options or {},
                'start_time': datetime.now().isoformat(),
                'status': 'running',
                'output': [],
                'resource_file': resource_file.name
            }
            
            # Start monitoring thread
            threading.Thread(target=self._monitor_exploit, 
                          args=(session_id,), daemon=True).start()
            
            return {
                'session_id': session_id,
                'status': 'started',
                'target': target,
                'exploit': exploit,
                'payload': payload
            }
            
        except Exception as e:
            self.logger.error(f"Error starting exploit session: {e}")
            return {'error': f'Failed to start exploit: {str(e)}'}
    
    def _monitor_exploit(self, session_id: str):
        """Monitor exploit execution and capture output"""
        if session_id not in self.active_exploits:
            return
        
        session = self.active_exploits[session_id]
        process = session['process']
        
        try:
            while True:
                output = process.stdout.readline()
                if output:
                    session['output'].append({
                        'timestamp': datetime.now().isoformat(),
                        'message': output.strip()
                    })
                
                # Check if process is still running
                if process.poll() is not None:
                    break
                
                time.sleep(0.1)
            
            # Process finished
            session['status'] = 'completed'
            session['end_time'] = datetime.now().isoformat()
            
            # Clean up resource file
            try:
                os.unlink(session['resource_file'])
            except:
                pass
                
        except Exception as e:
            self.logger.error(f"Error monitoring exploit {session_id}: {e}")
            session['status'] = 'failed'
            session['error'] = str(e)
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get status of an exploit session"""
        if session_id not in self.active_exploits:
            return {'error': 'Session not found'}
        
        session = self.active_exploits[session_id]
        
        return {
            'session_id': session_id,
            'status': session['status'],
            'target': session['target'],
            'exploit': session['exploit'],
            'payload': session['payload'],
            'options': session['options'],
            'start_time': session['start_time'],
            'end_time': session.get('end_time'),
            'output': session['output'][-50:],  # Last 50 lines
            'error': session.get('error')
        }
    
    def stop_session(self, session_id: str) -> Dict[str, Any]:
        """Stop an active exploit session"""
        if session_id not in self.active_exploits:
            return {'error': 'Session not found'}
        
        session = self.active_exploits[session_id]
        
        try:
            # Terminate the process
            session['process'].terminate()
            
            # Wait a bit, then force kill if needed
            try:
                session['process'].wait(timeout=5)
            except subprocess.TimeoutExpired:
                session['process'].kill()
            
            session['status'] = 'stopped'
            session['end_time'] = datetime.now().isoformat()
            
            # Clean up resource file
            try:
                os.unlink(session['resource_file'])
            except:
                pass
            
            return {'status': 'stopped', 'session_id': session_id}
            
        except Exception as e:
            self.logger.error(f"Error stopping session {session_id}: {e}")
            return {'error': f'Failed to stop session: {str(e)}'}
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Get all active and completed sessions"""
        sessions = []
        
        for session_id, session in self.active_exploits.items():
            sessions.append({
                'session_id': session_id,
                'status': session['status'],
                'target': session['target'],
                'exploit': session['exploit'],
                'payload': session['payload'],
                'start_time': session['start_time'],
                'end_time': session.get('end_time'),
                'error': session.get('error')
            })
        
        return sessions
    
    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """Clean up old completed sessions"""
        current_time = datetime.now()
        
        sessions_to_remove = []
        for session_id, session in self.active_exploits.items():
            if session['status'] in ['completed', 'failed', 'stopped']:
                end_time = datetime.fromisoformat(session.get('end_time', session['start_time']))
                age_hours = (current_time - end_time).total_seconds() / 3600
                
                if age_hours > max_age_hours:
                    sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            del self.active_exploits[session_id]
    
    def get_exploit_info(self, exploit_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific exploit"""
        try:
            cmd = f'{self.msfconsole_path} -q -x "info {exploit_name}; exit"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                info = {
                    'name': exploit_name,
                    'description': '',
                    'options': [],
                    'targets': [],
                    'payloads': []
                }
                
                lines = result.stdout.split('\n')
                current_section = None
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    if line.startswith('Name:'):
                        info['name'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Description:'):
                        info['description'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Options:'):
                        current_section = 'options'
                    elif line.startswith('Targets:'):
                        current_section = 'targets'
                    elif line.startswith('Payloads:'):
                        current_section = 'payloads'
                    elif current_section == 'options' and '=' in line:
                        parts = line.split('=', 1)
                        if len(parts) == 2:
                            info['options'].append({
                                'name': parts[0].strip(),
                                'default': parts[1].strip()
                            })
                    elif current_section == 'targets' and line.startswith('Id'):
                        # Parse target information
                        pass
                    elif current_section == 'payloads' and line.strip():
                        info['payloads'].append(line.strip())
                
                return info
            else:
                return {'error': 'Failed to get exploit information'}
                
        except Exception as e:
            self.logger.error(f"Error getting exploit info: {e}")
            return {'error': f'Failed to get exploit information: {str(e)}'}

# Global instance
metasploit_tool = MetasploitTool() 