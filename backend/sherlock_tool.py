import subprocess
import json
import os
import tempfile
import threading
import time
from datetime import datetime
from flask import current_app

class SherlockTool:
    def __init__(self):
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self.sherlock_path = self._get_sherlock_path()
        
    def _get_sherlock_path(self):
        """Get the path to sherlock tool"""
        # Check if sherlock is installed
        try:
            result = subprocess.run(['which', 'sherlock'], capture_output=True, text=True)
            if result.returncode == 0:
                return 'sherlock'
        except:
            pass
        
        # Check common installation paths
        common_paths = [
            '/usr/local/bin/sherlock',
            '/usr/bin/sherlock',
            '/opt/sherlock/sherlock.py',
            os.path.expanduser('~/.local/bin/sherlock')
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
                
        return None
    
    def install_sherlock(self):
        """Install sherlock if not available"""
        try:
            # Try to install via pip
            subprocess.run(['pip', 'install', 'sherlock-project'], check=True)
            return True
        except subprocess.CalledProcessError:
            try:
                # Try git clone method
                subprocess.run([
                    'git', 'clone', 'https://github.com/sherlock-project/sherlock.git'
                ], check=True)
                subprocess.run([
                    'cd', 'sherlock', '&&', 'python3', '-m', 'pip', 'install', '-e', '.'
                ], check=True, shell=True)
                return True
            except subprocess.CalledProcessError:
                return False
    
    def start_username_search(self, username, platforms=None, timeout=300):
        """Start a username search across social media platforms"""
        session_id = f"sherlock_{int(time.time())}"
        
        if not self.sherlock_path:
            if not self.install_sherlock():
                return {
                    'session_id': session_id,
                    'status': 'error',
                    'error': 'Sherlock tool not available and could not be installed'
                }
            self.sherlock_path = 'sherlock'
        
        # Create temporary output file
        output_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        output_file.close()
        
        # Build command
        cmd = [self.sherlock_path, username, '--output', output_file.name, '--format', 'json']
        
        if platforms:
            cmd.extend(['--site', ','.join(platforms)])
        
        # Start the process
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Store session info
            with self.sessions_lock:
                self.sessions[session_id] = {
                    'username': username,
                    'process': process,
                    'output_file': output_file.name,
                    'start_time': datetime.now(),
                    'status': 'running',
                    'results': [],
                    'platforms': platforms or 'all'
                }
            
            # Start monitoring thread
            thread = threading.Thread(
                target=self._monitor_process,
                args=(session_id, process, output_file.name, timeout)
            )
            thread.daemon = True
            thread.start()
            
            return {
                'session_id': session_id,
                'status': 'started',
                'username': username,
                'platforms': platforms or 'all'
            }
            
        except Exception as e:
            return {
                'session_id': session_id,
                'status': 'error',
                'error': str(e)
            }
    
    def _monitor_process(self, session_id, process, output_file, timeout):
        """Monitor the sherlock process and collect results"""
        try:
            # Wait for process to complete with timeout
            process.wait(timeout=timeout)
            
            # Read results from output file
            results = []
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                results.append(json.loads(line))
                except Exception as e:
                    current_app.logger.error(f"Error reading sherlock results: {e}")
            
            # Update session status
            with self.sessions_lock:
                if session_id in self.sessions:
                    self.sessions[session_id].update({
                        'status': 'completed',
                        'results': results,
                        'end_time': datetime.now(),
                        'exit_code': process.returncode
                    })
                    
        except subprocess.TimeoutExpired:
            # Kill process if it times out
            process.kill()
            with self.sessions_lock:
                if session_id in self.sessions:
                    self.sessions[session_id].update({
                        'status': 'timeout',
                        'end_time': datetime.now()
                    })
        except Exception as e:
            current_app.logger.error(f"Error monitoring sherlock process: {e}")
            with self.sessions_lock:
                if session_id in self.sessions:
                    self.sessions[session_id].update({
                        'status': 'error',
                        'error': str(e),
                        'end_time': datetime.now()
                    })
        finally:
            # Clean up output file
            try:
                os.unlink(output_file)
            except:
                pass
    
    def get_session_status(self, session_id):
        """Get the status of a sherlock session"""
        with self.sessions_lock:
            return self.sessions.get(session_id, None)
    
    def get_all_sessions(self):
        """Get all active sessions"""
        with self.sessions_lock:
            return list(self.sessions.keys())
    
    def stop_session(self, session_id):
        """Stop a running session"""
        with self.sessions_lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                if session['status'] == 'running' and 'process' in session:
                    try:
                        session['process'].kill()
                        session['status'] = 'stopped'
                        session['end_time'] = datetime.now()
                        return True
                    except:
                        pass
        return False
    
    def get_available_platforms(self):
        """Get list of available platforms"""
        if not self.sherlock_path:
            return []
        
        try:
            result = subprocess.run(
                [self.sherlock_path, '--help'],
                capture_output=True,
                text=True
            )
            
            # Parse platforms from help output
            platforms = []
            for line in result.stdout.split('\n'):
                if '--site' in line:
                    # Extract platform names from help text
                    continue
            
            return platforms
        except:
            return []

# Global sherlock tool instance
sherlock_tool = SherlockTool() 