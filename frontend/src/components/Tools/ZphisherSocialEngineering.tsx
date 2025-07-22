import React, { useEffect, useState, useRef } from 'react';
import {
  Box, Card, CardContent, Typography, Button, Select, MenuItem, FormControl, InputLabel, Alert, Chip, CircularProgress, Divider, List, ListItem, ListItemText, ListItemIcon, Tooltip, TextField
} from '@mui/material';
import PhishingIcon from '@mui/icons-material/Phishing';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import LinkIcon from '@mui/icons-material/Link';
import KeyIcon from '@mui/icons-material/VpnKey';
import TerminalIcon from '@mui/icons-material/Terminal';
import axios from 'axios';
import DownloadIcon from '@mui/icons-material/Download';
import DeleteIcon from '@mui/icons-material/Delete';
import SettingsIcon from '@mui/icons-material/Settings';
import HistoryIcon from '@mui/icons-material/History';
import RefreshIcon from '@mui/icons-material/Refresh';

const ZphisherSocialEngineering: React.FC<{ userRole?: string }> = ({ userRole }) => {
  const [templates, setTemplates] = useState<string[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const intervalRef = useRef<any>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [port, setPort] = useState('');
  const [tunnel, setTunnel] = useState('');
  const [sessionHistory, setSessionHistory] = useState<any[]>([]);
  const [selectedSession, setSelectedSession] = useState<any | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [templateLoading, setTemplateLoading] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);

  const tunnelOptions = [
    { label: 'Localhost', value: 'localhost', index: 1 },
    { label: 'Cloudflared', value: 'cloudflared', index: 2 },
    { label: 'LocalXpose', value: 'localxpose', index: 3 },
  ];

  // Attach JWT to all axios requests automatically
  axios.interceptors.request.use(config => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  });

  // Fetch templates on mount
  const fetchTemplates = async () => {
    setTemplateLoading(true);
    setError(null);
    console.log('🔄 Fetching Zphisher templates...');
    try {
      // Vite dev server proxy will forward this to Flask backend
      const res = await axios.get(`/api/tools/social/zphisher/templates?ts=${Date.now()}`, {
        headers: { 'Cache-Control': 'no-cache' }
      });
      console.log('✅ Templates API Response:', res.data);
      const templates = res.data?.templates || [];
      setTemplates(templates);
      console.log("📋 Fetched templates:", templates);
      console.log('📊 Response source:', res.data?.source);
      if (templates.length && !selectedTemplate) setSelectedTemplate(templates[0]);
      if (res.data?.source === 'fallback' && res.data?.error) {
        console.warn('⚠️ Using fallback templates:', res.data.error);
        setError('Zphisher dynamic template fetch failed. Using fallback list. ' + res.data.error);
      }
    } catch (err: any) {
      console.error('❌ Failed to fetch templates:', err);
      setError('Failed to fetch Zphisher templates.');
      setTemplates([]);
    } finally {
      setTemplateLoading(false);
    }
  };
  useEffect(() => { fetchTemplates(); }, []);

  // Poll status if running and sessionId is set
  useEffect(() => {
    if (sessionId && status?.running) {
      intervalRef.current = setInterval(() => {
        axios.get(`/api/tools/social/zphisher/status?session_id=${sessionId}`)
          .then(res => setStatus(res.data))
          .catch(() => setError('Failed to fetch Zphisher status.'));
      }, 2000);
    } else {
      clearInterval(intervalRef.current);
    }
    return () => clearInterval(intervalRef.current);
  }, [status?.running, sessionId]);

  // Fetch session history
  const fetchHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await axios.get('/api/tools/social/zphisher/history');
      setSessionHistory(res.data.sessions || []);
    } catch {
      setSessionHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  };
  useEffect(() => { fetchHistory(); }, [status?.running]);
  const handleViewSession = async (session_id: string) => {
    setHistoryLoading(true);
    try {
      const res = await axios.get(`/api/tools/social/zphisher/history/${session_id}`);
      setSelectedSession({ ...res.data, session_id });
    } catch {
      setSelectedSession(null);
    } finally {
      setHistoryLoading(false);
    }
  };
  const handleDownloadCredsSession = (creds: string[], session_id: string) => {
    if (!creds?.length) return;
    const csv = 'Credential\n' + creds.map((c: string) => `"${c.replace(/"/g, '""')}"`).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `zphisher_credentials_${session_id}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };
  const handleDownloadLogSession = (output: string[], session_id: string) => {
    if (!output?.length) return;
    const blob = new Blob([output.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `zphisher_session_log_${session_id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleStart = async () => {
    setError(null);
    setStarting(true);
    try {
      // Map tunnel to tunnel_index
      let tunnel_index = 1; // Default to Localhost
      if (tunnel) {
        const found = tunnelOptions.find(opt => opt.value === tunnel);
        if (found) tunnel_index = found.index;
      }
      const res = await axios.post('/api/tools/social/zphisher/start', {
        template: selectedTemplate,
        port: port || undefined,
        tunnel: tunnel || undefined,
        tunnel_index,
      });
      const newSessionId = res.data.session_id;
      setSessionId(newSessionId);
      setStatus({ running: true, session_id: newSessionId, template: selectedTemplate });
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to start Zphisher.');
    } finally {
      setStarting(false);
    }
  };

  const handleStop = async () => {
    setError(null);
    setStopping(true);
    try {
      if (!sessionId) throw new Error('No active session');
      await axios.post('/api/tools/social/zphisher/stop', { session_id: sessionId });
      setStatus((prev: any) => ({ ...prev, running: false }));
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to stop Zphisher.');
    } finally {
      setStopping(false);
    }
  };

  const handleDownloadCreds = () => {
    if (!status?.credentials?.length) return;
    const csv = 'Credential\n' + status.credentials.map((c: string) => `"${c.replace(/"/g, '""')}"`).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'zphisher_credentials.csv';
    a.click();
    URL.revokeObjectURL(url);
  };
  const handleDownloadLog = () => {
    if (!status?.output?.length) return;
    const blob = new Blob([status.output.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'zphisher_session_log.txt';
    a.click();
    URL.revokeObjectURL(url);
  };
  const handleClearSession = () => {
    setStatus((prev: any) => ({ ...prev, output: [], credentials: [] }));
  };

  // Only allow admin/analyst
  if (userRole && !['admin', 'analyst'].includes(userRole)) {
    return <Alert severity="error">You do not have permission to access social engineering tools.</Alert>;
  }

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto', mt: 4 }}>
      <Card>
        <CardContent>
          <Typography variant="h4" sx={{ mb: 2, fontWeight: 700 }}>
            <PhishingIcon sx={{ mr: 1, verticalAlign: 'middle' }} /> Social Engineering (Zphisher)
          </Typography>
          <Alert severity="info" sx={{ mb: 2 }}>
            Launch phishing campaigns using Zphisher. Select a template, start the attack, and monitor results in real time. <b>For authorized use only.</b>
          </Alert>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          <FormControl fullWidth sx={{ mb: 2, position: 'relative' }}>
            <InputLabel id="zphisher-template-label">Template</InputLabel>
            <Select
              labelId="zphisher-template-label"
              value={selectedTemplate}
              label="Template"
              onChange={e => setSelectedTemplate(e.target.value)}
              disabled={status?.running || starting || templateLoading}
            >
              {templates.map(t => (
                <MenuItem key={t} value={t}>{t}</MenuItem>
              ))}
            </Select>
            <Tooltip title="Templates are auto-detected from the backend Zphisher installation. Click to refresh." arrow>
              <span>
                <Button
                  onClick={fetchTemplates}
                  size="small"
                  sx={{ position: 'absolute', right: 8, top: 8, minWidth: 0, p: 0.5 }}
                  disabled={templateLoading || status?.running || starting}
                >
                  {templateLoading ? <CircularProgress size={18} /> : <RefreshIcon />}
                </Button>
              </span>
            </Tooltip>
          </FormControl>
          <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
            <TextField
              label="Custom Port (optional)"
              value={port}
              onChange={e => setPort(e.target.value.replace(/[^0-9]/g, ''))}
              size="small"
              sx={{ width: 180 }}
              disabled={status?.running || starting}
            />
            <FormControl fullWidth sx={{ mb: 2, position: 'relative' }}>
              <InputLabel id="zphisher-tunnel-label">Tunnel/Port Forwarding</InputLabel>
              <Select
                labelId="zphisher-tunnel-label"
                value={tunnel}
                label="Tunnel/Port Forwarding"
                onChange={e => setTunnel(e.target.value)}
                disabled={status?.running || starting}
                displayEmpty
              >
                <MenuItem value=""><em>Default (Localhost)</em></MenuItem>
                {tunnelOptions.map(opt => (
                  <MenuItem key={opt.value} value={opt.value}>{opt.label}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>
          <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
            <Button
              variant="contained"
              color="primary"
              startIcon={<PlayArrowIcon />}
              onClick={() => handleStart()}
              disabled={!selectedTemplate || status?.running || starting}
            >
              {starting ? <CircularProgress size={18} /> : 'Start Attack'}
            </Button>
            <Button
              variant="outlined"
              color="error"
              startIcon={<StopIcon />}
              onClick={handleStop}
              disabled={!status?.running || stopping}
            >
              {stopping ? <CircularProgress size={18} /> : 'Stop Attack'}
            </Button>
          </Box>
          {status?.template && (
            <Chip label={`Template: ${status.template}`} color="info" sx={{ mr: 1 }} />
          )}
          {status?.running && (
            <Chip label="Running" color="success" sx={{ mr: 1 }} />
          )}
          {!status?.running && status?.template && (
            <Chip label="Stopped" color="warning" sx={{ mr: 1 }} />
          )}
          {status?.session_id && (
            <Chip label={`Session ID: ${status.session_id}`} color="default" sx={{ mr: 1 }} />
          )}
          <Divider sx={{ my: 2 }} />
          {status?.link && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                <LinkIcon sx={{ mr: 1, verticalAlign: 'middle' }} /> Phishing Link
              </Typography>
              <Alert severity="success" sx={{ fontWeight: 600, fontSize: 16, display: 'flex', alignItems: 'center' }}>
                <span>{status.link}</span>
                <Chip
                  label={
                    status.link.includes('ngrok') ? 'ngrok' :
                    status.link.includes('serveo') ? 'serveo' :
                    status.link.includes('localhost') ? 'localhost' :
                    status.link.includes('trycloudflare') ? 'cloudflared' : 'other'
                  }
                  sx={{ ml: 2 }}
                />
                <Button onClick={() => navigator.clipboard.writeText(status.link)} sx={{ ml: 2 }} size="small" variant="outlined">Copy</Button>
              </Alert>
              <Typography variant="body2" sx={{ mt: 1 }}>
                {status.link.includes('localhost')
                  ? 'This link is only accessible from your local machine.'
                  : 'This link is accessible from the internet (via tunnel).'}
              </Typography>
              <Typography variant="caption" sx={{ mt: 1, display: 'block' }}>
                The cloned template files are served from <b>backend/zphisher/.server/www</b> on the backend.
              </Typography>
            </Box>
          )}
          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
              <TerminalIcon sx={{ mr: 1, verticalAlign: 'middle' }} /> Real-Time Output
            </Typography>
            <Box sx={{ background: '#181c24', color: '#fff', borderRadius: 2, p: 2, minHeight: 120, maxHeight: 240, overflowY: 'auto', fontFamily: 'monospace', fontSize: 14 }}>
              {status?.output?.length ? status.output.slice(-20).map((line: string, idx: number) => (
                <div key={idx}>{line}</div>
              )) : <span style={{ color: '#aaa' }}>No output yet.</span>}
            </Box>
          </Box>
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
              <KeyIcon sx={{ mr: 1, verticalAlign: 'middle' }} /> Harvested Credentials
            </Typography>
            {status?.credentials?.length ? (
              <List>
                {status.credentials.map((cred: string, idx: number) => (
                  <ListItem key={idx}>
                    <ListItemIcon><KeyIcon color="primary" /></ListItemIcon>
                    <ListItemText primary={cred} />
                  </ListItem>
                ))}
              </List>
            ) : <Alert severity="info">No credentials captured yet.</Alert>}
          </Box>
        </CardContent>
      </Card>
      <Box sx={{ mt: 4 }}>
        <Divider sx={{ my: 2 }} />
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <HistoryIcon color="action" />
          <Typography variant="h6" sx={{ fontWeight: 600, flex: 1 }}>Session History</Typography>
          <Button size="small" onClick={fetchHistory} disabled={historyLoading}>{historyLoading ? <CircularProgress size={16} /> : 'Refresh'}</Button>
        </Box>
        <Box sx={{ background: '#f8fafc', borderRadius: 2, p: 2, mb: 2, minHeight: 80 }}>
          {sessionHistory.length === 0 ? (
            <Alert severity="info">No past Zphisher sessions found.</Alert>
          ) : (
            <List>
              {sessionHistory.map(s => (
                <ListItem key={s.session_id} button onClick={() => handleViewSession(s.session_id)} selected={selectedSession?.session_id === s.session_id}>
                  <ListItemIcon><PhishingIcon color="primary" /></ListItemIcon>
                  <ListItemText
                    primary={`Template: ${s.template}`}
                    secondary={`Session: ${s.session_id} | Link: ${s.link || 'N/A'} | Credentials: ${s.credentials_count}`}
                  />
                </ListItem>
              ))}
            </List>
          )}
        </Box>
        {selectedSession && (
          <Box sx={{ background: '#fff', borderRadius: 2, p: 2, mb: 2, border: '1px solid #eee' }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>Session Details</Typography>
            <Chip label={`Session ID: ${selectedSession.session_id}`} sx={{ mr: 1 }} />
            <Chip label={`Template: ${selectedSession.template}`} sx={{ mr: 1 }} />
            {selectedSession.link && <Chip label={`Link: ${selectedSession.link}`} sx={{ mr: 1 }} />}
            <Box sx={{ mt: 2, mb: 1 }}>
              <Button variant="outlined" startIcon={<DownloadIcon />} onClick={() => handleDownloadCredsSession(selectedSession.credentials, selectedSession.session_id)} disabled={!selectedSession.credentials?.length} sx={{ mr: 1 }}>
                Download Credentials (CSV)
              </Button>
              <Button variant="outlined" startIcon={<DownloadIcon />} onClick={() => handleDownloadLogSession(selectedSession.output, selectedSession.session_id)} disabled={!selectedSession.output?.length}>
                Download Session Log
              </Button>
            </Box>
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Credentials</Typography>
            {selectedSession.credentials?.length ? (
              <List>
                {selectedSession.credentials.map((cred: string, idx: number) => (
                  <ListItem key={idx}><ListItemIcon><KeyIcon color="primary" /></ListItemIcon><ListItemText primary={cred} /></ListItem>
                ))}
              </List>
            ) : <Alert severity="info">No credentials captured in this session.</Alert>}
            <Divider sx={{ my: 2 }} />
            <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Session Log</Typography>
            <Box sx={{ background: '#181c24', color: '#fff', borderRadius: 2, p: 2, minHeight: 80, maxHeight: 200, overflowY: 'auto', fontFamily: 'monospace', fontSize: 14 }}>
              {selectedSession.output?.length ? selectedSession.output.map((line: string, idx: number) => (
                <div key={idx}>{line}</div>
              )) : <span style={{ color: '#aaa' }}>No output.</span>}
            </Box>
          </Box>
        )}
      </Box>
      <Box sx={{ mt: 4 }}>
        <Divider sx={{ my: 2 }} />
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <SettingsIcon color="action" />
          <Typography variant="h6" sx={{ fontWeight: 600, flex: 1 }}>Advanced Options & Logs</Typography>
          <Button size="small" onClick={() => setShowAdvanced(v => !v)}>{showAdvanced ? 'Hide' : 'Show'}</Button>
        </Box>
        {showAdvanced && (
          <Box sx={{ background: '#f8fafc', borderRadius: 2, p: 2, mb: 2 }}>
            <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
              <Button variant="outlined" startIcon={<DownloadIcon />} onClick={handleDownloadCreds} disabled={!status?.credentials?.length}>
                Download Credentials (CSV)
              </Button>
              <Button variant="outlined" startIcon={<DownloadIcon />} onClick={handleDownloadLog} disabled={!status?.output?.length}>
                Download Session Log
              </Button>
              <Button variant="outlined" color="warning" startIcon={<DeleteIcon />} onClick={handleClearSession}>
                Clear Session/Logs
              </Button>
            </Box>
            <Alert severity="info" sx={{ mb: 2 }}>
              <b>Advanced Zphisher Options (coming soon):</b> Custom port, tunneling method, webhook integration, persistent log storage, and more.
            </Alert>
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default ZphisherSocialEngineering; 