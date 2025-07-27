import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  LinearProgress,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Grid,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Switch,
  FormControlLabel
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Security as SecurityIcon,
  ExpandMore as ExpandMoreIcon,
  Settings as SettingsIcon,
  BugReport as BugReportIcon,
  Code as CodeIcon
} from '@mui/icons-material';

interface Exploit {
  name: string;
  disclosure_date: string;
  rank: string;
  check: string;
  description: string;
}

interface Payload {
  name: string;
  disclosure_date: string;
  rank: string;
  check: string;
  description: string;
}

interface ExploitInfo {
  name: string;
  description: string;
  options: Array<{name: string; default: string}>;
  targets: string[];
  payloads: string[];
}

interface ExploitSession {
  session_id: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  target: string;
  exploit: string;
  payload: string;
  options: Record<string, string>;
  start_time: string;
  end_time?: string;
  output: Array<{timestamp: string; message: string}>;
  error?: string;
}

const MetasploitTool: React.FC = () => {
  const [target, setTarget] = useState('');
  const [selectedExploit, setSelectedExploit] = useState('');
  const [selectedPayload, setSelectedPayload] = useState('');
  const [exploits, setExploits] = useState<Exploit[]>([]);
  const [payloads, setPayloads] = useState<Payload[]>([]);
  const [sessions, setSessions] = useState<ExploitSession[]>([]);
  const [currentSession, setCurrentSession] = useState<ExploitSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [installationStatus, setInstallationStatus] = useState<any>(null);
  const [exploitInfo, setExploitInfo] = useState<ExploitInfo | null>(null);
  const [showExploitInfo, setShowExploitInfo] = useState(false);
  const [customOptions, setCustomOptions] = useState<Record<string, string>>({});

  // Helper function to get auth headers
  const getAuthHeaders = () => {
    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        throw new Error('No access token found');
      }
      return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      };
    } catch (error) {
      console.error('Error getting auth headers:', error);
      return {
        'Content-Type': 'application/json'
      };
    }
  };

  // Check authentication status
  const checkAuth = async () => {
    try {
      const response = await fetch('/api/health', {
        headers: getAuthHeaders()
      });
      setIsAuthenticated(response.ok);
      return response.ok;
    } catch (error) {
      console.error('Auth check failed:', error);
      setIsAuthenticated(false);
      return false;
    }
  };

  // Check Metasploit installation
  const checkMetasploitInstallation = async () => {
    try {
      const response = await fetch('/api/tools/metasploit/status', {
        headers: getAuthHeaders()
      });

      if (response.ok) {
        const status = await response.json();
        setInstallationStatus(status);
        return status.installed;
      } else {
        setInstallationStatus({ installed: false, error: 'Failed to check installation' });
        return false;
      }
    } catch (error) {
      console.error('Error checking Metasploit installation:', error);
      setInstallationStatus({ installed: false, error: 'Network error' });
      return false;
    }
  };

  // Fetch available exploits
  const fetchExploits = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/metasploit/exploits', {
        headers: getAuthHeaders()
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data.exploits && Array.isArray(data.exploits)) {
        setExploits(data.exploits);
      } else {
        // Fallback to sample exploits
        setExploits([
          {
            name: 'exploit/multi/handler',
            disclosure_date: '2019-01-01',
            rank: 'excellent',
            check: 'Yes',
            description: 'Generic Payload Handler'
          },
          {
            name: 'exploit/windows/smb/ms17_010_eternalblue',
            disclosure_date: '2017-03-14',
            rank: 'excellent',
            check: 'Yes',
            description: 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption'
          },
          {
            name: 'exploit/linux/misc/redis_unauth_exec',
            disclosure_date: '2019-07-10',
            rank: 'excellent',
            check: 'Yes',
            description: 'Redis Unauthenticated Code Execution'
          }
        ]);
      }
    } catch (error) {
      console.error('Error fetching exploits:', error);
      setError('Failed to load exploits. Using sample data.');
      setExploits([
        {
          name: 'exploit/multi/handler',
          disclosure_date: '2019-01-01',
          rank: 'excellent',
          check: 'Yes',
          description: 'Generic Payload Handler'
        },
        {
          name: 'exploit/windows/smb/ms17_010_eternalblue',
          disclosure_date: '2017-03-14',
          rank: 'excellent',
          check: 'Yes',
          description: 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption'
        },
        {
          name: 'exploit/linux/misc/redis_unauth_exec',
          disclosure_date: '2019-07-10',
          rank: 'excellent',
          check: 'Yes',
          description: 'Redis Unauthenticated Code Execution'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  // Fetch available payloads
  const fetchPayloads = async () => {
    try {
      const response = await fetch('/api/tools/metasploit/payloads', {
        headers: getAuthHeaders()
      });

      if (response.ok) {
        const data = await response.json();
        if (data.payloads && Array.isArray(data.payloads)) {
          setPayloads(data.payloads);
        } else {
          // Fallback to sample payloads
          setPayloads([
            {
              name: 'windows/meterpreter/reverse_tcp',
              disclosure_date: '2019-01-01',
              rank: 'excellent',
              check: 'Yes',
              description: 'Windows Meterpreter Reverse TCP'
            },
            {
              name: 'linux/x86/meterpreter/reverse_tcp',
              disclosure_date: '2019-01-01',
              rank: 'excellent',
              check: 'Yes',
              description: 'Linux x86 Meterpreter Reverse TCP'
            },
            {
              name: 'windows/shell/reverse_tcp',
              disclosure_date: '2019-01-01',
              rank: 'excellent',
              check: 'Yes',
              description: 'Windows Command Shell Reverse TCP'
            }
          ]);
        }
      }
    } catch (error) {
      console.error('Error fetching payloads:', error);
      setPayloads([
        {
          name: 'windows/meterpreter/reverse_tcp',
          disclosure_date: '2019-01-01',
          rank: 'excellent',
          check: 'Yes',
          description: 'Windows Meterpreter Reverse TCP'
        },
        {
          name: 'linux/x86/meterpreter/reverse_tcp',
          disclosure_date: '2019-01-01',
          rank: 'excellent',
          check: 'Yes',
          description: 'Linux x86 Meterpreter Reverse TCP'
        },
        {
          name: 'windows/shell/reverse_tcp',
          disclosure_date: '2019-01-01',
          rank: 'excellent',
          check: 'Yes',
          description: 'Windows Command Shell Reverse TCP'
        }
      ]);
    }
  };

  // Fetch exploit information
  const fetchExploitInfo = async (exploitName: string) => {
    try {
      const response = await fetch(`/api/tools/metasploit/exploit/${encodeURIComponent(exploitName)}/info`, {
        headers: getAuthHeaders()
      });

      if (response.ok) {
        const info = await response.json();
        if (!info.error) {
          setExploitInfo(info);
          setShowExploitInfo(true);
        }
      }
    } catch (error) {
      console.error('Error fetching exploit info:', error);
    }
  };

  // Fetch existing sessions
  const fetchSessions = async () => {
    try {
      const response = await fetch('/api/tools/metasploit/sessions', {
        headers: getAuthHeaders()
      });

      if (response.ok) {
        const data = await response.json();
        if (data.sessions && Array.isArray(data.sessions)) {
          setSessions(data.sessions);
        }
      }
    } catch (error) {
      console.error('Error fetching sessions:', error);
    }
  };

  // Start a new exploit
  const startExploit = async () => {
    if (!target.trim()) {
      setError('Please enter a target');
      return;
    }

    if (!selectedExploit) {
      setError('Please select an exploit');
      return;
    }

    if (!selectedPayload) {
      setError('Please select a payload');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/metasploit/exploit/start', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          target: target.trim(),
          exploit: selectedExploit,
          payload: selectedPayload,
          options: customOptions
        })
      });

      if (!response.ok) {
        if (response.status === 401) {
          setError('Authentication failed. Please log in again.');
          return;
        }
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data.session_id) {
        // Create a new session object
        const newSession: ExploitSession = {
          session_id: data.session_id,
          target: target.trim(),
          exploit: selectedExploit,
          payload: selectedPayload,
          options: customOptions,
          status: 'running',
          start_time: new Date().toISOString(),
          output: []
        };
        
        setCurrentSession(newSession);
        setSessions(prev => [newSession, ...prev]);
        
        // Start polling for updates
        pollSessionStatus(data.session_id);
      }
    } catch (error) {
      console.error('Error starting exploit:', error);
      setError('Failed to start exploit. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Poll session status
  const pollSessionStatus = async (sessionId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/tools/metasploit/session/${sessionId}/status`, {
          headers: getAuthHeaders()
        });

        if (response.ok) {
          const data = await response.json();
          
          setCurrentSession(prev => {
            if (prev && prev.session_id === sessionId) {
              return {
                ...prev,
                status: data.status,
                output: data.output || prev.output,
                end_time: data.end_time,
                error: data.error
              };
            }
            return prev;
          });

          setSessions(prev => prev.map(session => 
            session.session_id === sessionId 
              ? {
                  ...session,
                  status: data.status,
                  output: data.output || session.output,
                  end_time: data.end_time,
                  error: data.error
                }
              : session
          ));

          // Stop polling if session is complete
          if (data.status === 'completed' || data.status === 'failed' || data.status === 'stopped') {
            clearInterval(pollInterval);
          }
        }
      } catch (error) {
        console.error('Error polling session status:', error);
      }
    }, 2000); // Poll every 2 seconds

    // Cleanup after 10 minutes
    setTimeout(() => {
      clearInterval(pollInterval);
    }, 600000);
  };

  // Stop an exploit session
  const stopSession = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/tools/metasploit/session/${sessionId}/stop`, {
        method: 'POST',
        headers: getAuthHeaders()
      });

      if (response.ok) {
        setSessions(prev => prev.map(session => 
          session.session_id === sessionId 
            ? { ...session, status: 'stopped', end_time: new Date().toISOString() }
            : session
        ));
        
        if (currentSession?.session_id === sessionId) {
          setCurrentSession(prev => prev ? { ...prev, status: 'stopped', end_time: new Date().toISOString() } : null);
        }
      }
    } catch (error) {
      console.error('Error stopping session:', error);
      setError('Failed to stop session');
    }
  };

  // Handle exploit selection
  const handleExploitChange = (event: any) => {
    setSelectedExploit(event.target.value);
    setCustomOptions({}); // Reset custom options
  };

  // Initialize component
  useEffect(() => {
    const initialize = async () => {
      const authOk = await checkAuth();
      if (authOk) {
        await checkMetasploitInstallation();
        await fetchExploits();
        await fetchPayloads();
        await fetchSessions();
      } else {
        setError('Authentication required. Please log in.');
      }
    };

    initialize();
  }, []);

  // Auto-refresh sessions every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      if (isAuthenticated) {
        fetchSessions();
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [isAuthenticated]);

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <SecurityIcon />
        Metasploit Framework
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {!isAuthenticated && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Please log in to use the Metasploit Framework.
        </Alert>
      )}

      {installationStatus && !installationStatus.installed && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Metasploit Framework is not installed or not accessible. 
          Please install Metasploit Framework to use this tool.
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Exploit Configuration */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Exploit Configuration
              </Typography>
              
              <TextField
                fullWidth
                label="Target"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Enter target IP or hostname"
                sx={{ mb: 2 }}
                disabled={loading}
              />

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Exploit</InputLabel>
                <Select
                  value={selectedExploit}
                  onChange={handleExploitChange}
                  disabled={loading}
                >
                  {exploits.map((exploit) => (
                    <MenuItem key={exploit.name} value={exploit.name}>
                      <Box>
                        <Typography variant="body2" fontWeight="bold">
                          {exploit.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {exploit.description}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              {selectedExploit && (
                <Button
                  fullWidth
                  variant="outlined"
                  onClick={() => fetchExploitInfo(selectedExploit)}
                  startIcon={<InfoIcon />}
                  sx={{ mb: 2 }}
                >
                  View Exploit Info
                </Button>
              )}

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Payload</InputLabel>
                <Select
                  value={selectedPayload}
                  onChange={(e) => setSelectedPayload(e.target.value)}
                  disabled={loading}
                >
                  {payloads.map((payload) => (
                    <MenuItem key={payload.name} value={payload.name}>
                      <Box>
                        <Typography variant="body2" fontWeight="bold">
                          {payload.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {payload.description}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <Button
                fullWidth
                variant="contained"
                onClick={startExploit}
                disabled={loading || !target.trim() || !selectedExploit || !selectedPayload || !isAuthenticated}
                startIcon={<PlayIcon />}
                sx={{ mb: 1 }}
              >
                {loading ? 'Starting Exploit...' : 'Start Exploit'}
              </Button>

              <Button
                fullWidth
                variant="outlined"
                onClick={() => {
                  setExploits([]);
                  setPayloads([]);
                  fetchExploits();
                  fetchPayloads();
                }}
                disabled={loading}
                startIcon={<RefreshIcon />}
              >
                Refresh Lists
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Current Session */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Current Session
              </Typography>
              
              {currentSession ? (
                <Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="subtitle1">
                      Target: <strong>{currentSession.target}</strong>
                    </Typography>
                    <Box>
                      <Chip
                        label={currentSession.status}
                        color={
                          currentSession.status === 'running' ? 'primary' :
                          currentSession.status === 'completed' ? 'success' :
                          currentSession.status === 'failed' ? 'error' : 'default'
                        }
                        size="small"
                      />
                      {currentSession.status === 'running' && (
                        <IconButton
                          size="small"
                          onClick={() => stopSession(currentSession.session_id)}
                          color="error"
                          sx={{ ml: 1 }}
                        >
                          <StopIcon />
                        </IconButton>
                      )}
                    </Box>
                  </Box>

                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Exploit: {currentSession.exploit}<br/>
                    Payload: {currentSession.payload}
                  </Typography>

                  {currentSession.status === 'running' && (
                    <Box sx={{ mb: 2 }}>
                      <LinearProgress />
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        Exploit in progress...
                      </Typography>
                    </Box>
                  )}

                  {currentSession.output.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" gutterBottom>
                        Output ({currentSession.output.length} lines)
                      </Typography>
                      <Paper sx={{ maxHeight: 300, overflow: 'auto', p: 2, bgcolor: 'grey.900', color: 'grey.100' }}>
                        <pre style={{ margin: 0, fontSize: '12px' }}>
                          {currentSession.output.map((line, index) => (
                            <div key={index}>
                              <span style={{ color: '#888' }}>[{line.timestamp}]</span> {line.message}
                            </div>
                          ))}
                        </pre>
                      </Paper>
                    </Box>
                  )}

                  {currentSession.error && (
                    <Alert severity="error" sx={{ mt: 2 }}>
                      {currentSession.error}
                    </Alert>
                  )}
                </Box>
              ) : (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                  <BugReportIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="body1" color="text.secondary">
                    No active exploit session. Configure and start a new exploit to begin.
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Previous Sessions */}
      {sessions.length > 0 && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Previous Sessions
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Target</TableCell>
                    <TableCell>Exploit</TableCell>
                    <TableCell>Payload</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Start Time</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sessions.map((session) => (
                    <TableRow key={session.session_id}>
                      <TableCell>{session.target}</TableCell>
                      <TableCell>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                          {session.exploit}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 150 }}>
                          {session.payload}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={session.status}
                          color={
                            session.status === 'running' ? 'primary' :
                            session.status === 'completed' ? 'success' :
                            session.status === 'failed' ? 'error' : 'default'
                          }
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {new Date(session.start_time).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {session.status === 'running' && (
                          <Tooltip title="Stop Exploit">
                            <IconButton
                              size="small"
                              onClick={() => stopSession(session.session_id)}
                              color="error"
                            >
                              <StopIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}

      {/* Exploit Info Dialog */}
      <Dialog
        open={showExploitInfo}
        onClose={() => setShowExploitInfo(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CodeIcon />
            Exploit Information
          </Typography>
        </DialogTitle>
        <DialogContent>
          {exploitInfo && (
            <Box>
              <Typography variant="h6" gutterBottom>
                {exploitInfo.name}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                {exploitInfo.description}
              </Typography>

              {exploitInfo.options.length > 0 && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">Options</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {exploitInfo.options.map((option, index) => (
                        <ListItem key={index}>
                          <ListItemText
                            primary={option.name}
                            secondary={`Default: ${option.default}`}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {exploitInfo.payloads.length > 0 && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">Compatible Payloads</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {exploitInfo.payloads.map((payload, index) => (
                        <ListItem key={index}>
                          <ListItemText primary={payload} />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowExploitInfo(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default MetasploitTool; 