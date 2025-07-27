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
  FormControlLabel,
  Badge
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
  Code as CodeIcon,
  Warning as WarningIcon,
  Report as ReportIcon,
  Visibility as VisibilityIcon
} from '@mui/icons-material';

interface ScanType {
  id: string;
  name: string;
  description: string;
}

interface Vulnerability {
  name: string;
  risk: string;
  confidence: string;
  description: string;
  solution: string;
  reference: string;
  evidence: string;
  cweid: string;
  wascid: string;
}

interface ScanSession {
  session_id: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  target_url: string;
  scan_type: string;
  progress: number;
  start_time: string;
  end_time?: string;
  alerts: Vulnerability[];
  results: any;
  error?: string;
}

interface VulnerabilitySummary {
  session_id: string;
  total_alerts: number;
  risk_breakdown: {
    High: number;
    Medium: number;
    Low: number;
    Informational: number;
  };
  high_risk_alerts: Vulnerability[];
  medium_risk_alerts: Vulnerability[];
}

const ZAPTool: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [selectedScanType, setSelectedScanType] = useState('');
  const [scanTypes, setScanTypes] = useState<ScanType[]>([]);
  const [sessions, setSessions] = useState<ScanSession[]>([]);
  const [currentSession, setCurrentSession] = useState<ScanSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [installationStatus, setInstallationStatus] = useState<any>(null);
  const [vulnerabilitySummary, setVulnerabilitySummary] = useState<VulnerabilitySummary | null>(null);
  const [showVulnerabilityDetails, setShowVulnerabilityDetails] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);

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

  // Check ZAP installation
  const checkZAPInstallation = async () => {
    try {
      const response = await fetch('/api/tools/zap/status', {
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
      console.error('Error checking ZAP installation:', error);
      setInstallationStatus({ installed: false, error: 'Network error' });
      return false;
    }
  };

  // Fetch scan types
  const fetchScanTypes = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/zap/scan-types', {
        headers: getAuthHeaders()
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data.scan_types && Array.isArray(data.scan_types)) {
        setScanTypes(data.scan_types);
      } else {
        // Fallback to sample scan types
        setScanTypes([
          {
            id: 'spider',
            name: 'Spider Scan',
            description: 'Crawl the website to discover pages and resources'
          },
          {
            id: 'active',
            name: 'Active Scan',
            description: 'Actively test for vulnerabilities by sending malicious requests'
          },
          {
            id: 'full',
            name: 'Full Scan',
            description: 'Complete spider and active scan combination'
          },
          {
            id: 'baseline',
            name: 'Baseline Scan',
            description: 'Quick passive scan for common vulnerabilities'
          }
        ]);
      }
    } catch (error) {
      console.error('Error fetching scan types:', error);
      setError('Failed to load scan types. Using sample data.');
      setScanTypes([
        {
          id: 'spider',
          name: 'Spider Scan',
          description: 'Crawl the website to discover pages and resources'
        },
        {
          id: 'active',
          name: 'Active Scan',
          description: 'Actively test for vulnerabilities by sending malicious requests'
        },
        {
          id: 'full',
          name: 'Full Scan',
          description: 'Complete spider and active scan combination'
        },
        {
          id: 'baseline',
          name: 'Baseline Scan',
          description: 'Quick passive scan for common vulnerabilities'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  // Fetch existing sessions
  const fetchSessions = async () => {
    try {
      const response = await fetch('/api/tools/zap/sessions', {
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

  // Start a new scan
  const startScan = async () => {
    if (!targetUrl.trim()) {
      setError('Please enter a target URL');
      return;
    }

    if (!selectedScanType) {
      setError('Please select a scan type');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/zap/scan/start', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          scan_type: selectedScanType,
          options: {}
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
        const newSession: ScanSession = {
          session_id: data.session_id,
          target_url: targetUrl.trim(),
          scan_type: selectedScanType,
          status: 'running',
          progress: 0,
          start_time: new Date().toISOString(),
          alerts: [],
          results: {}
        };
        
        setCurrentSession(newSession);
        setSessions(prev => [newSession, ...prev]);
        
        // Start polling for updates
        pollSessionStatus(data.session_id);
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      setError('Failed to start scan. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Poll session status
  const pollSessionStatus = async (sessionId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/tools/zap/session/${sessionId}/status`, {
          headers: getAuthHeaders()
        });

        if (response.ok) {
          const data = await response.json();
          
          setCurrentSession(prev => {
            if (prev && prev.session_id === sessionId) {
              return {
                ...prev,
                status: data.status,
                progress: data.progress || prev.progress,
                alerts: data.alerts || prev.alerts,
                results: data.results || prev.results,
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
                  progress: data.progress || session.progress,
                  alerts: data.alerts || session.alerts,
                  results: data.results || session.results,
                  end_time: data.end_time,
                  error: data.error
                }
              : session
          ));

          // Stop polling if session is complete
          if (data.status === 'completed' || data.status === 'failed' || data.status === 'stopped') {
            clearInterval(pollInterval);
            // Fetch vulnerability summary
            fetchVulnerabilitySummary(sessionId);
          }
        }
      } catch (error) {
        console.error('Error polling session status:', error);
      }
    }, 3000); // Poll every 3 seconds

    // Cleanup after 30 minutes
    setTimeout(() => {
      clearInterval(pollInterval);
    }, 1800000);
  };

  // Fetch vulnerability summary
  const fetchVulnerabilitySummary = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/tools/zap/session/${sessionId}/vulnerabilities`, {
        headers: getAuthHeaders()
      });

      if (response.ok) {
        const summary = await response.json();
        setVulnerabilitySummary(summary);
      }
    } catch (error) {
      console.error('Error fetching vulnerability summary:', error);
    }
  };

  // Stop a scan session
  const stopSession = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/tools/zap/session/${sessionId}/stop`, {
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

  // Handle scan type selection
  const handleScanTypeChange = (event: any) => {
    setSelectedScanType(event.target.value);
  };

  // Initialize component
  useEffect(() => {
    const initialize = async () => {
      const authOk = await checkAuth();
      if (authOk) {
        await checkZAPInstallation();
        await fetchScanTypes();
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

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'High': return 'error';
      case 'Medium': return 'warning';
      case 'Low': return 'info';
      default: return 'default';
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <SecurityIcon />
        OWASP ZAP Web Application Scanner
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {!isAuthenticated && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Please log in to use the OWASP ZAP scanner.
        </Alert>
      )}

      {installationStatus && !installationStatus.installed && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          OWASP ZAP is not installed or not accessible. 
          Please install OWASP ZAP to use this tool.
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Scan Configuration */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Scan Configuration
              </Typography>
              
              <TextField
                fullWidth
                label="Target URL"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                sx={{ mb: 2 }}
                disabled={loading}
              />

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Scan Type</InputLabel>
                <Select
                  value={selectedScanType}
                  onChange={handleScanTypeChange}
                  disabled={loading}
                >
                  {scanTypes.map((scanType) => (
                    <MenuItem key={scanType.id} value={scanType.id}>
                      <Box>
                        <Typography variant="body2" fontWeight="bold">
                          {scanType.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {scanType.description}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <Button
                fullWidth
                variant="contained"
                onClick={startScan}
                disabled={loading || !targetUrl.trim() || !selectedScanType || !isAuthenticated}
                startIcon={<PlayIcon />}
                sx={{ mb: 1 }}
              >
                {loading ? 'Starting Scan...' : 'Start Scan'}
              </Button>

              <Button
                fullWidth
                variant="outlined"
                onClick={() => {
                  setScanTypes([]);
                  fetchScanTypes();
                }}
                disabled={loading}
                startIcon={<RefreshIcon />}
              >
                Refresh Scan Types
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Current Session */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Current Scan
              </Typography>
              
              {currentSession ? (
                <Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="subtitle1">
                      Target: <strong>{currentSession.target_url}</strong>
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
                    Scan Type: {currentSession.scan_type}
                  </Typography>

                  {currentSession.status === 'running' && (
                    <Box sx={{ mb: 2 }}>
                      <LinearProgress 
                        variant="determinate" 
                        value={currentSession.progress} 
                        sx={{ mb: 1 }}
                      />
                      <Typography variant="body2" color="text.secondary">
                        Progress: {currentSession.progress}%
                      </Typography>
                    </Box>
                  )}

                  {currentSession.alerts.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" gutterBottom>
                        Vulnerabilities Found ({currentSession.alerts.length})
                      </Typography>
                      <Box sx={{ maxHeight: 300, overflow: 'auto' }}>
                        {currentSession.alerts.map((alert, index) => (
                          <Card key={index} sx={{ mb: 1, p: 1 }}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <Typography variant="body2" fontWeight="bold">
                                {alert.name}
                              </Typography>
                              <Chip
                                label={alert.risk}
                                color={getRiskColor(alert.risk) as any}
                                size="small"
                              />
                            </Box>
                            <Typography variant="caption" color="text.secondary">
                              {alert.description}
                            </Typography>
                          </Card>
                        ))}
                      </Box>
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
                    No active scan session. Configure and start a new scan to begin.
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Vulnerability Summary */}
      {vulnerabilitySummary && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Vulnerability Summary
            </Typography>
            
            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'error.main', color: 'white', borderRadius: 1 }}>
                  <Typography variant="h4">{vulnerabilitySummary.risk_breakdown.High}</Typography>
                  <Typography variant="body2">High Risk</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'warning.main', color: 'white', borderRadius: 1 }}>
                  <Typography variant="h4">{vulnerabilitySummary.risk_breakdown.Medium}</Typography>
                  <Typography variant="body2">Medium Risk</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'info.main', color: 'white', borderRadius: 1 }}>
                  <Typography variant="h4">{vulnerabilitySummary.risk_breakdown.Low}</Typography>
                  <Typography variant="body2">Low Risk</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'grey.500', color: 'white', borderRadius: 1 }}>
                  <Typography variant="h4">{vulnerabilitySummary.risk_breakdown.Informational}</Typography>
                  <Typography variant="body2">Informational</Typography>
                </Box>
              </Grid>
            </Grid>

            {vulnerabilitySummary.high_risk_alerts.length > 0 && (
              <Box sx={{ mt: 3 }}>
                <Typography variant="h6" color="error" gutterBottom>
                  High Risk Vulnerabilities
                </Typography>
                <TableContainer component={Paper}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Vulnerability</TableCell>
                        <TableCell>Confidence</TableCell>
                        <TableCell>Description</TableCell>
                        <TableCell>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {vulnerabilitySummary.high_risk_alerts.map((alert, index) => (
                        <TableRow key={index}>
                          <TableCell>{alert.name}</TableCell>
                          <TableCell>
                            <Chip label={alert.confidence} size="small" />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                              {alert.description}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <IconButton
                              size="small"
                              onClick={() => {
                                setSelectedVulnerability(alert);
                                setShowVulnerabilityDetails(true);
                              }}
                            >
                              <VisibilityIcon />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      {/* Previous Sessions */}
      {sessions.length > 0 && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Previous Scans
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Target URL</TableCell>
                    <TableCell>Scan Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Progress</TableCell>
                    <TableCell>Start Time</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sessions.map((session) => (
                    <TableRow key={session.session_id}>
                      <TableCell>
                        <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                          {session.target_url}
                        </Typography>
                      </TableCell>
                      <TableCell>{session.scan_type}</TableCell>
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
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <Box sx={{ width: '100%', mr: 1 }}>
                            <LinearProgress variant="determinate" value={session.progress} />
                          </Box>
                          <Box sx={{ minWidth: 35 }}>
                            <Typography variant="body2" color="text.secondary">
                              {session.progress}%
                            </Typography>
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>
                        {new Date(session.start_time).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {session.status === 'running' && (
                          <Tooltip title="Stop Scan">
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

      {/* Vulnerability Details Dialog */}
      <Dialog
        open={showVulnerabilityDetails}
        onClose={() => setShowVulnerabilityDetails(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <WarningIcon color="error" />
            Vulnerability Details
          </Typography>
        </DialogTitle>
        <DialogContent>
          {selectedVulnerability && (
            <Box>
              <Typography variant="h6" gutterBottom>
                {selectedVulnerability.name}
              </Typography>
              
              <Box sx={{ mb: 2 }}>
                <Chip
                  label={selectedVulnerability.risk}
                  color={getRiskColor(selectedVulnerability.risk) as any}
                  sx={{ mr: 1 }}
                />
                <Chip
                  label={selectedVulnerability.confidence}
                  variant="outlined"
                />
              </Box>

              <Typography variant="subtitle1" gutterBottom>
                Description
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                {selectedVulnerability.description}
              </Typography>

              <Typography variant="subtitle1" gutterBottom>
                Solution
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                {selectedVulnerability.solution}
              </Typography>

              {selectedVulnerability.evidence && (
                <>
                  <Typography variant="subtitle1" gutterBottom>
                    Evidence
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'grey.100', mb: 2 }}>
                    <Typography variant="body2" fontFamily="monospace">
                      {selectedVulnerability.evidence}
                    </Typography>
                  </Paper>
                </>
              )}

              {selectedVulnerability.reference && (
                <>
                  <Typography variant="subtitle1" gutterBottom>
                    Reference
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    {selectedVulnerability.reference}
                  </Typography>
                </>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowVulnerabilityDetails(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ZAPTool; 