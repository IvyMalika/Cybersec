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
  Badge,
  Tabs,
  Tab,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Slider,
  InputAdornment
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
  Visibility as VisibilityIcon,
  School as SchoolIcon,
  Speed as SpeedIcon,
  Timer as TimerIcon,
  NetworkCheck as NetworkCheckIcon,
  Send as SendIcon,
  Download as DownloadIcon,
  Build as BuildIcon,
  Psychology as PsychologyIcon,
  Gavel as GavelIcon,
  Security as SecurityIcon
} from '@mui/icons-material';

interface ReportType {
  id: string;
  name: string;
  description: string;
  reasons: string[];
}

interface CampaignSession {
  session_id: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  target_url: string;
  report_type: string;
  start_time: string;
  end_time?: string;
  statistics: {
    reports_sent: number;
    reports_successful: number;
    reports_failed: number;
    errors: any[];
  };
  results: any[];
  error?: string;
}

interface EducationalInfo {
  purpose: string;
  disclaimer: string;
  ethical_guidelines: string[];
  learning_objectives: string[];
  legal_notice: string;
}

const MassReportTool: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [reportTypes, setReportTypes] = useState<ReportType[]>([]);
  const [sessions, setSessions] = useState<CampaignSession[]>([]);
  const [currentSession, setCurrentSession] = useState<CampaignSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [educationalInfo, setEducationalInfo] = useState<EducationalInfo | null>(null);

  // Campaign Configuration State
  const [campaignConfig, setCampaignConfig] = useState({
    target_url: '',
    report_type: 'spam',
    report_reason: '',
    user_agent: '',
    proxy_list: [] as string[],
    delay_min: 1.0,
    delay_max: 3.0,
    max_reports: 100,
    timeout: 30,
    use_proxies: false,
    rotate_user_agents: true
  });

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

  // Fetch report types
  const fetchReportTypes = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/mass-report/report-types', {
        headers: getAuthHeaders()
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data.report_types && Array.isArray(data.report_types)) {
        setReportTypes(data.report_types);
      } else {
        // Fallback to sample report types
        setReportTypes([
          {
            id: 'spam',
            name: 'Spam or misleading content',
            description: 'Report for spam or misleading content',
            reasons: ['This content appears to be spam or misleading', 'Unsolicited promotional content']
          },
          {
            id: 'harassment',
            name: 'Harassment or bullying',
            description: 'Report for harassment or bullying',
            reasons: ['Content that harasses or bullies individuals', 'Hate speech or discriminatory content']
          },
          {
            id: 'violence',
            name: 'Violence or dangerous organizations',
            description: 'Report for violence or dangerous organizations',
            reasons: ['Content promoting violence or harm', 'Dangerous organization promotion']
          }
        ]);
      }
    } catch (error) {
      console.error('Error fetching report types:', error);
      setError('Failed to load report types. Using sample data.');
    } finally {
      setLoading(false);
    }
  };

  // Fetch educational information
  const fetchEducationalInfo = async () => {
    try {
      const response = await fetch('/api/tools/mass-report/educational-info', {
        headers: getAuthHeaders()
      });

      if (response.ok) {
        const data = await response.json();
        setEducationalInfo(data);
      }
    } catch (error) {
      console.error('Error fetching educational info:', error);
    }
  };

  // Fetch existing sessions
  const fetchSessions = async () => {
    try {
      const response = await fetch('/api/tools/mass-report/sessions', {
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

  // Start mass report campaign
  const startCampaign = async () => {
    if (!campaignConfig.target_url.trim()) {
      setError('Please enter a target URL');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/mass-report/campaign/start', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(campaignConfig)
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
        const newSession: CampaignSession = {
          session_id: data.session_id,
          target_url: campaignConfig.target_url,
          report_type: campaignConfig.report_type,
          status: 'running',
          start_time: new Date().toISOString(),
          statistics: {
            reports_sent: 0,
            reports_successful: 0,
            reports_failed: 0,
            errors: []
          },
          results: []
        };
        
        setCurrentSession(newSession);
        setSessions(prev => [newSession, ...prev]);
        
        // Start polling for updates
        pollSessionStatus(data.session_id);
      }
    } catch (error) {
      console.error('Error starting campaign:', error);
      setError('Failed to start campaign. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Poll session status
  const pollSessionStatus = async (sessionId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/tools/mass-report/session/${sessionId}/status`, {
          headers: getAuthHeaders()
        });

        if (response.ok) {
          const data = await response.json();
          
          setCurrentSession(prev => {
            if (prev && prev.session_id === sessionId) {
              return {
                ...prev,
                status: data.status,
                statistics: data.statistics || prev.statistics,
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
                  statistics: data.statistics || session.statistics,
                  results: data.results || session.results,
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
    }, 3000); // Poll every 3 seconds

    // Cleanup after 30 minutes
    setTimeout(() => {
      clearInterval(pollInterval);
    }, 1800000);
  };

  // Stop a session
  const stopSession = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/tools/mass-report/session/${sessionId}/stop`, {
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

  // Handle campaign config changes
  const handleConfigChange = (field: string, value: any) => {
    setCampaignConfig(prev => ({ ...prev, [field]: value }));
  };

  // Initialize component
  useEffect(() => {
    const initialize = async () => {
      const authOk = await checkAuth();
      if (authOk) {
        await fetchReportTypes();
        await fetchEducationalInfo();
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'primary';
      case 'completed': return 'success';
      case 'failed': return 'error';
      case 'stopped': return 'default';
      default: return 'default';
    }
  };

  const getSuccessRate = (statistics: any) => {
    if (statistics.reports_sent === 0) return 0;
    return (statistics.reports_successful / statistics.reports_sent) * 100;
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <GavelIcon />
        Mass Report Tool (Educational)
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {!isAuthenticated && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Please log in to use the Mass Report Tool.
        </Alert>
      )}

      {educationalInfo && (
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="subtitle2" gutterBottom>
            <SchoolIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Educational Purpose Only
          </Typography>
          <Typography variant="body2">
            {educationalInfo.disclaimer}
          </Typography>
        </Alert>
      )}

      <Tabs value={activeTab} onChange={(_, newValue) => setActiveTab(newValue)} sx={{ mb: 3 }}>
        <Tab label="Campaign Setup" icon={<SettingsIcon />} />
        <Tab label="Educational Info" icon={<SchoolIcon />} />
        <Tab label="Sessions" icon={<ReportIcon />} />
      </Tabs>

      {/* Campaign Setup Tab */}
      {activeTab === 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Mass Report Campaign Configuration
            </Typography>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Target Configuration
                </Typography>
                
                <TextField
                  fullWidth
                  label="Target URL"
                  value={campaignConfig.target_url}
                  onChange={(e) => handleConfigChange('target_url', e.target.value)}
                  placeholder="https://example.com"
                  sx={{ mb: 2 }}
                />

                <FormControl fullWidth sx={{ mb: 2 }}>
                  <InputLabel>Report Type</InputLabel>
                  <Select
                    value={campaignConfig.report_type}
                    onChange={(e) => handleConfigChange('report_type', e.target.value)}
                  >
                    {reportTypes.map((reportType) => (
                      <MenuItem key={reportType.id} value={reportType.id}>
                            <Box>
                              <Typography variant="body2" fontWeight="bold">
                                {reportType.name}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {reportType.description}
                              </Typography>
                            </Box>
                          </MenuItem>
                    ))}
                  </Select>
                </FormControl>

                <TextField
                  fullWidth
                  label="Report Reason (Optional)"
                  value={campaignConfig.report_reason}
                  onChange={(e) => handleConfigChange('report_reason', e.target.value)}
                  placeholder="Custom reason for reporting"
                  multiline
                  rows={3}
                  sx={{ mb: 2 }}
                />

                <TextField
                  fullWidth
                  label="Custom User Agent (Optional)"
                  value={campaignConfig.user_agent}
                  onChange={(e) => handleConfigChange('user_agent', e.target.value)}
                  placeholder="Mozilla/5.0..."
                  sx={{ mb: 2 }}
                />
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Campaign Settings
                </Typography>

                <TextField
                  fullWidth
                  label="Maximum Reports"
                  type="number"
                  value={campaignConfig.max_reports}
                  onChange={(e) => handleConfigChange('max_reports', parseInt(e.target.value))}
                  sx={{ mb: 2 }}
                />

                <Typography gutterBottom>
                  Delay Range (seconds)
                </Typography>
                <Box sx={{ px: 2, mb: 2 }}>
                  <Slider
                    value={[campaignConfig.delay_min, campaignConfig.delay_max]}
                    onChange={(_, value) => {
                      const [min, max] = value as number[];
                      handleConfigChange('delay_min', min);
                      handleConfigChange('delay_max', max);
                    }}
                    valueLabelDisplay="auto"
                    min={0.1}
                    max={10}
                    step={0.1}
                  />
                  <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                    <Typography variant="caption">{campaignConfig.delay_min}s</Typography>
                    <Typography variant="caption">{campaignConfig.delay_max}s</Typography>
                  </Box>
                </Box>

                <TextField
                  fullWidth
                  label="Timeout (seconds)"
                  type="number"
                  value={campaignConfig.timeout}
                  onChange={(e) => handleConfigChange('timeout', parseInt(e.target.value))}
                  sx={{ mb: 2 }}
                />

                <FormControlLabel
                  control={
                    <Switch
                      checked={campaignConfig.rotate_user_agents}
                      onChange={(e) => handleConfigChange('rotate_user_agents', e.target.checked)}
                    />
                  }
                  label="Rotate User Agents"
                  sx={{ mb: 1 }}
                />

                <FormControlLabel
                  control={
                    <Switch
                      checked={campaignConfig.use_proxies}
                      onChange={(e) => handleConfigChange('use_proxies', e.target.checked)}
                    />
                  }
                  label="Use Proxies"
                  sx={{ mb: 2 }}
                />

                <Button
                  fullWidth
                  variant="contained"
                  onClick={startCampaign}
                  disabled={loading || !campaignConfig.target_url.trim() || !isAuthenticated}
                  startIcon={<SendIcon />}
                >
                  {loading ? 'Starting Campaign...' : 'Start Mass Report Campaign'}
                </Button>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Educational Info Tab */}
      {activeTab === 1 && educationalInfo && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Educational Information
            </Typography>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Purpose & Disclaimer
                </Typography>
                
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    {educationalInfo.purpose}
                  </Typography>
                </Alert>

                <Typography variant="body2" sx={{ mb: 2 }}>
                  {educationalInfo.disclaimer}
                </Typography>

                <Typography variant="subtitle1" gutterBottom>
                  Learning Objectives
                </Typography>
                <List dense>
                  {educationalInfo.learning_objectives.map((objective, index) => (
                    <ListItem key={index}>
                      <ListItemText primary={objective} />
                    </ListItem>
                  ))}
                </List>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Ethical Guidelines
                </Typography>
                
                <Alert severity="warning" sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    {educationalInfo.legal_notice}
                  </Typography>
                </Alert>

                <List dense>
                  {educationalInfo.ethical_guidelines.map((guideline, index) => (
                    <ListItem key={index}>
                      <ListItemText primary={guideline} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Sessions Tab */}
      {activeTab === 2 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Campaign Sessions
            </Typography>

            {sessions.length > 0 ? (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Target URL</TableCell>
                      <TableCell>Report Type</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Statistics</TableCell>
                      <TableCell>Success Rate</TableCell>
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
                        <TableCell>
                          <Chip label={session.report_type} size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={session.status}
                            color={getStatusColor(session.status) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Box>
                            <Typography variant="caption" display="block">
                              Sent: {session.statistics.reports_sent}
                            </Typography>
                            <Typography variant="caption" display="block">
                              Success: {session.statistics.reports_successful}
                            </Typography>
                            <Typography variant="caption" display="block">
                              Failed: {session.statistics.reports_failed}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {getSuccessRate(session.statistics).toFixed(1)}%
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {session.status === 'running' && (
                            <Tooltip title="Stop Campaign">
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
            ) : (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <ReportIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                <Typography variant="body1" color="text.secondary">
                  No campaign sessions found. Start a campaign to see sessions here.
                </Typography>
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      {/* Current Session Display */}
      {currentSession && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Current Campaign: {currentSession.report_type.toUpperCase()}
            </Typography>
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="subtitle1">
                Status: <strong>{currentSession.status}</strong>
              </Typography>
              {currentSession.status === 'running' && (
                <Button
                  variant="outlined"
                  color="error"
                  onClick={() => stopSession(currentSession.session_id)}
                  startIcon={<StopIcon />}
                >
                  Stop Campaign
                </Button>
              )}
            </Box>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Statistics
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  <Chip label={`Sent: ${currentSession.statistics.reports_sent}`} size="small" />
                  <Chip label={`Success: ${currentSession.statistics.reports_successful}`} size="small" color="success" />
                  <Chip label={`Failed: ${currentSession.statistics.reports_failed}`} size="small" color="error" />
                  <Chip label={`Rate: ${getSuccessRate(currentSession.statistics).toFixed(1)}%`} size="small" />
                </Box>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Session Info
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Target: {currentSession.target_url}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Start: {new Date(currentSession.start_time).toLocaleString()}
                </Typography>
                {currentSession.end_time && (
                  <Typography variant="body2" color="text.secondary">
                    End: {new Date(currentSession.end_time).toLocaleString()}
                  </Typography>
                )}
              </Grid>
            </Grid>

            {currentSession.error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {currentSession.error}
              </Alert>
            )}
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default MassReportTool; 