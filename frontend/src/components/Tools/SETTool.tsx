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
  StepContent
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
  Email as EmailIcon,
  Web as WebIcon,
  Phone as PhoneIcon,
  Computer as ComputerIcon,
  Person as PersonIcon,
  Group as GroupIcon,
  Send as SendIcon,
  Download as DownloadIcon,
  Build as BuildIcon,
  Psychology as PsychologyIcon
} from '@mui/icons-material';

interface AttackType {
  id: string;
  name: string;
  description: string;
  category: string;
}

interface AttackTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  template: {
    subject: string;
    sender: string;
    body: string;
  };
}

interface Target {
  email: string;
  name: string;
  company?: string;
  position?: string;
}

interface AttackSession {
  session_id: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  attack_type: string;
  start_time: string;
  end_time?: string;
  results: any[];
  statistics: {
    emails_sent: number;
    emails_opened: number;
    payloads_delivered: number;
    credentials_harvested: number;
    visitors: number;
    payloads_created: number;
  };
  error?: string;
}

const SETTool: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [attackTypes, setAttackTypes] = useState<AttackType[]>([]);
  const [templates, setTemplates] = useState<AttackTemplate[]>([]);
  const [sessions, setSessions] = useState<AttackSession[]>([]);
  const [currentSession, setCurrentSession] = useState<AttackSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [installationStatus, setInstallationStatus] = useState<any>(null);

  // Spear Phishing State
  const [phishingTargets, setPhishingTargets] = useState<Target[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState('');
  const [payloadType, setPayloadType] = useState('windows');
  const [smtpConfig, setSmtpConfig] = useState({
    server: 'localhost',
    port: 25,
    username: '',
    password: ''
  });

  // Web Attack State
  const [webTargetUrl, setWebTargetUrl] = useState('');
  const [webPort, setWebPort] = useState(80);
  const [webSSL, setWebSSL] = useState(false);

  // Payload Generation State
  const [payloadConfig, setPayloadConfig] = useState({
    type: 'windows',
    lhost: '',
    lport: 4444,
    encoder: '',
    iterations: 1,
    output_dir: '/tmp/set_payloads'
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

  // Check SET installation
  const checkSETInstallation = async () => {
    try {
      const response = await fetch('/api/tools/set/status', {
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
      console.error('Error checking SET installation:', error);
      setInstallationStatus({ installed: false, error: 'Network error' });
      return false;
    }
  };

  // Fetch attack types
  const fetchAttackTypes = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/set/attacks', {
        headers: getAuthHeaders()
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data.attacks && Array.isArray(data.attacks)) {
        setAttackTypes(data.attacks);
      } else {
        // Fallback to sample attack types
        setAttackTypes([
          {
            id: 'spear_phishing',
            name: 'Spear-Phishing Attack Vector',
            description: 'Send targeted phishing emails with malicious payloads',
            category: 'Email Attacks'
          },
          {
            id: 'web_attack',
            name: 'Web Attack Vector',
            description: 'Create malicious websites for credential harvesting',
            category: 'Web Attacks'
          },
          {
            id: 'infectious_media',
            name: 'Infectious Media Generator',
            description: 'Create malicious USB drives and media',
            category: 'Physical Attacks'
          },
          {
            id: 'harvester',
            name: 'Harvester Attack',
            description: 'Harvest credentials from web forms',
            category: 'Web Attacks'
          },
          {
            id: 'mass_mailer',
            name: 'Mass Mailer Attack',
            description: 'Send mass phishing emails',
            category: 'Email Attacks'
          }
        ]);
      }
    } catch (error) {
      console.error('Error fetching attack types:', error);
      setError('Failed to load attack types. Using sample data.');
    } finally {
      setLoading(false);
    }
  };

  // Fetch templates
  const fetchTemplates = async () => {
    try {
      const response = await fetch('/api/tools/set/templates', {
        headers: getAuthHeaders()
      });

      if (response.ok) {
        const data = await response.json();
        if (data.templates && Array.isArray(data.templates)) {
          setTemplates(data.templates);
        } else {
          // Fallback to sample templates
          setTemplates([
            {
              id: 'gmail_phishing',
              name: 'Gmail Phishing',
              description: 'Phishing template mimicking Gmail login',
              category: 'Email Attacks',
              template: {
                subject: 'Gmail Security Alert',
                sender: 'noreply@gmail.com',
                body: 'Your Gmail account has been compromised...'
              }
            },
            {
              id: 'linkedin_phishing',
              name: 'LinkedIn Phishing',
              description: 'Phishing template mimicking LinkedIn',
              category: 'Email Attacks',
              template: {
                subject: 'LinkedIn Security Update',
                sender: 'security@linkedin.com',
                body: 'Your LinkedIn account needs verification...'
              }
            }
          ]);
        }
      }
    } catch (error) {
      console.error('Error fetching templates:', error);
    }
  };

  // Fetch existing sessions
  const fetchSessions = async () => {
    try {
      const response = await fetch('/api/tools/set/sessions', {
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

  // Start spear-phishing attack
  const startSpearPhishing = async () => {
    if (phishingTargets.length === 0) {
      setError('Please add at least one target');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/set/attack/spear-phishing', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          targets: phishingTargets,
          payload_type: payloadType,
          email_template: selectedTemplate,
          smtp_server: smtpConfig.server,
          smtp_port: smtpConfig.port,
          smtp_username: smtpConfig.username,
          smtp_password: smtpConfig.password
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
        const newSession: AttackSession = {
          session_id: data.session_id,
          attack_type: 'spear_phishing',
          status: 'running',
          start_time: new Date().toISOString(),
          results: [],
          statistics: {
            emails_sent: 0,
            emails_opened: 0,
            payloads_delivered: 0,
            credentials_harvested: 0,
            visitors: 0,
            payloads_created: 0
          }
        };
        
        setCurrentSession(newSession);
        setSessions(prev => [newSession, ...prev]);
        
        // Start polling for updates
        pollSessionStatus(data.session_id);
      }
    } catch (error) {
      console.error('Error starting spear-phishing attack:', error);
      setError('Failed to start attack. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Start web attack
  const startWebAttack = async () => {
    if (!webTargetUrl.trim()) {
      setError('Please enter a target URL');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/set/attack/web-attack', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          target_url: webTargetUrl.trim(),
          port: webPort,
          ssl: webSSL
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data.session_id) {
        const newSession: AttackSession = {
          session_id: data.session_id,
          attack_type: 'web_attack',
          status: 'running',
          start_time: new Date().toISOString(),
          results: [],
          statistics: {
            emails_sent: 0,
            emails_opened: 0,
            payloads_delivered: 0,
            credentials_harvested: 0,
            visitors: 0,
            payloads_created: 0
          }
        };
        
        setCurrentSession(newSession);
        setSessions(prev => [newSession, ...prev]);
        
        pollSessionStatus(data.session_id);
      }
    } catch (error) {
      console.error('Error starting web attack:', error);
      setError('Failed to start attack. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Start payload generation
  const startPayloadGeneration = async () => {
    if (!payloadConfig.lhost.trim()) {
      setError('Please enter a listener host');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/set/attack/payload-generation', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify(payloadConfig)
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data.session_id) {
        const newSession: AttackSession = {
          session_id: data.session_id,
          attack_type: 'payload_generation',
          status: 'running',
          start_time: new Date().toISOString(),
          results: [],
          statistics: {
            emails_sent: 0,
            emails_opened: 0,
            payloads_delivered: 0,
            credentials_harvested: 0,
            visitors: 0,
            payloads_created: 0
          }
        };
        
        setCurrentSession(newSession);
        setSessions(prev => [newSession, ...prev]);
        
        pollSessionStatus(data.session_id);
      }
    } catch (error) {
      console.error('Error starting payload generation:', error);
      setError('Failed to start payload generation. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Poll session status
  const pollSessionStatus = async (sessionId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/tools/set/session/${sessionId}/status`, {
          headers: getAuthHeaders()
        });

        if (response.ok) {
          const data = await response.json();
          
          setCurrentSession(prev => {
            if (prev && prev.session_id === sessionId) {
              return {
                ...prev,
                status: data.status,
                results: data.results || prev.results,
                statistics: data.statistics || prev.statistics,
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
                  results: data.results || session.results,
                  statistics: data.statistics || session.statistics,
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
      const response = await fetch(`/api/tools/set/session/${sessionId}/stop`, {
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

  // Add phishing target
  const addPhishingTarget = () => {
    const newTarget: Target = {
      email: '',
      name: '',
      company: '',
      position: ''
    };
    setPhishingTargets(prev => [...prev, newTarget]);
  };

  // Update phishing target
  const updatePhishingTarget = (index: number, field: keyof Target, value: string) => {
    setPhishingTargets(prev => prev.map((target, i) => 
      i === index ? { ...target, [field]: value } : target
    ));
  };

  // Remove phishing target
  const removePhishingTarget = (index: number) => {
    setPhishingTargets(prev => prev.filter((_, i) => i !== index));
  };

  // Initialize component
  useEffect(() => {
    const initialize = async () => {
      const authOk = await checkAuth();
      if (authOk) {
        await checkSETInstallation();
        await fetchAttackTypes();
        await fetchTemplates();
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

  const getAttackIcon = (attackType: string) => {
    switch (attackType) {
      case 'spear_phishing': return <EmailIcon />;
      case 'web_attack': return <WebIcon />;
      case 'infectious_media': return <ComputerIcon />;
      case 'harvester': return <BugReportIcon />;
      case 'mass_mailer': return <SendIcon />;
      case 'payload_generation': return <BuildIcon />;
      default: return <SecurityIcon />;
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <PsychologyIcon />
        Social Engineer Toolkit (SET)
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {!isAuthenticated && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Please log in to use the Social Engineer Toolkit.
        </Alert>
      )}

      {installationStatus && !installationStatus.installed && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          SET is not installed or not accessible. 
          Please install SET to use this tool.
        </Alert>
      )}

      <Tabs value={activeTab} onChange={(_, newValue) => setActiveTab(newValue)} sx={{ mb: 3 }}>
        <Tab label="Spear Phishing" icon={<EmailIcon />} />
        <Tab label="Web Attacks" icon={<WebIcon />} />
        <Tab label="Payload Generation" icon={<BuildIcon />} />
        <Tab label="Sessions" icon={<GroupIcon />} />
      </Tabs>

      {/* Spear Phishing Tab */}
      {activeTab === 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Spear-Phishing Attack Configuration
            </Typography>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Targets
                </Typography>
                
                {phishingTargets.map((target, index) => (
                  <Box key={index} sx={{ mb: 2, p: 2, border: '1px solid #ddd', borderRadius: 1 }}>
                    <Grid container spacing={2}>
                      <Grid item xs={12} sm={6}>
                        <TextField
                          fullWidth
                          label="Email"
                          value={target.email}
                          onChange={(e) => updatePhishingTarget(index, 'email', e.target.value)}
                          size="small"
                        />
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <TextField
                          fullWidth
                          label="Name"
                          value={target.name}
                          onChange={(e) => updatePhishingTarget(index, 'name', e.target.value)}
                          size="small"
                        />
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <TextField
                          fullWidth
                          label="Company"
                          value={target.company || ''}
                          onChange={(e) => updatePhishingTarget(index, 'company', e.target.value)}
                          size="small"
                        />
                      </Grid>
                      <Grid item xs={12} sm={6}>
                        <TextField
                          fullWidth
                          label="Position"
                          value={target.position || ''}
                          onChange={(e) => updatePhishingTarget(index, 'position', e.target.value)}
                          size="small"
                        />
                      </Grid>
                    </Grid>
                    <Button
                      size="small"
                      color="error"
                      onClick={() => removePhishingTarget(index)}
                      sx={{ mt: 1 }}
                    >
                      Remove
                    </Button>
                  </Box>
                ))}

                <Button
                  variant="outlined"
                  onClick={addPhishingTarget}
                  startIcon={<PersonIcon />}
                  sx={{ mb: 2 }}
                >
                  Add Target
                </Button>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Attack Configuration
                </Typography>

                <FormControl fullWidth sx={{ mb: 2 }}>
                  <InputLabel>Email Template</InputLabel>
                  <Select
                    value={selectedTemplate}
                    onChange={(e) => setSelectedTemplate(e.target.value)}
                  >
                    {templates.map((template) => (
                      <MenuItem key={template.id} value={template.id}>
                        {template.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>

                <FormControl fullWidth sx={{ mb: 2 }}>
                  <InputLabel>Payload Type</InputLabel>
                  <Select
                    value={payloadType}
                    onChange={(e) => setPayloadType(e.target.value)}
                  >
                    <MenuItem value="windows">Windows</MenuItem>
                    <MenuItem value="linux">Linux</MenuItem>
                    <MenuItem value="mac">macOS</MenuItem>
                    <MenuItem value="android">Android</MenuItem>
                  </Select>
                </FormControl>

                <Typography variant="subtitle2" gutterBottom>
                  SMTP Configuration
                </Typography>
                
                <TextField
                  fullWidth
                  label="SMTP Server"
                  value={smtpConfig.server}
                  onChange={(e) => setSmtpConfig(prev => ({ ...prev, server: e.target.value }))}
                  size="small"
                  sx={{ mb: 1 }}
                />
                
                <TextField
                  fullWidth
                  label="SMTP Port"
                  type="number"
                  value={smtpConfig.port}
                  onChange={(e) => setSmtpConfig(prev => ({ ...prev, port: parseInt(e.target.value) }))}
                  size="small"
                  sx={{ mb: 1 }}
                />
                
                <TextField
                  fullWidth
                  label="Username"
                  value={smtpConfig.username}
                  onChange={(e) => setSmtpConfig(prev => ({ ...prev, username: e.target.value }))}
                  size="small"
                  sx={{ mb: 1 }}
                />
                
                <TextField
                  fullWidth
                  label="Password"
                  type="password"
                  value={smtpConfig.password}
                  onChange={(e) => setSmtpConfig(prev => ({ ...prev, password: e.target.value }))}
                  size="small"
                  sx={{ mb: 2 }}
                />

                <Button
                  fullWidth
                  variant="contained"
                  onClick={startSpearPhishing}
                  disabled={loading || phishingTargets.length === 0 || !isAuthenticated}
                  startIcon={<SendIcon />}
                >
                  {loading ? 'Starting Attack...' : 'Start Spear-Phishing Attack'}
                </Button>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Web Attacks Tab */}
      {activeTab === 1 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Web Attack Configuration
            </Typography>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Target URL"
                  value={webTargetUrl}
                  onChange={(e) => setWebTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  sx={{ mb: 2 }}
                />

                <TextField
                  fullWidth
                  label="Port"
                  type="number"
                  value={webPort}
                  onChange={(e) => setWebPort(parseInt(e.target.value))}
                  sx={{ mb: 2 }}
                />

                <FormControlLabel
                  control={
                    <Switch
                      checked={webSSL}
                      onChange={(e) => setWebSSL(e.target.checked)}
                    />
                  }
                  label="Use SSL"
                  sx={{ mb: 2 }}
                />

                <Button
                  fullWidth
                  variant="contained"
                  onClick={startWebAttack}
                  disabled={loading || !webTargetUrl.trim() || !isAuthenticated}
                  startIcon={<WebIcon />}
                >
                  {loading ? 'Starting Attack...' : 'Start Web Attack'}
                </Button>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Attack Information
                </Typography>
                
                <Alert severity="info" sx={{ mb: 2 }}>
                  This attack will create a malicious website that mimics the target site
                  to harvest credentials from unsuspecting users.
                </Alert>

                <Typography variant="body2" color="text.secondary">
                  • Creates a clone of the target website
                  • Harvests login credentials
                  • Tracks visitor statistics
                  • Provides real-time monitoring
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Payload Generation Tab */}
      {activeTab === 2 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Payload Generation
            </Typography>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth sx={{ mb: 2 }}>
                  <InputLabel>Payload Type</InputLabel>
                  <Select
                    value={payloadConfig.type}
                    onChange={(e) => setPayloadConfig(prev => ({ ...prev, type: e.target.value }))}
                  >
                    <MenuItem value="windows">Windows</MenuItem>
                    <MenuItem value="linux">Linux</MenuItem>
                    <MenuItem value="mac">macOS</MenuItem>
                    <MenuItem value="android">Android</MenuItem>
                  </Select>
                </FormControl>

                <TextField
                  fullWidth
                  label="Listener Host (LHOST)"
                  value={payloadConfig.lhost}
                  onChange={(e) => setPayloadConfig(prev => ({ ...prev, lhost: e.target.value }))}
                  placeholder="192.168.1.100"
                  sx={{ mb: 2 }}
                />

                <TextField
                  fullWidth
                  label="Listener Port (LPORT)"
                  type="number"
                  value={payloadConfig.lport}
                  onChange={(e) => setPayloadConfig(prev => ({ ...prev, lport: parseInt(e.target.value) }))}
                  sx={{ mb: 2 }}
                />

                <TextField
                  fullWidth
                  label="Encoder"
                  value={payloadConfig.encoder}
                  onChange={(e) => setPayloadConfig(prev => ({ ...prev, encoder: e.target.value }))}
                  placeholder="shikata_ga_nai"
                  sx={{ mb: 2 }}
                />

                <TextField
                  fullWidth
                  label="Iterations"
                  type="number"
                  value={payloadConfig.iterations}
                  onChange={(e) => setPayloadConfig(prev => ({ ...prev, iterations: parseInt(e.target.value) }))}
                  sx={{ mb: 2 }}
                />

                <TextField
                  fullWidth
                  label="Output Directory"
                  value={payloadConfig.output_dir}
                  onChange={(e) => setPayloadConfig(prev => ({ ...prev, output_dir: e.target.value }))}
                  sx={{ mb: 2 }}
                />

                <Button
                  fullWidth
                  variant="contained"
                  onClick={startPayloadGeneration}
                  disabled={loading || !payloadConfig.lhost.trim() || !isAuthenticated}
                  startIcon={<BuildIcon />}
                >
                  {loading ? 'Generating Payloads...' : 'Generate Payloads'}
                </Button>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Payload Information
                </Typography>
                
                <Alert severity="warning" sx={{ mb: 2 }}>
                  Generated payloads are for educational and authorized testing purposes only.
                </Alert>

                <Typography variant="body2" color="text.secondary">
                  • Creates malicious executables
                  • Supports multiple platforms
                  • Includes encoding options
                  • Configurable listener settings
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Sessions Tab */}
      {activeTab === 3 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Attack Sessions
            </Typography>

            {sessions.length > 0 ? (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Attack Type</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Start Time</TableCell>
                      <TableCell>Statistics</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {sessions.map((session) => (
                      <TableRow key={session.session_id}>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {getAttackIcon(session.attack_type)}
                            {session.attack_type.replace('_', ' ').toUpperCase()}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={session.status}
                            color={getStatusColor(session.status) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          {new Date(session.start_time).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <Box>
                            <Typography variant="caption" display="block">
                              Emails: {session.statistics.emails_sent}
                            </Typography>
                            <Typography variant="caption" display="block">
                              Credentials: {session.statistics.credentials_harvested}
                            </Typography>
                            <Typography variant="caption" display="block">
                              Payloads: {session.statistics.payloads_created}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          {session.status === 'running' && (
                            <Tooltip title="Stop Attack">
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
                <SecurityIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                <Typography variant="body1" color="text.secondary">
                  No attack sessions found. Start an attack to see sessions here.
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
              Current Session: {currentSession.attack_type.replace('_', ' ').toUpperCase()}
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
                  Stop Attack
                </Button>
              )}
            </Box>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Statistics
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  <Chip label={`Emails: ${currentSession.statistics.emails_sent}`} size="small" />
                  <Chip label={`Opened: ${currentSession.statistics.emails_opened}`} size="small" />
                  <Chip label={`Payloads: ${currentSession.statistics.payloads_delivered}`} size="small" />
                  <Chip label={`Credentials: ${currentSession.statistics.credentials_harvested}`} size="small" />
                  <Chip label={`Visitors: ${currentSession.statistics.visitors}`} size="small" />
                  <Chip label={`Created: ${currentSession.statistics.payloads_created}`} size="small" />
                </Box>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Session Info
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

export default SETTool; 