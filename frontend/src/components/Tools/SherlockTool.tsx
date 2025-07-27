import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Alert,
  Chip,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  OutlinedInput,
  Checkbox,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  Fade,
  LinearProgress
} from '@mui/material';
import {
  Search as SearchIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Info as InfoIcon,
  Security as SecurityIcon,
  Person as PersonIcon,
  Web as WebIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  ExpandMore as ExpandMoreIcon
} from '@mui/icons-material';

interface SherlockResult {
  username: string;
  name: string;
  url_main: string;
  url_user: string;
  exists: string;
  category: string;
  http_status: number;
  response_time_ms: number;
  domain: string;
}

interface SherlockSession {
  session_id: string;
  username: string;
  status: 'running' | 'completed' | 'error' | 'timeout' | 'stopped';
  start_time: string;
  end_time?: string;
  results: SherlockResult[];
  platforms: string | string[];
  error?: string;
}

const SherlockTool: React.FC = () => {
  const [username, setUsername] = useState('');
  const [selectedPlatforms, setSelectedPlatforms] = useState<string[]>([]);
  const [availablePlatforms, setAvailablePlatforms] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentSession, setCurrentSession] = useState<SherlockSession | null>(null);
  const [sessions, setSessions] = useState<SherlockSession[]>([]);
  const [showPlatformsDialog, setShowPlatformsDialog] = useState(false);
  const [timeout, setTimeout] = useState(300);

  // Popular platforms for quick selection
  const popularPlatforms = [
    'Twitter', 'Instagram', 'Facebook', 'LinkedIn', 'GitHub', 
    'YouTube', 'Reddit', 'TikTok', 'Snapchat', 'Pinterest'
  ];

  // Helper function to get auth headers
  const getAuthHeaders = () => {
    const token = localStorage.getItem('access_token');
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    };
  };

  useEffect(() => {
    fetchAvailablePlatforms();
    fetchSessions();
  }, []);

  const fetchAvailablePlatforms = async () => {
    try {
      const response = await fetch('/api/tools/sherlock/platforms', {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setAvailablePlatforms(data.platforms || popularPlatforms);
      } else {
        console.error('Failed to fetch platforms:', response.status);
        setAvailablePlatforms(popularPlatforms);
      }
    } catch (error) {
      console.error('Error fetching platforms:', error);
      setAvailablePlatforms(popularPlatforms);
    }
  };

  const fetchSessions = async () => {
    try {
      const response = await fetch('/api/tools/sherlock/sessions', {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setSessions(data.sessions || []);
      } else {
        console.error('Failed to fetch sessions:', response.status);
      }
    } catch (error) {
      console.error('Error fetching sessions:', error);
    }
  };

  const handleSearch = async () => {
    if (!username.trim()) {
      setError('Please enter a username to search');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/tools/sherlock/search', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          username: username.trim(),
          platforms: selectedPlatforms.length > 0 ? selectedPlatforms : undefined,
          timeout
        })
      });

      if (response.ok) {
        const session = await response.json();
        setCurrentSession(session);
        
        // Start polling for status updates
        if (session.status === 'started') {
          pollSessionStatus(session.session_id);
        }
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Failed to start search');
      }
    } catch (error: any) {
      setError(error.message || 'Failed to start search');
    } finally {
      setLoading(false);
    }
  };

  const pollSessionStatus = async (sessionId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/tools/sherlock/status/${sessionId}`, {
          headers: getAuthHeaders()
        });
        
        if (response.ok) {
          const session = await response.json();
          setCurrentSession(session);
          
          if (session.status === 'completed' || session.status === 'error' || session.status === 'timeout') {
            clearInterval(pollInterval);
            fetchSessions(); // Refresh sessions list
          }
        } else {
          console.error('Error polling session status:', response.status);
          clearInterval(pollInterval);
        }
      } catch (error) {
        console.error('Error polling session status:', error);
        clearInterval(pollInterval);
      }
    }, 2000); // Poll every 2 seconds
  };

  const handleStopSession = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/tools/sherlock/stop/${sessionId}`, {
        method: 'POST',
        headers: getAuthHeaders()
      });
      
      if (response.ok) {
        fetchSessions();
        if (currentSession?.session_id === sessionId) {
          setCurrentSession(prev => prev ? { ...prev, status: 'stopped' } : null);
        }
      } else {
        console.error('Error stopping session:', response.status);
      }
    } catch (error) {
      console.error('Error stopping session:', error);
    }
  };

  const handlePlatformChange = (event: any) => {
    const value = event.target.value;
    setSelectedPlatforms(typeof value === 'string' ? value.split(',') : value);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'primary';
      case 'completed': return 'success';
      case 'error': return 'error';
      case 'timeout': return 'warning';
      case 'stopped': return 'default';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return <CircularProgress size={16} />;
      case 'completed': return <CheckCircleIcon />;
      case 'error': return <ErrorIcon />;
      case 'timeout': return <WarningIcon />;
      case 'stopped': return <StopIcon />;
      default: return <InfoIcon />;
    }
  };

  const formatResults = (results: SherlockResult[]) => {
    const found = results.filter(r => r.exists === 'yes');
    const notFound = results.filter(r => r.exists === 'no');
    
    return { found, notFound, total: results.length };
  };

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto', p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <SecurityIcon sx={{ mr: 1 }} />
        Sherlock Username Enumeration
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">
          Sherlock is a powerful tool for finding usernames across social media platforms. 
          Enter a username to search across multiple platforms and discover where the username exists.
        </Typography>
      </Alert>

      {/* Search Form */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            <PersonIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Username Search
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
            <TextField
              label="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username to search"
              sx={{ minWidth: 200 }}
              disabled={loading}
            />
            
            <Button
              variant="outlined"
              onClick={() => setShowPlatformsDialog(true)}
              disabled={loading}
              startIcon={<WebIcon />}
            >
              {selectedPlatforms.length > 0 
                ? `${selectedPlatforms.length} platforms selected`
                : 'Select platforms'
              }
            </Button>
            
            <TextField
              label="Timeout (seconds)"
              type="number"
              value={timeout}
              onChange={(e) => setTimeout(Number(e.target.value))}
              sx={{ width: 120 }}
              disabled={loading}
            />
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <Button
            variant="contained"
            onClick={handleSearch}
            disabled={loading || !username.trim()}
            startIcon={loading ? <CircularProgress size={20} /> : <SearchIcon />}
            sx={{ mr: 1 }}
          >
            {loading ? 'Searching...' : 'Start Search'}
          </Button>

          {currentSession && currentSession.status === 'running' && (
            <Button
              variant="outlined"
              color="error"
              onClick={() => handleStopSession(currentSession.session_id)}
              startIcon={<StopIcon />}
            >
              Stop Search
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Current Session Results */}
      {currentSession && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Search Results for "{currentSession.username}"
              </Typography>
              <Chip
                icon={getStatusIcon(currentSession.status)}
                label={currentSession.status.toUpperCase()}
                color={getStatusColor(currentSession.status)}
              />
            </Box>

            {currentSession.status === 'running' && (
              <Box sx={{ width: '100%', mb: 2 }}>
                <LinearProgress />
                <Typography variant="body2" sx={{ mt: 1 }}>
                  Searching across platforms...
                </Typography>
              </Box>
            )}

            {currentSession.status === 'completed' && currentSession.results && (
              <Box>
                {(() => {
                  const { found, notFound, total } = formatResults(currentSession.results);
                  return (
                    <Box>
                      <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                        <Chip label={`Found: ${found.length}`} color="success" />
                        <Chip label={`Not Found: ${notFound.length}`} color="default" />
                        <Chip label={`Total: ${total}`} color="primary" />
                      </Box>

                      <Accordion defaultExpanded>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography variant="subtitle1">
                            Found Accounts ({found.length})
                          </Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          <TableContainer component={Paper}>
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>Platform</TableCell>
                                  <TableCell>URL</TableCell>
                                  <TableCell>Category</TableCell>
                                  <TableCell>Response Time</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {found.map((result, index) => (
                                  <TableRow key={index}>
                                    <TableCell>
                                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                        <WebIcon sx={{ mr: 1 }} />
                                        {result.name}
                                      </Box>
                                    </TableCell>
                                    <TableCell>
                                      <a href={result.url_user} target="_blank" rel="noopener noreferrer">
                                        {result.url_user}
                                      </a>
                                    </TableCell>
                                    <TableCell>{result.category}</TableCell>
                                    <TableCell>{result.response_time_ms}ms</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        </AccordionDetails>
                      </Accordion>
                    </Box>
                  );
                })()}
              </Box>
            )}

            {currentSession.error && (
              <Alert severity="error">
                Error: {currentSession.error}
              </Alert>
            )}
          </CardContent>
        </Card>
      )}

      {/* Previous Sessions */}
      {sessions.length > 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Previous Searches
            </Typography>
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Username</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Platforms</TableCell>
                    <TableCell>Start Time</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sessions.map((session) => (
                    <TableRow key={session.session_id}>
                      <TableCell>{session.username}</TableCell>
                      <TableCell>
                        <Chip
                          icon={getStatusIcon(session.status)}
                          label={session.status}
                          color={getStatusColor(session.status)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {Array.isArray(session.platforms) 
                          ? session.platforms.join(', ')
                          : session.platforms
                        }
                      </TableCell>
                      <TableCell>
                        {new Date(session.start_time).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {session.status === 'running' && (
                          <Tooltip title="Stop search">
                            <IconButton
                              size="small"
                              onClick={() => handleStopSession(session.session_id)}
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

      {/* Platforms Selection Dialog */}
      <Dialog
        open={showPlatformsDialog}
        onClose={() => setShowPlatformsDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Select Platforms</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Select specific platforms to search. Leave empty to search all available platforms.
          </Typography>
          <FormControl fullWidth>
            <InputLabel>Platforms</InputLabel>
            <Select
              multiple
              value={selectedPlatforms}
              onChange={handlePlatformChange}
              input={<OutlinedInput label="Platforms" />}
              renderValue={(selected) => selected.join(', ')}
            >
              {availablePlatforms.map((platform) => (
                <MenuItem key={platform} value={platform}>
                  <Checkbox checked={selectedPlatforms.indexOf(platform) > -1} />
                  <ListItemText primary={platform} />
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelectedPlatforms([])}>
            Clear All
          </Button>
          <Button onClick={() => setShowPlatformsDialog(false)}>
            Done
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default SherlockTool; 