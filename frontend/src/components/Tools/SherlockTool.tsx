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
  Divider
} from '@mui/material';
import {
  Search as SearchIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  PersonSearch as PersonSearchIcon
} from '@mui/icons-material';

interface Platform {
  name: string;
  url: string;
}

interface SearchResult {
  platform: string;
  url: string;
  status: 'found' | 'not_found' | 'error';
  error?: string;
}

interface SearchSession {
  id: string;
  username: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  progress: number;
  results: SearchResult[];
  startTime: string;
  endTime?: string;
}

const SherlockTool: React.FC = () => {
  const [username, setUsername] = useState('');
  const [selectedPlatforms, setSelectedPlatforms] = useState<string[]>([]);
  const [availablePlatforms, setAvailablePlatforms] = useState<Platform[]>([]);
  const [sessions, setSessions] = useState<SearchSession[]>([]);
  const [currentSession, setCurrentSession] = useState<SearchSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Helper function to get auth headers with proper error handling
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

  // Fetch available platforms with retry mechanism
  const fetchAvailablePlatforms = async (retryCount = 0) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/tools/sherlock/platforms', {
        headers: getAuthHeaders()
      });

      if (!response.ok) {
        if (response.status === 401 && retryCount < 2) {
          // Try to re-authenticate
          await checkAuth();
          return fetchAvailablePlatforms(retryCount + 1);
        }
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (data.platforms && Array.isArray(data.platforms)) {
        setAvailablePlatforms(data.platforms);
      } else {
        // Fallback to sample platforms if API doesn't return expected format
        setAvailablePlatforms([
          { name: 'GitHub', url: 'https://github.com/{username}' },
          { name: 'Twitter', url: 'https://twitter.com/{username}' },
          { name: 'Instagram', url: 'https://instagram.com/{username}' },
          { name: 'Facebook', url: 'https://facebook.com/{username}' },
          { name: 'LinkedIn', url: 'https://linkedin.com/in/{username}' },
          { name: 'Reddit', url: 'https://reddit.com/user/{username}' },
          { name: 'YouTube', url: 'https://youtube.com/@{username}' },
          { name: 'TikTok', url: 'https://tiktok.com/@{username}' }
        ]);
      }
    } catch (error) {
      console.error('Error fetching platforms:', error);
      setError('Failed to load platforms. Using sample data.');
      // Set fallback platforms
      setAvailablePlatforms([
        { name: 'GitHub', url: 'https://github.com/{username}' },
        { name: 'Twitter', url: 'https://twitter.com/{username}' },
        { name: 'Instagram', url: 'https://instagram.com/{username}' },
        { name: 'Facebook', url: 'https://facebook.com/{username}' },
        { name: 'LinkedIn', url: 'https://linkedin.com/in/{username}' },
        { name: 'Reddit', url: 'https://reddit.com/user/{username}' },
        { name: 'YouTube', url: 'https://youtube.com/@{username}' },
        { name: 'TikTok', url: 'https://tiktok.com/@{username}' }
      ]);
    } finally {
      setLoading(false);
    }
  };

  // Fetch existing sessions
  const fetchSessions = async () => {
    try {
      const response = await fetch('/api/tools/sherlock/sessions', {
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

  // Start a new search
  const startSearch = async () => {
    if (!username.trim()) {
      setError('Please enter a username');
      return;
    }

    if (selectedPlatforms.length === 0) {
      setError('Please select at least one platform');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/tools/sherlock/search', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          username: username.trim(),
          platforms: selectedPlatforms,
          timeout: 300
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
        const newSession: SearchSession = {
          id: data.session_id,
          username: username.trim(),
          status: 'running',
          progress: 0,
          results: [],
          startTime: new Date().toISOString()
        };
        
        setCurrentSession(newSession);
        setSessions(prev => [newSession, ...prev]);
        
        // Start polling for updates
        pollSessionStatus(data.session_id);
      }
    } catch (error) {
      console.error('Error starting search:', error);
      setError('Failed to start search. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Poll session status
  const pollSessionStatus = async (sessionId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/tools/sherlock/status/${sessionId}`, {
          headers: getAuthHeaders()
        });

        if (response.ok) {
          const data = await response.json();
          
          setCurrentSession(prev => {
            if (prev && prev.id === sessionId) {
              return {
                ...prev,
                status: data.status,
                progress: data.progress || prev.progress,
                results: data.results || prev.results,
                endTime: data.status !== 'running' ? new Date().toISOString() : prev.endTime
              };
            }
            return prev;
          });

          setSessions(prev => prev.map(session => 
            session.id === sessionId 
              ? {
                  ...session,
                  status: data.status,
                  progress: data.progress || session.progress,
                  results: data.results || session.results,
                  endTime: data.status !== 'running' ? new Date().toISOString() : session.endTime
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

  // Stop a search
  const stopSearch = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/tools/sherlock/stop/${sessionId}`, {
        method: 'POST',
        headers: getAuthHeaders()
      });

      if (response.ok) {
        setSessions(prev => prev.map(session => 
          session.id === sessionId 
            ? { ...session, status: 'stopped', endTime: new Date().toISOString() }
            : session
        ));
        
        if (currentSession?.id === sessionId) {
          setCurrentSession(prev => prev ? { ...prev, status: 'stopped', endTime: new Date().toISOString() } : null);
        }
      }
    } catch (error) {
      console.error('Error stopping search:', error);
      setError('Failed to stop search');
    }
  };

  // Handle platform selection
  const handlePlatformChange = (event: any) => {
    setSelectedPlatforms(event.target.value);
  };

  // Initialize component
  useEffect(() => {
    const initialize = async () => {
      const authOk = await checkAuth();
      if (authOk) {
        await fetchAvailablePlatforms();
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
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <PersonSearchIcon />
        Username Enumeration Tool
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {!isAuthenticated && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Please log in to use the username enumeration tool.
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Search Configuration */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Search Configuration
              </Typography>
              
              <TextField
                fullWidth
                label="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username to search"
                sx={{ mb: 2 }}
                disabled={loading}
              />

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Platforms</InputLabel>
                <Select
                  multiple
                  value={selectedPlatforms}
                  onChange={handlePlatformChange}
                  renderValue={(selected) => (
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {selected.map((value) => (
                        <Chip key={value} label={value} size="small" />
                      ))}
                    </Box>
                  )}
                  disabled={loading}
                >
                  {availablePlatforms.map((platform) => (
                    <MenuItem key={platform.name} value={platform.name}>
                      {platform.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <Button
                fullWidth
                variant="contained"
                onClick={startSearch}
                disabled={loading || !username.trim() || selectedPlatforms.length === 0 || !isAuthenticated}
                startIcon={<SearchIcon />}
                sx={{ mb: 1 }}
              >
                {loading ? 'Starting Search...' : 'Start Search'}
              </Button>

              <Button
                fullWidth
                variant="outlined"
                onClick={() => {
                  setSelectedPlatforms(availablePlatforms.map(p => p.name));
                }}
                disabled={loading}
                startIcon={<RefreshIcon />}
              >
                Select All Platforms
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
                      Searching for: <strong>{currentSession.username}</strong>
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
                          onClick={() => stopSearch(currentSession.id)}
                          color="error"
                          sx={{ ml: 1 }}
                        >
                          <StopIcon />
                        </IconButton>
                      )}
                    </Box>
                  </Box>

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

                  {currentSession.results.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" gutterBottom>
                        Results ({currentSession.results.length} found)
                      </Typography>
                      <TableContainer component={Paper} sx={{ maxHeight: 300 }}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Platform</TableCell>
                              <TableCell>URL</TableCell>
                              <TableCell>Status</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {currentSession.results.map((result, index) => (
                              <TableRow key={index}>
                                <TableCell>{result.platform}</TableCell>
                                <TableCell>
                                  <a href={result.url} target="_blank" rel="noopener noreferrer">
                                    {result.url}
                                  </a>
                                </TableCell>
                                <TableCell>
                                  <Chip
                                    icon={result.status === 'found' ? <CheckCircleIcon /> : <ErrorIcon />}
                                    label={result.status === 'found' ? 'Found' : 'Not Found'}
                                    color={result.status === 'found' ? 'success' : 'default'}
                                    size="small"
                                  />
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Box>
                  )}
                </Box>
              ) : (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                  <InfoIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="body1" color="text.secondary">
                    No active search session. Start a new search to begin.
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
                    <TableCell>Username</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Results</TableCell>
                    <TableCell>Start Time</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sessions.map((session) => (
                    <TableRow key={session.id}>
                      <TableCell>{session.username}</TableCell>
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
                        {session.results.filter(r => r.status === 'found').length} found
                      </TableCell>
                      <TableCell>
                        {new Date(session.startTime).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {session.status === 'running' && (
                          <Tooltip title="Stop Search">
                            <IconButton
                              size="small"
                              onClick={() => stopSearch(session.id)}
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
    </Box>
  );
};

export default SherlockTool; 