import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  Chip,
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
  CircularProgress,
  Fade,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  GetApp as DownloadIcon,
  Visibility as ViewIcon,
  NetworkCheck as NetworkIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Router as RouterIcon,
  Computer as ComputerIcon,
} from '@mui/icons-material';
import { useForm, Controller } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { useMutation, useQuery } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { NetworkMonitorRequest, NetworkMonitorResponse } from '../../types/api';
import TerminalOutput from '../Common/TerminalOutput';
import ScanProgress from '../Common/ScanProgress';

const networkMonitorSchema = yup.object({
  interface: yup.string().required('Network interface is required'),
  timeout: yup.number().min(10).max(300).required('Timeout is required'),
});

interface NetworkMonitorFormData {
  interface: string;
  timeout: number;
}

const networkInterfaces = [
  { value: 'eth0', label: 'Ethernet (eth0)', description: 'Primary ethernet interface' },
  { value: 'wlan0', label: 'Wireless (wlan0)', description: 'Wireless network interface' },
  { value: 'lo', label: 'Loopback (lo)', description: 'Local loopback interface' },
  { value: 'any', label: 'All Interfaces', description: 'Monitor all network interfaces' },
];

const NetworkMonitor: React.FC = () => {
  const [monitorResults, setMonitorResults] = useState<NetworkMonitorResponse | null>(null);
  const [currentJobId, setCurrentJobId] = useState<number | null>(null);
  const [showResults, setShowResults] = useState(false);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [timeRemaining, setTimeRemaining] = useState(0);

  const {
    control,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<NetworkMonitorFormData>({
    resolver: yupResolver(networkMonitorSchema),
    defaultValues: {
      interface: 'eth0',
      timeout: 60,
    },
  });

  const selectedInterface = watch('interface');
  const selectedTimeout = watch('timeout');

  const networkMutation = useMutation({
    mutationFn: (data: NetworkMonitorRequest) => apiClient.monitorNetwork(data),
    onSuccess: (data: NetworkMonitorResponse) => {
      setMonitorResults(data);
      setCurrentJobId(data.job_id);
      setShowResults(true);
      setIsMonitoring(false);
    },
    onError: (error) => {
      console.error('Network monitoring failed:', error);
      setIsMonitoring(false);
    },
  });

  const {
    data: jobDetails,
    isLoading: jobLoading,
    error: jobError,
  } = useQuery({
    queryKey: ['job', currentJobId],
    queryFn: () => apiClient.getJob(currentJobId!),
    enabled: !!currentJobId,
    refetchInterval: 2000,
  });

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isMonitoring && timeRemaining > 0) {
      interval = setInterval(() => {
        setTimeRemaining((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isMonitoring, timeRemaining]);

  const onSubmit = (data: NetworkMonitorFormData) => {
    setIsMonitoring(true);
    setTimeRemaining(data.timeout);
    networkMutation.mutate(data);
  };

  const handleStopMonitoring = () => {
    setIsMonitoring(false);
    setTimeRemaining(0);
    // In a real implementation, you would cancel the monitoring job
  };

  const handleDownloadReport = async () => {
    if (!currentJobId) return;
    
    try {
      const reportData = await apiClient.getJobReport(currentJobId);
      const blob = new Blob([reportData], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `network_monitor_${currentJobId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to download report:', error);
    }
  };

  const getSeverityColor = (type: string) => {
    if (type.toLowerCase().includes('suspicious') || type.toLowerCase().includes('attack')) {
      return colors.severity.critical;
    }
    if (type.toLowerCase().includes('anomaly') || type.toLowerCase().includes('unusual')) {
      return colors.severity.high;
    }
    return colors.severity.medium;
  };

  const getAnomalyIcon = (type: string) => {
    if (type.toLowerCase().includes('login')) {
      return <SecurityIcon />;
    }
    if (type.toLowerCase().includes('flood') || type.toLowerCase().includes('dos')) {
      return <WarningIcon />;
    }
    return <InfoIcon />;
  };

  const formatBytes = (bytes: number) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Defensive destructuring for monitorResults
  const anomalies = Array.isArray(monitorResults?.results?.anomalies) ? monitorResults.results.anomalies : [];
  const samplePackets = Array.isArray(monitorResults?.results?.sample_packets) ? monitorResults.results.sample_packets : [];

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Network Monitor
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Monitor Configuration
              </Typography>

              <form onSubmit={handleSubmit(onSubmit)}>
                <Controller
                  name="interface"
                  control={control}
                  render={({ field }) => (
                    <FormControl fullWidth sx={{ mb: 2 }}>
                      <InputLabel>Network Interface</InputLabel>
                      <Select {...field} label="Network Interface">
                        {networkInterfaces.map((iface) => (
                          <MenuItem key={iface.value} value={iface.value}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <NetworkIcon />
                              <Box>
                                <Typography variant="body1">{iface.label}</Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {iface.description}
                                </Typography>
                              </Box>
                            </Box>
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  )}
                />

                <Controller
                  name="timeout"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      fullWidth
                      label="Monitoring Duration (seconds)"
                      type="number"
                      inputProps={{ min: 10, max: 300 }}
                      error={!!errors.timeout}
                      helperText={errors.timeout?.message}
                      sx={{ mb: 3 }}
                    />
                  )}
                />

                {!isMonitoring ? (
                  <Button
                    type="submit"
                    fullWidth
                    variant="contained"
                    disabled={networkMutation.isPending}
                    startIcon={networkMutation.isPending ? <CircularProgress size={20} /> : <PlayIcon />}
                    sx={{
                      backgroundColor: colors.primary.main,
                      '&:hover': {
                        backgroundColor: colors.primary.dark,
                      },
                    }}
                  >
                    {networkMutation.isPending ? 'Starting...' : 'Start Monitoring'}
                  </Button>
                ) : (
                  <Box>
                    <LinearProgress
                      variant="determinate"
                      value={((selectedTimeout - timeRemaining) / selectedTimeout) * 100}
                      sx={{
                        mb: 2,
                        height: 8,
                        borderRadius: 4,
                        backgroundColor: colors.background.elevated,
                        '& .MuiLinearProgress-bar': {
                          backgroundColor: colors.primary.main,
                        },
                      }}
                    />
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                      <Typography variant="body2" color="text.secondary">
                        Time remaining: {formatTime(timeRemaining)}
                      </Typography>
                      <Chip
                        label="MONITORING"
                        size="small"
                        sx={{
                          backgroundColor: colors.status.info + '30',
                          color: colors.status.info,
                          animation: 'pulse 2s infinite',
                        }}
                      />
                    </Box>
                    <Button
                      fullWidth
                      variant="outlined"
                      onClick={handleStopMonitoring}
                      startIcon={<StopIcon />}
                      sx={{
                        borderColor: colors.severity.critical,
                        color: colors.severity.critical,
                        '&:hover': {
                          borderColor: colors.severity.critical,
                          backgroundColor: colors.severity.critical + '10',
                        },
                      }}
                    >
                      Stop Monitoring
                    </Button>
                  </Box>
                )}
              </form>

              {networkMutation.error && (
                <Alert
                  severity="error"
                  sx={{
                    mt: 2,
                    backgroundColor: colors.severity.critical + '20',
                    color: colors.severity.critical,
                    border: `1px solid ${colors.severity.critical}40`,
                  }}
                >
                  {typeof networkMutation.error === 'string'
                    ? networkMutation.error
                    : networkMutation.error?.message
                      ? networkMutation.error.message
                      : networkMutation.error?.error
                        ? networkMutation.error.error
                        : JSON.stringify(networkMutation.error)}
                </Alert>
              )}
            </CardContent>
          </Card>

          {/* Interface Details */}
          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Interface Details
              </Typography>
              {networkInterfaces.map((iface) => (
                <Box
                  key={iface.value}
                  sx={{
                    p: 2,
                    mb: 1,
                    borderRadius: 1,
                    backgroundColor: selectedInterface === iface.value ? 
                      colors.primary.main + '20' : 'transparent',
                    border: `1px solid ${selectedInterface === iface.value ? 
                      colors.primary.main : colors.border.primary}`,
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <NetworkIcon />
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      {iface.label}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {iface.description}
                  </Typography>
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          {isMonitoring && (
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <ScanProgress 
                  jobId={currentJobId} 
                  isActive={isMonitoring}
                  onComplete={() => {
                    setIsMonitoring(false);
                  }}
                />
              </CardContent>
            </Card>
          )}

          {showResults && monitorResults && (
            <Fade in={showResults}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      Network Monitoring Results
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Tooltip title="Download Report">
                        <IconButton onClick={handleDownloadReport}>
                          <DownloadIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>

                  <Grid container spacing={2} sx={{ mb: 3 }}>
                    <Grid item xs={12} sm={4}>
                      <Card sx={{ backgroundColor: colors.primary.main + '20' }}>
                        <CardContent sx={{ textAlign: 'center' }}>
                          <Typography variant="h4" sx={{ color: colors.primary.main, fontWeight: 600 }}>
                            {monitorResults.results.total_packets}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            Total Packets
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <Card sx={{ backgroundColor: colors.severity.high + '20' }}>
                        <CardContent sx={{ textAlign: 'center' }}>
                          <Typography variant="h4" sx={{ color: colors.severity.high, fontWeight: 600 }}>
                            {anomalies.length}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            Anomalies Detected
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <Card sx={{ backgroundColor: colors.severity.info + '20' }}>
                        <CardContent sx={{ textAlign: 'center' }}>
                          <Typography variant="h4" sx={{ color: colors.severity.info, fontWeight: 600 }}>
                            {samplePackets.length}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            Sample Packets
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  </Grid>

                  <Divider sx={{ mb: 2 }} />

                  <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                    Detected Anomalies
                  </Typography>

                  {anomalies.length > 0 ? (
                    <List>
                      {anomalies.map((anomaly, index) => (
                        <ListItem
                          key={index}
                          sx={{
                            mb: 1,
                            backgroundColor: colors.background.elevated,
                            borderRadius: 1,
                            border: `1px solid ${getSeverityColor(anomaly.type)}40`,
                          }}
                        >
                          <ListItemIcon>
                            {getAnomalyIcon(anomaly.type)}
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                                  {anomaly.type}
                                </Typography>
                                <Chip
                                  label="ANOMALY"
                                  size="small"
                                  sx={{
                                    backgroundColor: getSeverityColor(anomaly.type) + '30',
                                    color: getSeverityColor(anomaly.type),
                                  }}
                                />
                              </Box>
                            }
                            secondary={
                              <Box sx={{ mt: 1 }}>
                                <Typography variant="body2" sx={{ mb: 1 }}>
                                  <strong>Source:</strong> {anomaly.source} → <strong>Destination:</strong> {anomaly.destination}
                                </Typography>
                                {anomaly.port && (
                                  <Typography variant="body2" sx={{ mb: 1 }}>
                                    <strong>Port:</strong> {anomaly.port}
                                  </Typography>
                                )}
                                {anomaly.size && (
                                  <Typography variant="body2" sx={{ mb: 1 }}>
                                    <strong>Size:</strong> {formatBytes(anomaly.size)}
                                  </Typography>
                                )}
                                {anomaly.payload && (
                                  <Typography
                                    variant="body2"
                                    sx={{
                                      fontFamily: 'monospace',
                                      backgroundColor: colors.background.default,
                                      p: 1,
                                      borderRadius: 1,
                                      mt: 1,
                                    }}
                                  >
                                    <strong>Payload:</strong> {anomaly.payload}
                                  </Typography>
                                )}
                              </Box>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  ) : (
                    <Alert severity="success">
                      No network anomalies detected during monitoring period.
                    </Alert>
                  )}

                  <Divider sx={{ my: 2 }} />

                  <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                    Sample Network Traffic
                  </Typography>

                  <TableContainer component={Paper} sx={{ backgroundColor: colors.background.paper }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 600 }}>Source</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Destination</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Protocol</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Size</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {(() => {
                          return samplePackets.length > 0 ? (
                            samplePackets.map((packet, index) => (
                              <TableRow key={index}>
                                <TableCell sx={{ fontFamily: 'monospace' }}>
                                  {packet.source}
                                </TableCell>
                                <TableCell sx={{ fontFamily: 'monospace' }}>
                                  {packet.destination}
                                </TableCell>
                                <TableCell>
                                  <Chip
                                    label={packet.protocol === 6 ? 'TCP' : packet.protocol === 17 ? 'UDP' : `Protocol ${packet.protocol}`}
                                    size="small"
                                    sx={{
                                      backgroundColor: packet.protocol === 6 ? 
                                        colors.primary.main + '30' : colors.severity.info + '30',
                                      color: packet.protocol === 6 ? 
                                        colors.primary.main : colors.severity.info,
                                    }}
                                  />
                                </TableCell>
                                <TableCell>{formatBytes(packet.size)}</TableCell>
                              </TableRow>
                            ))
                          ) : (
                            <TableRow>
                              <TableCell colSpan={4} align="center">
                                No sample packets available.
                              </TableCell>
                            </TableRow>
                          );
                        })()}

                      </TableBody>
                    </Table>
                  </TableContainer>

                  {/* MITRE ATT&CK Mappings Display */}
                  {(() => {
                    const mitre = Array.isArray(monitorResults?.mitre_mappings)
                      ? monitorResults.mitre_mappings
                      : [];
                    return mitre.length > 0 && (
                      <Box sx={{ mt: 3 }}>
                        <Typography variant="h6" sx={{ mb: 1, fontWeight: 600 }}>
                          MITRE ATT&CK Techniques Detected
                        </Typography>
                        <List>
                          {mitre.map((technique, idx) => (
                            <ListItem key={idx}>
                              <ListItemIcon>
                                <SecurityIcon color="primary" />
                              </ListItemIcon>
                              <ListItemText
                                primary={technique.name || technique.technique_id}
                                secondary={technique.technique_id}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    );
                  })()}

                </CardContent>
              </Card>
            </Fade>
          )}

          {jobDetails && (
            <Card sx={{ mt: 2 }}>
              <CardContent>
                <TerminalOutput
                  jobId={currentJobId}
                  results={jobDetails.results}
                  title="Network Monitor Output"
                />
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>
    </Box>
  );
};

export default NetworkMonitor;