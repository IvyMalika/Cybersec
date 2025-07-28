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
  alpha,
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
  ExpandMore as ExpandMoreIcon,
  ErrorOutline as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  MoreVert as MoreVertIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  Assessment as AssessmentIcon,
  Speed as SpeedIcon,
  Router as RouterIcon,
  Wifi as WifiIcon,
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

const networkSchema = yup.object({
  interface: yup.string().required('Network interface is required'),
  duration: yup.number().min(1).max(3600).required('Duration is required'),
  filter: yup.string().optional(),
});

interface NetworkFormData {
  interface: string;
  duration: number;
  filter?: string;
}

const networkInterfaces = [
  { value: 'eth0', label: 'Ethernet 0', description: 'Primary network interface' },
  { value: 'wlan0', label: 'Wireless LAN 0', description: 'WiFi interface' },
  { value: 'lo', label: 'Loopback', description: 'Local loopback interface' },
  { value: 'any', label: 'All Interfaces', description: 'Monitor all interfaces' },
];

const NetworkStatCard: React.FC<{
  title: string;
  value: string | number;
  color: string;
  icon: React.ReactNode;
  subtitle?: string;
  trend?: 'up' | 'down' | 'stable';
}> = ({ title, value, color, icon, subtitle, trend }) => (
  <Card
    sx={{
      backgroundColor: colors.background.paper,
      border: `1px solid ${colors.border.primary}`,
      borderRadius: 2,
      transition: 'all 0.3s ease-in-out',
      '&:hover': {
        transform: 'translateY(-2px)',
        boxShadow: `0 8px 32px ${alpha(color, 0.2)}`,
      },
    }}
  >
    <CardContent sx={{ p: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, color, mr: 1 }}>
              {value}
            </Typography>
            {trend && (
              <TrendingUpIcon 
                sx={{ 
                  color: trend === 'up' ? colors.severity.critical : 
                         trend === 'down' ? colors.severity.low : colors.text.secondary,
                  fontSize: 16,
                  transform: trend === 'down' ? 'rotate(180deg)' : 'none',
                }} 
              />
            )}
          </Box>
          <Typography variant="body2" sx={{ color: colors.text.secondary }}>
            {title}
          </Typography>
          {subtitle && (
            <Typography variant="caption" sx={{ color: colors.text.secondary }}>
              {subtitle}
            </Typography>
          )}
        </Box>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 48,
            height: 48,
            borderRadius: '50%',
            backgroundColor: alpha(color, 0.2),
            color,
          }}
        >
          {icon}
        </Box>
      </Box>
    </CardContent>
  </Card>
);

const NetworkMonitor: React.FC = () => {
  const [monitoringResults, setMonitoringResults] = useState<NetworkMonitorResponse | null>(null);
  const [currentJobId, setCurrentJobId] = useState<number | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [realTimeData, setRealTimeData] = useState<any>(null);

  const {
    control,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<NetworkFormData>({
    resolver: yupResolver(networkSchema),
    defaultValues: {
      interface: 'eth0',
      duration: 300,
      filter: '',
    },
  });

  const selectedInterface = watch('interface');
  const selectedInterfaceData = networkInterfaces.find(iface => iface.value === selectedInterface);

  const monitoringMutation = useMutation({
    mutationFn: (data: NetworkMonitorRequest) => apiClient.startNetworkMonitoring(data),
    onSuccess: (response) => {
      setCurrentJobId(response.job_id);
      setIsMonitoring(true);
    },
    onError: (error) => {
      console.error('Network monitoring failed:', error);
    },
  });

  const stopMonitoringMutation = useMutation({
    mutationFn: () => apiClient.stopNetworkMonitoring(currentJobId!),
    onSuccess: () => {
      setIsMonitoring(false);
    },
    onError: (error) => {
      console.error('Stop monitoring failed:', error);
    },
  });

  const { data: jobStatus } = useQuery({
    queryKey: ['job', currentJobId],
    queryFn: () => apiClient.getJobStatus(currentJobId!),
    enabled: !!currentJobId && isMonitoring,
    refetchInterval: 1000,
  });

  // Simulate real-time data updates
  useEffect(() => {
    if (isMonitoring) {
      const interval = setInterval(() => {
        setRealTimeData({
          packets_per_sec: Math.floor(Math.random() * 1000) + 100,
          bytes_per_sec: Math.floor(Math.random() * 1000000) + 100000,
          connections: Math.floor(Math.random() * 50) + 10,
          suspicious_activity: Math.floor(Math.random() * 5),
          bandwidth_usage: Math.floor(Math.random() * 100),
        });
      }, 2000);

      return () => clearInterval(interval);
    }
  }, [isMonitoring]);

  const onSubmit = (data: NetworkFormData) => {
    monitoringMutation.mutate({
      interface: data.interface,
      duration: data.duration,
      filter: data.filter,
    });
  };

  const handleStopMonitoring = () => {
    stopMonitoringMutation.mutate();
  };

  const handleDownloadReport = async () => {
    if (monitoringResults) {
      try {
        const response = await apiClient.downloadReport(monitoringResults.job_id);
        const blob = new Blob([response], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `network-monitor-${monitoringResults.job_id}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } catch (error) {
        console.error('Download failed:', error);
      }
    }
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 700, color: colors.text.primary }}>
          Network Monitor
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton
              onClick={() => window.location.reload()}
              sx={{
                backgroundColor: alpha(colors.primary.main, 0.1),
                '&:hover': {
                  backgroundColor: alpha(colors.primary.main, 0.2),
                },
              }}
            >
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      <Grid container spacing={3}>
        {/* Monitoring Configuration Card */}
        <Grid item xs={12} md={4}>
          <Card
            sx={{
              backgroundColor: colors.background.paper,
              border: `1px solid ${colors.border.primary}`,
              borderRadius: 2,
              height: 'fit-content',
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                <NetworkIcon sx={{ mr: 2, color: colors.accent.blue, fontSize: 28 }} />
                <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                  Monitoring Configuration
                </Typography>
              </Box>

              <form onSubmit={handleSubmit(onSubmit)}>
                <Box sx={{ mb: 3 }}>
                  <Controller
                    name="interface"
                    control={control}
                    render={({ field }) => (
                      <FormControl fullWidth>
                        <InputLabel>Network Interface</InputLabel>
                        <Select {...field} label="Network Interface">
                          {networkInterfaces.map((iface) => (
                            <MenuItem key={iface.value} value={iface.value}>
                              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <Box
                                  sx={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    width: 32,
                                    height: 32,
                                    borderRadius: '50%',
                                    backgroundColor: alpha(colors.accent.blue, 0.2),
                                    color: colors.accent.blue,
                                    mr: 2,
                                  }}
                                >
                                  {iface.value.includes('wlan') ? <WifiIcon /> : <RouterIcon />}
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                                    {iface.label}
                                  </Typography>
                                  <Typography variant="caption" sx={{ color: colors.text.secondary }}>
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
                </Box>

                <Box sx={{ mb: 3 }}>
                  <Controller
                    name="duration"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Duration (seconds)"
                        type="number"
                        fullWidth
                        error={!!errors.duration}
                        helperText={errors.duration?.message}
                        inputProps={{ min: 1, max: 3600 }}
                        sx={{
                          '& .MuiOutlinedInput-root': {
                            backgroundColor: colors.background.elevated,
                          },
                        }}
                      />
                    )}
                  />
                </Box>

                <Box sx={{ mb: 3 }}>
                  <Controller
                    name="filter"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Packet Filter (optional)"
                        placeholder="tcp port 80 or udp port 53"
                        fullWidth
                        error={!!errors.filter}
                        helperText={errors.filter?.message || 'BPF filter syntax'}
                        sx={{
                          '& .MuiOutlinedInput-root': {
                            backgroundColor: colors.background.elevated,
                          },
                        }}
                      />
                    )}
                  />
                </Box>

                <Box sx={{ display: 'flex', gap: 2 }}>
                  {!isMonitoring ? (
                    <Button
                      type="submit"
                      variant="contained"
                      fullWidth
                      disabled={monitoringMutation.isPending}
                      startIcon={monitoringMutation.isPending ? <CircularProgress size={20} /> : <PlayIcon />}
                      sx={{
                        backgroundColor: colors.accent.blue,
                        '&:hover': {
                          backgroundColor: colors.accent.blue + 'CC',
                        },
                        py: 1.5,
                      }}
                    >
                      {monitoringMutation.isPending ? 'Starting...' : 'Start Monitoring'}
                    </Button>
                  ) : (
                    <Button
                      variant="contained"
                      fullWidth
                      disabled={stopMonitoringMutation.isPending}
                      startIcon={stopMonitoringMutation.isPending ? <CircularProgress size={20} /> : <StopIcon />}
                      onClick={handleStopMonitoring}
                      sx={{
                        backgroundColor: colors.severity.critical,
                        '&:hover': {
                          backgroundColor: colors.severity.critical + 'CC',
                        },
                        py: 1.5,
                      }}
                    >
                      {stopMonitoringMutation.isPending ? 'Stopping...' : 'Stop Monitoring'}
                    </Button>
                  )}
                </Box>
              </form>
            </CardContent>
          </Card>
        </Grid>

        {/* Real-time Monitoring Dashboard */}
        <Grid item xs={12} md={8}>
          {isMonitoring && (
            <>
              {/* Real-time Statistics */}
              <Card
                sx={{
                  backgroundColor: colors.background.paper,
                  border: `1px solid ${colors.border.primary}`,
                  borderRadius: 2,
                  mb: 3,
                }}
              >
                <CardContent sx={{ p: 3 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                      Real-time Network Statistics
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Box
                        sx={{
                          width: 8,
                          height: 8,
                          borderRadius: '50%',
                          backgroundColor: colors.severity.critical,
                          animation: 'pulse 1s infinite',
                        }}
                      />
                      <Typography variant="caption" sx={{ color: colors.text.secondary }}>
                        Live
                      </Typography>
                    </Box>
                  </Box>

                  {realTimeData && (
                    <Grid container spacing={2}>
                      <Grid item xs={12} sm={6} md={3}>
                        <NetworkStatCard
                          title="Packets/sec"
                          value={realTimeData.packets_per_sec}
                          color={colors.accent.blue}
                          icon={<SpeedIcon />}
                          trend="up"
                        />
                      </Grid>
                      <Grid item xs={12} sm={6} md={3}>
                        <NetworkStatCard
                          title="Bytes/sec"
                          value={`${(realTimeData.bytes_per_sec / 1024 / 1024).toFixed(1)} MB`}
                          color={colors.primary.main}
                          icon={<TrendingUpIcon />}
                          trend="up"
                        />
                      </Grid>
                      <Grid item xs={12} sm={6} md={3}>
                        <NetworkStatCard
                          title="Active Connections"
                          value={realTimeData.connections}
                          color={colors.accent.teal}
                          icon={<NetworkIcon />}
                          trend="stable"
                        />
                      </Grid>
                      <Grid item xs={12} sm={6} md={3}>
                        <NetworkStatCard
                          title="Suspicious Activity"
                          value={realTimeData.suspicious_activity}
                          color={colors.severity.high}
                          icon={<SecurityIcon />}
                          trend="up"
                        />
                      </Grid>
                    </Grid>
                  )}
                </CardContent>
              </Card>

              {/* Bandwidth Usage */}
              <Card
                sx={{
                  backgroundColor: colors.background.paper,
                  border: `1px solid ${colors.border.primary}`,
                  borderRadius: 2,
                  mb: 3,
                }}
              >
                <CardContent sx={{ p: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: colors.text.primary }}>
                    Bandwidth Usage
                  </Typography>
                  
                  <Box sx={{ mb: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                      <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                        Current Usage
                      </Typography>
                      <Typography variant="body2" sx={{ color: colors.text.primary, fontWeight: 600 }}>
                        {realTimeData?.bandwidth_usage || 0}%
                      </Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={realTimeData?.bandwidth_usage || 0}
                      sx={{
                        height: 8,
                        borderRadius: 4,
                        backgroundColor: colors.background.elevated,
                        '& .MuiLinearProgress-bar': {
                          backgroundColor: colors.accent.blue,
                          borderRadius: 4,
                        },
                      }}
                    />
                  </Box>
                </CardContent>
              </Card>
            </>
          )}

          {/* Monitoring Results */}
          {monitoringResults && !isMonitoring && (
            <Card
              sx={{
                backgroundColor: colors.background.paper,
                border: `1px solid ${colors.border.primary}`,
                borderRadius: 2,
                mb: 3,
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                    Monitoring Results
                  </Typography>
                  <Button
                    variant="outlined"
                    startIcon={<DownloadIcon />}
                    onClick={handleDownloadReport}
                    sx={{
                      borderColor: colors.border.secondary,
                      color: colors.text.primary,
                      '&:hover': {
                        borderColor: colors.primary.main,
                      },
                    }}
                  >
                    Download Report
                  </Button>
                </Box>

                {monitoringResults.packet_analysis && (
                  <TableContainer component={Paper} sx={{ backgroundColor: colors.background.elevated }}>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Protocol</TableCell>
                          <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Packets</TableCell>
                          <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Bytes</TableCell>
                          <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Status</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {Object.entries(monitoringResults.packet_analysis).map(([protocol, data]: [string, any]) => (
                          <TableRow key={protocol}>
                            <TableCell sx={{ color: colors.text.primary }}>
                              <Chip
                                label={protocol.toUpperCase()}
                                size="small"
                                sx={{
                                  backgroundColor: alpha(colors.accent.blue, 0.2),
                                  color: colors.accent.blue,
                                }}
                              />
                            </TableCell>
                            <TableCell sx={{ color: colors.text.primary }}>{data.packets}</TableCell>
                            <TableCell sx={{ color: colors.text.primary }}>{data.bytes}</TableCell>
                            <TableCell>
                              <Chip
                                label={data.suspicious ? 'Suspicious' : 'Normal'}
                                size="small"
                                color={data.suspicious ? 'error' : 'success'}
                                sx={{
                                  backgroundColor: data.suspicious ? colors.severity.critical : colors.severity.low,
                                  color: colors.text.primary,
                                }}
                              />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </CardContent>
            </Card>
          )}

          {/* Terminal Output */}
          {currentJobId && (
            <Card
              sx={{
                backgroundColor: colors.background.paper,
                border: `1px solid ${colors.border.primary}`,
                borderRadius: 2,
                mt: 3,
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: colors.text.primary }}>
                  Terminal Output
                </Typography>
                <TerminalOutput jobId={currentJobId} />
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>
    </Box>
  );
};

export default NetworkMonitor;