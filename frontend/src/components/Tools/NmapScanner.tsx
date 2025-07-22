import React, { useState } from 'react';
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
  LinearProgress,
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
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  GetApp as DownloadIcon,
  Visibility as ViewIcon,
  BugReport as BugReportIcon,
  NetworkCheck as NetworkIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useForm, Controller } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { useMutation, useQuery } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { NmapScanRequest, NmapScanResponse } from '../../types/api';
import TerminalOutput from '../Common/TerminalOutput';
import ScanProgress from '../Common/ScanProgress';

const nmapSchema = yup.object({
  target: yup
    .string()
    .required('Target is required')
    .matches(
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$|^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
      'Please enter a valid IP address, CIDR range, or domain name'
    ),
  scan_type: yup.string().required('Scan type is required'),
});

interface NmapFormData {
  target: string;
  scan_type: 'quick' | 'full' | 'vuln';
}

const scanTypes = [
  {
    value: 'quick',
    label: 'Quick Scan',
    description: 'Fast scan of common ports',
    icon: <NetworkIcon />,
  },
  {
    value: 'full',
    label: 'Full Scan',
    description: 'Comprehensive scan of all ports',
    icon: <SecurityIcon />,
  },
  {
    value: 'vuln',
    label: 'Vulnerability Scan',
    description: 'Scan for known vulnerabilities',
    icon: <BugReportIcon />,
  },
];

const NmapScanner: React.FC = () => {
  const [scanResults, setScanResults] = useState<NmapScanResponse | null>(null);
  const [currentJobId, setCurrentJobId] = useState<number | null>(null);
  const [showResults, setShowResults] = useState(false);

  const {
    control,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<NmapFormData>({
    resolver: yupResolver(nmapSchema),
    defaultValues: {
      target: '',
      scan_type: 'quick',
    },
  });

  const selectedScanType = watch('scan_type');

  const nmapMutation = useMutation({
    mutationFn: (data: NmapScanRequest) => apiClient.runNmapScan(data),
    onSuccess: (data: NmapScanResponse) => {
      setScanResults(data);
      setCurrentJobId(data.job_id);
      setShowResults(true);
    },
    onError: (error) => {
      console.error('Nmap scan failed:', error);
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

  const onSubmit = (data: NmapFormData) => {
    nmapMutation.mutate(data);
  };

  const handleDownloadReport = async () => {
    if (!currentJobId) return;
    
    try {
      const reportData = await apiClient.getJobReport(currentJobId);
      const blob = new Blob([reportData], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `nmap_report_${currentJobId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to download report:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return colors.severity.critical;
      case 'high':
        return colors.severity.high;
      case 'medium':
        return colors.severity.medium;
      case 'low':
        return colors.severity.low;
      default:
        return colors.severity.info;
    }
  };

  const getServiceIcon = (service: string) => {
    const serviceIcons: { [key: string]: React.ReactNode } = {
      http: <NetworkIcon />,
      https: <SecurityIcon />,
      ssh: <SecurityIcon />,
      ftp: <NetworkIcon />,
      smtp: <NetworkIcon />,
      default: <NetworkIcon />,
    };
    return serviceIcons[service.toLowerCase()] || serviceIcons.default;
  };

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Network Scanner (Nmap)
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Scan Configuration
              </Typography>

              <form onSubmit={handleSubmit(onSubmit)}>
                <Controller
                  name="target"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      fullWidth
                      label="Target"
                      placeholder="192.168.1.1 or example.com"
                      error={!!errors.target}
                      helperText={errors.target?.message}
                      sx={{ mb: 2 }}
                    />
                  )}
                />

                <Controller
                  name="scan_type"
                  control={control}
                  render={({ field }) => (
                    <FormControl fullWidth sx={{ mb: 3 }}>
                      <InputLabel>Scan Type</InputLabel>
                      <Select {...field} label="Scan Type">
                        {scanTypes.map((type) => (
                          <MenuItem key={type.value} value={type.value}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              {type.icon}
                              <Box>
                                <Typography variant="body1">{type.label}</Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {type.description}
                                </Typography>
                              </Box>
                            </Box>
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  )}
                />

                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  disabled={nmapMutation.isPending}
                  startIcon={nmapMutation.isPending ? <CircularProgress size={20} /> : <PlayIcon />}
                  sx={{
                    backgroundColor: colors.primary.main,
                    '&:hover': {
                      backgroundColor: colors.primary.dark,
                    },
                  }}
                >
                  {nmapMutation.isPending ? 'Scanning...' : 'Start Scan'}
                </Button>
              </form>

              {nmapMutation.error && (
                <Alert
                  severity="error"
                  sx={{
                    mt: 2,
                    backgroundColor: colors.severity.critical + '20',
                    color: colors.severity.critical,
                    border: `1px solid ${colors.severity.critical}40`,
                  }}
                >
                  {nmapMutation.error.message}
                </Alert>
              )}
            </CardContent>
          </Card>

          {/* Scan Type Info */}
          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Scan Type Details
              </Typography>
              {scanTypes.map((type) => (
                <Box
                  key={type.value}
                  sx={{
                    p: 2,
                    mb: 1,
                    borderRadius: 1,
                    backgroundColor: selectedScanType === type.value ? 
                      colors.primary.main + '20' : 'transparent',
                    border: `1px solid ${selectedScanType === type.value ? 
                      colors.primary.main : colors.border.primary}`,
                    cursor: 'pointer',
                    transition: 'all 0.2s ease-in-out',
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    {type.icon}
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      {type.label}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {type.description}
                  </Typography>
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          {nmapMutation.isPending && (
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <ScanProgress 
                  jobId={currentJobId} 
                  isActive={nmapMutation.isPending}
                  onComplete={() => {
                    nmapMutation.reset();
                  }}
                />
              </CardContent>
            </Card>
          )}

          {showResults && scanResults && (
            <Fade in={showResults}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      Scan Results
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Tooltip title="Download Report">
                        <IconButton onClick={handleDownloadReport}>
                          <DownloadIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Refresh">
                        <IconButton onClick={() => setShowResults(false)}>
                          <RefreshIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>

                  <Alert
                    severity="success"
                    sx={{
                      mb: 2,
                      backgroundColor: colors.severity.low + '20',
                      color: colors.severity.low,
                      border: `1px solid ${colors.severity.low}40`,
                    }}
                  >
                    Scan completed successfully! Found {(Array.isArray(scanResults.open_ports) ? scanResults.open_ports.length : 0)} open ports.
                  </Alert>

                  <Divider sx={{ mb: 2 }} />

                  <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                    Open Ports
                  </Typography>

                  {Array.isArray(scanResults.open_ports) && scanResults.open_ports.length > 0 ? (
                    <TableContainer 
                      component={Paper} 
                      sx={{ 
                        backgroundColor: colors.background.paper,
                        border: `1px solid ${colors.border.primary}`,
                      }}
                    >
                      <Table>
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ fontWeight: 600 }}>Port</TableCell>
                            <TableCell sx={{ fontWeight: 600 }}>State</TableCell>
                            <TableCell sx={{ fontWeight: 600 }}>Service</TableCell>
                            <TableCell sx={{ fontWeight: 600 }}>Version</TableCell>
                            <TableCell sx={{ fontWeight: 600 }}>Actions</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {scanResults.open_ports.map((port, index) => (
                            <TableRow key={index}>
                              <TableCell>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                  {getServiceIcon(port.service)}
                                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                                    {port.port}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={port.state}
                                  size="small"
                                  sx={{
                                    backgroundColor: port.state === 'open' ? 
                                      colors.severity.low + '30' : colors.severity.critical + '30',
                                    color: port.state === 'open' ? 
                                      colors.severity.low : colors.severity.critical,
                                  }}
                                />
                              </TableCell>
                              <TableCell>
                                <Typography variant="body2">{port.service}</Typography>
                              </TableCell>
                              <TableCell>
                                <Typography variant="body2" color="text.secondary">
                                  {port.version || 'Unknown'}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                <Tooltip title="View Details">
                                  <IconButton size="small">
                                    <ViewIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  ) : (
                    <Alert severity="info">
                      No open ports found on the target.
                    </Alert>
                  )}
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
                  title="Nmap Output"
                />
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>
    </Box>
  );
};

export default NmapScanner;