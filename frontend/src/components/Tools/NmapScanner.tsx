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
  alpha,
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
  MoreVert as MoreVertIcon,
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
    color: colors.accent.blue,
  },
  {
    value: 'full',
    label: 'Full Scan',
    description: 'Comprehensive scan of all ports',
    icon: <SecurityIcon />,
    color: colors.primary.main,
  },
  {
    value: 'vuln',
    label: 'Vulnerability Scan',
    description: 'Scan for known vulnerabilities',
    icon: <BugReportIcon />,
    color: colors.accent.fuchsia,
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
  const selectedScanTypeData = scanTypes.find(type => type.value === selectedScanType);

  const scanMutation = useMutation({
    mutationFn: (data: NmapScanRequest) => apiClient.runNmapScan(data),
    onSuccess: (response) => {
      setCurrentJobId(response.job_id);
      setScanResults(response);
    },
    onError: (error) => {
      console.error('Scan failed:', error);
    },
  });

  const { data: jobStatus } = useQuery({
    queryKey: ['job', currentJobId],
    queryFn: () => apiClient.getJobStatus(currentJobId!),
    enabled: !!currentJobId,
    refetchInterval: 2000,
  });

  const onSubmit = (data: NmapFormData) => {
    scanMutation.mutate({
      target: data.target,
      scan_type: data.scan_type,
    });
  };

  const handleDownloadReport = async () => {
    if (scanResults) {
      try {
        const response = await apiClient.downloadReport(scanResults.job_id);
        const blob = new Blob([response], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nmap-scan-${scanResults.job_id}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } catch (error) {
        console.error('Download failed:', error);
      }
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return colors.severity.critical;
      case 'high':
        return colors.severity.high;
      case 'medium':
        return colors.severity.medium;
      case 'low':
        return colors.severity.low;
      default:
        return colors.text.secondary;
    }
  };

  const getServiceIcon = (service: string) => {
    switch (service.toLowerCase()) {
      case 'http':
      case 'https':
        return <SecurityIcon />;
      case 'ssh':
        return <NetworkIcon />;
      case 'ftp':
        return <NetworkIcon />;
      default:
        return <NetworkIcon />;
    }
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 700, color: colors.text.primary }}>
          Network Scanner
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
        {/* Scan Configuration Card */}
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
                <NetworkIcon sx={{ mr: 2, color: colors.primary.main, fontSize: 28 }} />
                <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                  Scan Configuration
                </Typography>
              </Box>

              <form onSubmit={handleSubmit(onSubmit)}>
                <Box sx={{ mb: 3 }}>
                  <Controller
                    name="target"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Target IP/Domain"
                        placeholder="192.168.1.1 or example.com"
                        fullWidth
                        error={!!errors.target}
                        helperText={errors.target?.message}
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
                    name="scan_type"
                    control={control}
                    render={({ field }) => (
                      <FormControl fullWidth>
                        <InputLabel>Scan Type</InputLabel>
                        <Select {...field} label="Scan Type">
                          {scanTypes.map((type) => (
                            <MenuItem key={type.value} value={type.value}>
                              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <Box
                                  sx={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    width: 32,
                                    height: 32,
                                    borderRadius: '50%',
                                    backgroundColor: alpha(type.color, 0.2),
                                    color: type.color,
                                    mr: 2,
                                  }}
                                >
                                  {type.icon}
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                                    {type.label}
                                  </Typography>
                                  <Typography variant="caption" sx={{ color: colors.text.secondary }}>
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
                </Box>

                <Button
                  type="submit"
                  variant="contained"
                  fullWidth
                  disabled={scanMutation.isPending}
                  startIcon={scanMutation.isPending ? <CircularProgress size={20} /> : <PlayIcon />}
                  sx={{
                    backgroundColor: colors.primary.main,
                    '&:hover': {
                      backgroundColor: colors.primary.dark,
                    },
                    py: 1.5,
                  }}
                >
                  {scanMutation.isPending ? 'Starting Scan...' : 'Start Scan'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </Grid>

        {/* Scan Progress and Results */}
        <Grid item xs={12} md={8}>
          {currentJobId && (
            <Card
              sx={{
                backgroundColor: colors.background.paper,
                border: `1px solid ${colors.border.primary}`,
                borderRadius: 2,
                mb: 3,
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                    Scan Progress
                  </Typography>
                  <IconButton size="small">
                    <MoreVertIcon sx={{ color: colors.text.secondary }} />
                  </IconButton>
                </Box>
                
                <ScanProgress jobId={currentJobId} />
                
                {jobStatus?.status === 'completed' && (
                  <Box sx={{ mt: 2 }}>
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
                )}
              </CardContent>
            </Card>
          )}

          {/* Scan Results */}
          {scanResults && jobStatus?.status === 'completed' && (
            <Card
              sx={{
                backgroundColor: colors.background.paper,
                border: `1px solid ${colors.border.primary}`,
                borderRadius: 2,
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                    Scan Results
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Chip
                      label={`${scanResults.hosts?.length || 0} Hosts Found`}
                      color="primary"
                      size="small"
                    />
                    <Chip
                      label={`${scanResults.vulnerabilities?.length || 0} Vulnerabilities`}
                      color="secondary"
                      size="small"
                    />
                  </Box>
                </Box>

                {scanResults.hosts && scanResults.hosts.length > 0 && (
                  <Box sx={{ mb: 3 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2, color: colors.text.primary }}>
                      Discovered Hosts
                    </Typography>
                    <TableContainer component={Paper} sx={{ backgroundColor: colors.background.elevated }}>
                      <Table>
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Host</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Status</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Open Ports</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Services</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {scanResults.hosts.map((host, index) => (
                            <TableRow key={index}>
                              <TableCell sx={{ color: colors.text.primary }}>{host.ip}</TableCell>
                              <TableCell>
                                <Chip
                                  label={host.status}
                                  size="small"
                                  color={host.status === 'up' ? 'success' : 'error'}
                                />
                              </TableCell>
                              <TableCell sx={{ color: colors.text.primary }}>
                                {host.ports?.length || 0}
                              </TableCell>
                              <TableCell>
                                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                  {host.services?.slice(0, 3).map((service, serviceIndex) => (
                                    <Chip
                                      key={serviceIndex}
                                      label={service}
                                      size="small"
                                      variant="outlined"
                                      sx={{
                                        borderColor: colors.border.secondary,
                                        color: colors.text.secondary,
                                      }}
                                    />
                                  ))}
                                  {host.services && host.services.length > 3 && (
                                    <Chip
                                      label={`+${host.services.length - 3}`}
                                      size="small"
                                      variant="outlined"
                                      sx={{
                                        borderColor: colors.border.secondary,
                                        color: colors.text.secondary,
                                      }}
                                    />
                                  )}
                                </Box>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Box>
                )}

                {scanResults.vulnerabilities && scanResults.vulnerabilities.length > 0 && (
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2, color: colors.text.primary }}>
                      Vulnerabilities Found
                    </Typography>
                    <TableContainer component={Paper} sx={{ backgroundColor: colors.background.elevated }}>
                      <Table>
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Vulnerability</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Severity</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Host</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Port</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {scanResults.vulnerabilities.map((vuln, index) => (
                            <TableRow key={index}>
                              <TableCell sx={{ color: colors.text.primary }}>{vuln.name}</TableCell>
                              <TableCell>
                                <Chip
                                  label={vuln.severity}
                                  size="small"
                                  sx={{
                                    backgroundColor: getSeverityColor(vuln.severity),
                                    color: colors.text.primary,
                                    fontWeight: 600,
                                  }}
                                />
                              </TableCell>
                              <TableCell sx={{ color: colors.text.primary }}>{vuln.host}</TableCell>
                              <TableCell sx={{ color: colors.text.primary }}>{vuln.port}</TableCell>
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

export default NmapScanner;