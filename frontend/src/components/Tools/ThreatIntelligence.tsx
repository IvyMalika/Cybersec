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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Tabs,
  Tab,
  LinearProgress,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  GetApp as DownloadIcon,
  Shield as ShieldIcon,
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  Public as PublicIcon,
  ExpandMore as ExpandMoreIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Language as LanguageIcon,
  Storage as StorageIcon,
} from '@mui/icons-material';
import { useForm, Controller, SubmitHandler } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { useMutation, useQuery } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { ThreatIntelRequest, ThreatIntelResponse } from '../../types/api';
import TerminalOutput from '../Common/TerminalOutput';
import ScanProgress from '../Common/ScanProgress';

const threatIntelSchema = yup.object({
  indicator: yup.string().required('Indicator is required'),
  type: yup.string().oneOf(['ip', 'domain', 'hash', 'url']).required('Indicator type is required'),
});

interface ThreatIntelFormData {
  indicator: string;
  type: 'ip' | 'domain' | 'hash' | 'url';
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function CustomTabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`threat-tabpanel-${index}`}
      aria-labelledby={`threat-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const indicatorTypes = [
  { value: 'ip', label: 'IP Address', description: 'IPv4 or IPv6 address', example: '192.168.1.1' },
  { value: 'domain', label: 'Domain', description: 'Domain name or FQDN', example: 'example.com' },
  { value: 'hash', label: 'File Hash', description: 'MD5, SHA1, or SHA256 hash', example: 'a1b2c3d4...' },
  { value: 'url', label: 'URL', description: 'Complete URL', example: 'https://example.com/path' },
];

const ThreatIntelligence: React.FC = () => {
  const [intelResults, setIntelResults] = useState<ThreatIntelResponse | null>(null);
  const [currentJobId, setCurrentJobId] = useState<number | null>(null);
  const [showResults, setShowResults] = useState(false);
  const [tabValue, setTabValue] = useState(0);

  const {
    control,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<ThreatIntelFormData>({
    resolver: yupResolver(threatIntelSchema),
    defaultValues: {
      indicator: '',
      type: 'ip',
    },
  });

  const selectedType = watch('type');

  const intelMutation = useMutation({
    mutationFn: (data: ThreatIntelRequest) => apiClient.getThreatIntel(data),
    onSuccess: (data: ThreatIntelResponse) => {
      setIntelResults(data);
      setCurrentJobId(data.job_id);
      setShowResults(true);
    },
    onError: (error) => {
      console.error('Threat intelligence failed:', error);
    },
  });

  const mutationError = intelMutation.error as any;

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

  const onSubmit: SubmitHandler<ThreatIntelFormData> = (data) => {
    intelMutation.mutate(data);
  };

  const handleDownloadReport = async () => {
    if (!currentJobId) return;
    
    try {
      const reportData = await apiClient.getJobReport(currentJobId);
      const blob = new Blob([reportData], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threat_intel_${currentJobId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to download report:', error);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const getIndicatorTypeInfo = (type: string) => {
    return indicatorTypes.find(it => it.value === type);
  };

  const renderVirusTotalData = (vtData: any) => {
    if (!vtData || vtData.error) {
      return (
        <Alert severity="warning">
          VirusTotal data unavailable: {vtData?.error || 'No data'}
        </Alert>
      );
    }

    const stats = vtData.data?.attributes?.last_analysis_stats;
    if (!stats) {
      return <Alert severity="info">No analysis data available</Alert>;
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const clean = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = Object.values(stats).reduce((sum: number, count: any) => sum + count, 0);

    return (
      <Box>
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
          <Box sx={{ flex: '1 1 200px', minWidth: 150 }}>
            <Card sx={{ backgroundColor: colors.severity.critical + '20', textAlign: 'center' }}>
              <CardContent>
                <Typography variant="h4" sx={{ color: colors.severity.critical, fontWeight: 600 }}>
                  {typeof malicious === 'number' || typeof malicious === 'string' ? malicious : JSON.stringify(malicious)}
                </Typography>
                <Typography variant="body2">Malicious</Typography>
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 200px', minWidth: 150 }}>
            <Card sx={{ backgroundColor: colors.severity.high + '20', textAlign: 'center' }}>
              <CardContent>
                <Typography variant="h4" sx={{ color: colors.severity.high, fontWeight: 600 }}>
                  {typeof suspicious === 'number' || typeof suspicious === 'string' ? suspicious : JSON.stringify(suspicious)}
                </Typography>
                <Typography variant="body2">Suspicious</Typography>
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 200px', minWidth: 150 }}>
            <Card sx={{ backgroundColor: colors.severity.low + '20', textAlign: 'center' }}>
              <CardContent>
                <Typography variant="h4" sx={{ color: colors.severity.low, fontWeight: 600 }}>
                  {typeof clean === 'number' || typeof clean === 'string' ? clean : JSON.stringify(clean)}
                </Typography>
                <Typography variant="body2">Clean</Typography>
              </CardContent>
            </Card>
          </Box>
          <Box sx={{ flex: '1 1 200px', minWidth: 150 }}>
            <Card sx={{ backgroundColor: colors.severity.info + '20', textAlign: 'center' }}>
              <CardContent>
                <Typography variant="h4" sx={{ color: colors.severity.info, fontWeight: 600 }}>
                  {typeof undetected === 'number' || typeof undetected === 'string' ? undetected : JSON.stringify(undetected)}
                </Typography>
                <Typography variant="body2">Undetected</Typography>
              </CardContent>
            </Card>
          </Box>
        </Box>

        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
          Detection Ratio
        </Typography>
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="body2">
              {(typeof malicious === 'number' ? malicious : 0) + (typeof suspicious === 'number' ? suspicious : 0)} / {typeof total === 'number' ? total : 0} engines detected threats
            </Typography>
            <Typography variant="body2">
              {typeof total === 'number' && total > 0 ? Math.round((((typeof malicious === 'number' ? malicious : 0) + (typeof suspicious === 'number' ? suspicious : 0)) / total) * 100) : 0}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={typeof total === 'number' && total > 0 ? (((typeof malicious === 'number' ? malicious : 0) + (typeof suspicious === 'number' ? suspicious : 0)) / total) * 100 : 0}
            sx={{
              height: 8,
              borderRadius: 4,
              backgroundColor: colors.background.elevated,
              '& .MuiLinearProgress-bar': {
                backgroundColor: malicious > 0 ? colors.severity.critical : 
                  suspicious > 0 ? colors.severity.high : colors.severity.low,
              },
            }}
          />
        </Box>

        {vtData.data?.attributes?.last_analysis_results && (
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                Detailed Engine Results
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Engine</TableCell>
                      <TableCell>Result</TableCell>
                      <TableCell>Category</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {Object.entries(vtData.data.attributes.last_analysis_results).map(([engine, result]: [string, any]) => (
                      <TableRow key={engine}>
                        <TableCell>{engine}</TableCell>
                        <TableCell>
                          <Chip
                            label={
                              typeof result.result === 'string' || typeof result.result === 'number'
                                ? result.result
                                : result.result
                                  ? JSON.stringify(result.result)
                                  : 'Clean'
                            }
                            size="small"
                            sx={{
                              backgroundColor: result.category === 'malicious' ? colors.severity.critical + '30' :
                                result.category === 'suspicious' ? colors.severity.high + '30' :
                                colors.severity.low + '30',
                              color: result.category === 'malicious' ? colors.severity.critical :
                                result.category === 'suspicious' ? colors.severity.high :
                                colors.severity.low,
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          {typeof result.category === 'string' || typeof result.category === 'number'
                            ? result.category
                            : result.category
                              ? JSON.stringify(result.category)
                              : ''}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        )}
      </Box>
    );
  };

  const renderAlienVaultData = (otxData: any) => {
    if (!otxData || otxData.error) {
      return (
        <Alert severity="warning">
          AlienVault OTX data unavailable: {otxData?.error || 'No data'}
        </Alert>
      );
    }

    const pulseInfo = otxData.pulse_info;
    if (!pulseInfo || pulseInfo.count === 0) {
      return <Alert severity="success">No threat intelligence found in AlienVault OTX</Alert>;
    }

    return (
      <Box>
        <Alert
          severity="warning"
          sx={{
            mb: 2,
            backgroundColor: colors.severity.high + '20',
            color: colors.severity.high,
            border: `1px solid ${colors.severity.high}40`,
          }}
        >
          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
            Threat Detected!
          </Typography>
          This indicator is associated with {pulseInfo.count} threat intelligence pulse(s).
        </Alert>

        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
          Associated Threat Pulses
        </Typography>

        <List>
          {pulseInfo.pulses?.slice(0, 10).map((pulse: any, index: number) => (
            <ListItem
              key={index}
              sx={{
                mb: 1,
                backgroundColor: colors.background.elevated,
                borderRadius: 1,
                border: `1px solid ${colors.border.primary}`,
              }}
            >
              <ListItemIcon>
                <WarningIcon sx={{ color: colors.severity.high }} />
              </ListItemIcon>
              <ListItemText
                primary={pulse.name}
                secondary={
                  <Box sx={{ mt: 1 }}>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      <strong>Description:</strong> {pulse.description || 'No description available'}
                    </Typography>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      <strong>Created:</strong> {new Date(pulse.created).toLocaleDateString()}
                    </Typography>
                    <Typography variant="body2">
                      <strong>Tags:</strong> {pulse.tags?.join(', ') || 'None'}
                    </Typography>
                  </Box>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    );
  };

  const renderMitreData = (mitreData: any[]) => {
    if (!mitreData || mitreData.length === 0) {
      return <Alert severity="info">No MITRE ATT&CK mappings available</Alert>;
    }

    return (
      <Box>
        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
          MITRE ATT&CK Techniques
        </Typography>
        <List>
          {mitreData.map((technique, index) => (
            <ListItem
              key={index}
              sx={{
                mb: 1,
                backgroundColor: colors.background.elevated,
                borderRadius: 1,
                border: `1px solid ${colors.border.primary}`,
              }}
            >
              <ListItemIcon>
                <ShieldIcon sx={{ color: colors.primary.main }} />
              </ListItemIcon>
              <ListItemText
                primary={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      {technique.technique}
                    </Typography>
                    <Chip
                      label={technique.technique_id}
                      size="small"
                      sx={{
                        backgroundColor: colors.primary.main + '30',
                        color: colors.primary.main,
                      }}
                    />
                  </Box>
                }
                secondary={
                  <Box sx={{ mt: 1 }}>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      <strong>Tactic:</strong> {technique.tactic}
                    </Typography>
                    <Typography variant="body2">
                      {technique.description}
                    </Typography>
                  </Box>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    );
  };

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Threat Intelligence
      </Typography>

      <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        <Box sx={{ flex: 1, minWidth: 320 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Indicator Analysis
              </Typography>

              <form onSubmit={handleSubmit(onSubmit)}>
                <Controller
                  name="type"
                  control={control}
                  render={({ field }) => (
                    <FormControl fullWidth sx={{ mb: 2 }}>
                      <InputLabel>Indicator Type</InputLabel>
                      <Select {...field} label="Indicator Type">
                        {indicatorTypes.map((type) => (
                          <MenuItem key={type.value} value={type.value}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <SecurityIcon />
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

                <Controller
                  name="indicator"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      fullWidth
                      label="Indicator Value"
                      placeholder={getIndicatorTypeInfo(selectedType)?.example}
                      error={!!errors.indicator}
                      helperText={errors.indicator?.message}
                      sx={{ mb: 3 }}
                    />
                  )}
                />

                <Button
                  type="submit"
                  fullWidth
                  variant="contained"
                  disabled={intelMutation.isPending}
                  startIcon={intelMutation.isPending ? <CircularProgress size={20} /> : <PlayIcon />}
                  sx={{
                    backgroundColor: colors.primary.main,
                    '&:hover': {
                      backgroundColor: colors.primary.dark,
                    },
                  }}
                >
                  {intelMutation.isPending ? 'Analyzing...' : 'Analyze Threat'}
                </Button>
              </form>

              {mutationError && (
                <Alert
                  severity="error"
                  sx={{
                    mt: 2,
                    backgroundColor: colors.severity.critical + '20',
                    color: colors.severity.critical,
                    border: `1px solid ${colors.severity.critical}40`,
                  }}
                >
                  {typeof mutationError === 'string'
                    ? mutationError
                    : mutationError?.message
                      ? mutationError.message
                      : mutationError?.error
                        ? mutationError.error
                        : JSON.stringify(mutationError)}
                </Alert>
              )}
            </CardContent>
          </Card>

          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Intelligence Sources
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemIcon>
                    <SecurityIcon sx={{ color: colors.primary.main }} />
                  </ListItemIcon>
                  <ListItemText
                    primary="VirusTotal"
                    secondary="Multi-engine malware detection"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <ShieldIcon sx={{ color: colors.primary.main }} />  
                  </ListItemIcon>
                  <ListItemText
                    primary="AlienVault OTX"
                    secondary="Open threat intelligence platform"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <BugReportIcon sx={{ color: colors.primary.main }} />
                  </ListItemIcon>
                  <ListItemText
                    primary="MITRE ATT&CK"
                    secondary="Adversarial tactics and techniques"
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Box>

        <Box sx={{ flex: 2, minWidth: 400 }}>
          {intelMutation.isPending && (
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <ScanProgress 
                  jobId={currentJobId} 
                  isActive={intelMutation.isPending}
                  onComplete={() => {
                    intelMutation.reset();
                  }}
                />
              </CardContent>
            </Card>
          )}

          {showResults && intelResults && (
            <Fade in={showResults}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      Threat Intelligence Results
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Tooltip title="Download Report">
                        <IconButton onClick={handleDownloadReport}>
                          <DownloadIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>

                  <Alert
                    severity={intelResults.malicious ? 'error' : 'success'}
                    sx={{
                      mb: 2,
                      backgroundColor: intelResults.malicious ? 
                        colors.severity.critical + '20' : colors.severity.low + '20',
                      color: intelResults.malicious ? 
                        colors.severity.critical : colors.severity.low,
                      border: `1px solid ${intelResults.malicious ? 
                        colors.severity.critical : colors.severity.low}40`,
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {intelResults.malicious ? <ErrorIcon /> : <CheckIcon />}
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                        {intelResults.malicious ? 'Malicious Indicator Detected!' : 'Indicator Appears Clean'}
                      </Typography>
                    </Box>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      {intelResults.malicious ? 
                        'This indicator has been flagged as malicious by threat intelligence sources.' :
                        'No malicious activity associated with this indicator was found.'}
                    </Typography>
                  </Alert>

                  <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
                    <Tabs value={tabValue} onChange={handleTabChange}>
                      <Tab label="VirusTotal" icon={<SecurityIcon />} />
                      <Tab label="AlienVault OTX" icon={<ShieldIcon />} />
                      <Tab label="MITRE ATT&CK" icon={<BugReportIcon />} />
                    </Tabs>
                  </Box>

                  <CustomTabPanel value={tabValue} index={0}>
                    {renderVirusTotalData(intelResults.intel_data.virustotal)}
                  </CustomTabPanel>

                  <CustomTabPanel value={tabValue} index={1}>
                    {renderAlienVaultData(intelResults.intel_data.alienvault_otx)}
                  </CustomTabPanel>

                  <CustomTabPanel value={tabValue} index={2}>
                    {renderMitreData(intelResults.intel_data.mitre_attack)}
                  </CustomTabPanel>
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
                  title="Threat Intelligence Output"
                />
              </CardContent>
            </Card>
          )}
        </Box>
      </Box>
    </Box>
  );
};

export default ThreatIntelligence;