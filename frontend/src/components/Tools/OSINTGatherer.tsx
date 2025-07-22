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
  TabPanel,
  InputAdornment,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  GetApp as DownloadIcon,
  Search as SearchIcon,
  Public as PublicIcon,
  Dns as DnsIcon,
  Security as SecurityIcon,
  ExpandMore as ExpandMoreIcon,
  Info as InfoIcon,
  Language as LanguageIcon,
  Storage as StorageIcon,
  NetworkCheck as NetworkIcon,
  Email as EmailIcon,
} from '@mui/icons-material';
import { useForm, Controller } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { useMutation, useQuery } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { OSINTRequest, OSINTResponse } from '../../types/api';
import TerminalOutput from '../Common/TerminalOutput';
import ScanProgress from '../Common/ScanProgress';
import { useState as useLocalState } from 'react';
import { useRef } from 'react';
import axios from 'axios';

const osintSchema = yup.object({
  target: yup
    .string()
    .matches(
      /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
      'Please enter a valid domain name or IP address'
    )
    .notRequired(),
  email: yup
    .string()
    .email('Please enter a valid email address')
    .notRequired(),
  url: yup
    .string()
    .url('Please enter a valid URL (for SQLi test)')
    .notRequired(),
}).test(
  'at-least-one',
  'Please enter at least a target (domain/IP), email address, or test URL.',
  (value) => {
    return !!(value.target || value.email || value.url);
  }
);

interface OSINTFormData {
  target: string;
  email?: string;
  url?: string;
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
      id={`osint-tabpanel-${index}`}
      aria-labelledby={`osint-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const OSINTGatherer: React.FC = () => {
  const [osintResults, setOsintResults] = useState<OSINTResponse | null>(null);
  const [currentJobId, setCurrentJobId] = useState<number | null>(null);
  const [showResults, setShowResults] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  // Local state for expanding EmailRep raw JSON
  const [showEmailRepRaw, setShowEmailRepRaw] = useLocalState(false);
  // Refs for autofocus
  const targetRef = useRef<HTMLInputElement>(null);
  const emailRef = useRef<HTMLInputElement>(null);
  const [harvesterResults, setHarvesterResults] = useState<{ emails: string[]; hosts: string[] } | null>(null);
  const [niktoResult, setNiktoResult] = useState<string | null>(null);
  const [sqlmapResult, setSqlmapResult] = useState<string | null>(null);
  // Nikto and Harvester error state
  const [niktoError, setNiktoError] = useState<string | null>(null);
  const [harvesterError, setHarvesterError] = useState<string | null>(null);

  // Clear/reset handler
  const handleClear = () => {
    setOsintResults(null);
    setCurrentJobId(null);
    setShowResults(false);
    control.setValue('target', '');
    control.setValue('email', '');
    control.setValue('url', '');
    setTimeout(() => {
      if (targetRef.current) targetRef.current.focus();
    }, 100);
  };

  const {
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<OSINTFormData>({
    resolver: yupResolver(osintSchema),
    defaultValues: {
      target: '',
    },
  });

  const osintMutation = useMutation({
    mutationFn: (data: OSINTRequest) => apiClient.gatherOSINT(data),
    onSuccess: (data: OSINTResponse) => {
      setOsintResults(data);
      setCurrentJobId(data.job_id);
      setShowResults(true);
    },
    onError: (error) => {
      console.error('OSINT gathering failed:', error);
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

  const onSubmit = async (data: OSINTFormData) => {
    osintMutation.mutate(data);
    setHarvesterResults(null);
    setNiktoResult(null);
    setSqlmapResult(null);
    setNiktoError(null);
    setHarvesterError(null);
    if (data.target) {
      try {
        const res = await axios.post('/api/tools/osint/harvester', { target: data.target });
        if (res.data.error) {
          setHarvesterError(res.data.error);
          setHarvesterResults({ emails: [], hosts: [] });
        } else {
          setHarvesterResults(res.data);
        }
      } catch (err: any) {
        setHarvesterError(err?.response?.data?.error || err.message || 'Unknown error');
        setHarvesterResults({ emails: [], hosts: [] });
      }
      try {
        const niktoRes = await axios.post('/api/tools/osint/nikto', { target: data.target });
        if (niktoRes.data.error) {
          setNiktoError(niktoRes.data.error);
          setNiktoResult('');
        } else {
          setNiktoResult(niktoRes.data.output || '');
        }
      } catch (err: any) {
        setNiktoError(err?.response?.data?.error || err.message || 'Unknown error');
        setNiktoResult('');
      }
    }
    if (data.url) {
      try {
        const sqlmapRes = await axios.post('/api/tools/osint/sqlmap', { url: data.url });
        setSqlmapResult(sqlmapRes.data.output || '');
      } catch (err) {
        setSqlmapResult('SQLmap scan failed or is not available.');
      }
    }
  };

  const handleDownloadReport = async () => {
    if (!currentJobId) return;
    
    try {
      const reportData = await apiClient.getJobReport(currentJobId);
      const blob = new Blob([reportData], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `osint_report_${currentJobId}.pdf`;
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

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleDateString();
    } catch {
      return dateString;
    }
  };

  const renderShodanData = (shodanData: any) => {
    if (!shodanData || Object.keys(shodanData).length === 0) {
      return <Alert severity="info">No Shodan data available</Alert>;
    }

    return (
      <Box>
        {shodanData.ports && shodanData.ports.length > 0 && (
          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
              Open Ports
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              {shodanData.ports.map((port: number, index: number) => (
                <Chip
                  key={index}
                  label={port}
                  size="small"
                  sx={{
                    backgroundColor: colors.primary.main + '30',
                    color: colors.primary.main,
                  }}
                />
              ))}
            </Box>
          </Box>
        )}

        {shodanData.vulns && Object.keys(shodanData.vulns).length > 0 && (
          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
              Vulnerabilities
            </Typography>
            <List>
              {Object.keys(shodanData.vulns).map((vuln, index) => (
                <ListItem key={index} sx={{ pl: 0 }}>
                  <ListItemIcon>
                    <SecurityIcon sx={{ color: colors.severity.critical }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={vuln}
                    secondary={JSON.stringify(shodanData.vulns[vuln])}
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        )}

        {shodanData.data && shodanData.data.length > 0 && (
          <Box>
            <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
              Service Data
            </Typography>
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Port</TableCell>
                    <TableCell>Service</TableCell>
                    <TableCell>Product</TableCell>
                    <TableCell>Version</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {shodanData.data.slice(0, 10).map((service: any, index: number) => (
                    <TableRow key={index}>
                      <TableCell>{service.port}</TableCell>
                      <TableCell>{service.transport}</TableCell>
                      <TableCell>{service.product || 'Unknown'}</TableCell>
                      <TableCell>{service.version || 'Unknown'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}
      </Box>
    );
  };

  const renderWhoisData = (whoisData: any) => {
    if (!whoisData || Object.keys(whoisData).length === 0) {
      return <Alert severity="info">No WHOIS data available</Alert>;
    }

    return (
      <TableContainer component={Paper}>
        <Table>
          <TableBody>
            {whoisData.registrar && (
              <TableRow>
                <TableCell sx={{ fontWeight: 600 }}>Registrar</TableCell>
                <TableCell>{whoisData.registrar}</TableCell>
              </TableRow>
            )}
            {whoisData.creation_date && (
              <TableRow>
                <TableCell sx={{ fontWeight: 600 }}>Creation Date</TableCell>
                <TableCell>{formatDate(whoisData.creation_date)}</TableCell>
              </TableRow>
            )}
            {whoisData.expiration_date && (
              <TableRow>
                <TableCell sx={{ fontWeight: 600 }}>Expiration Date</TableCell>
                <TableCell>{formatDate(whoisData.expiration_date)}</TableCell>
              </TableRow>
            )}
            {whoisData.name_servers && (
              <TableRow>
                <TableCell sx={{ fontWeight: 600 }}>Name Servers</TableCell>
                <TableCell>
                  {Array.isArray(whoisData.name_servers) ? (
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      {whoisData.name_servers.map((ns: string, index: number) => (
                        <Chip
                          key={index}
                          label={ns}
                          size="small"
                          sx={{
                            backgroundColor: colors.severity.info + '30',
                            color: colors.severity.info,
                          }}
                        />
                      ))}
                    </Box>
                  ) : (
                    whoisData.name_servers
                  )}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    );
  };

  const renderDnsData = (dnsData: any) => {
    if (!dnsData || Object.keys(dnsData).length === 0) {
      return <Alert severity="info">No DNS data available</Alert>;
    }

    return (
      <Box>
        {Object.keys(dnsData).map((recordType) => (
          <Accordion key={recordType} sx={{ mb: 1 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                {recordType} Records ({dnsData[recordType]?.length || 0})
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              {dnsData[recordType] && dnsData[recordType].length > 0 ? (
                <List dense>
                  {dnsData[recordType].map((record: string, index: number) => (
                    <ListItem key={index} sx={{ pl: 0 }}>
                      <ListItemIcon>
                        <DnsIcon fontSize="small" />
                      </ListItemIcon>
                      <ListItemText
                        primary={record}
                        primaryTypographyProps={{
                          fontFamily: 'monospace',
                          fontSize: '0.875rem',
                        }}
                      />
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No {recordType} records found
                </Typography>
              )}
            </AccordionDetails>
          </Accordion>
        ))}
      </Box>
    );
  };

  // Helper for EmailRep reputation color
  const getReputationColor = (rep: string) => {
    switch (rep) {
      case 'high': return 'success';
      case 'medium': return 'warning';
      case 'low':
      case 'bad': return 'error';
      default: return 'default';
    }
  };

  // Helper for Socialscan status color
  const getSocialscanColor = (status: string) => {
    switch (status) {
      case 'available': return 'success';
      case 'taken': return 'error';
      default: return 'default';
    }
  };

  // Helper to show which OSINT checks will run
  const getChecksToRun = (target: string, email: string) => {
    const checks = [];
    if (target) checks.push('WHOIS', 'DNS');
    if (email) checks.push('EmailRep.io', 'Socialscan');
    return checks;
  };

  // Update checks preview
  const osintChecks = [
    {
      key: 'whois',
      label: 'WHOIS',
      icon: <PublicIcon color="primary" />,
      desc: 'Domain registration info',
      field: 'target',
    },
    {
      key: 'dns',
      label: 'DNS',
      icon: <DnsIcon color="primary" />,
      desc: 'DNS records & security',
      field: 'target',
    },
    {
      key: 'hunterio',
      label: 'Hunter.io',
      icon: <EmailIcon color="primary" />,
      desc: 'Email discovery and verification',
      field: 'email',
    },
    {
      key: 'nikto',
      label: 'Nikto',
      icon: <SecurityIcon color="primary" />,
      desc: 'Web server vulnerability scan',
      field: 'target',
    },
  ];

  // Step details for OSINT process
  const osintStepDetails = [
    {
      key: 'whois',
      label: 'WHOIS',
      desc: 'Fetches domain registration and ownership information.',
      command: (target: string) => `whois ${target}`,
      outcome: 'Displays registrar, creation/expiration dates, and name servers.'
    },
    {
      key: 'dns',
      label: 'DNS',
      desc: 'Retrieves DNS records and security-related information.',
      command: (target: string) => `dig +short ANY ${target}`,
      outcome: 'Lists DNS records such as A, MX, TXT, NS, etc.'
    },
    {
      key: 'hunterio',
      label: 'Hunter.io',
      desc: 'Finds and verifies emails related to the domain.',
      command: (email: string) => `hunter.io API search for ${email}`,
      outcome: 'Shows discovered emails, types, confidence, and sources.'
    },
    {
      key: 'nikto',
      label: 'Nikto',
      desc: 'Scans the web server for vulnerabilities.',
      command: (target: string) => `nikto -h ${target}`,
      outcome: 'Reports web server vulnerabilities and misconfigurations.'
    },
    {
      key: 'theharvester',
      label: 'theHarvester',
      desc: 'Discovers emails and hosts using public sources.',
      command: (target: string) => `theHarvester -d ${target} -b all` ,
      outcome: 'Lists found emails and hosts.'
    },
    {
      key: 'sqlmap',
      label: 'sqlmap',
      desc: 'Tests the provided URL for SQL injection vulnerabilities.',
      command: (url: string) => `sqlmap -u "${url}" --batch`,
      outcome: 'Shows SQL injection vulnerabilities and extracted data.'
    }
  ];

  // Autofocus logic
  useEffect(() => {
    if (targetRef.current && !control._formValues?.target) {
      targetRef.current.focus();
    } else if (emailRef.current && !control._formValues?.email) {
      emailRef.current.focus();
    }
  }, []);

  // Animated error message
  const AnimatedError = ({ message }: { message: string }) => (
    <Fade in={!!message} timeout={400}>
      <Alert severity="error" sx={{ mb: 2 }}>{message}</Alert>
    </Fade>
  );

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto', display: 'flex', gap: 4 }}>
      <Box sx={{ flex: 1, minWidth: 0 }}>
      <Typography variant="h4" sx={{ mb: 2, fontWeight: 700 }}>
        OSINT Gatherer
      </Typography>
      <Alert severity="info" sx={{ mb: 2 }}>
        You can search by <b>target</b> (domain/IP), <b>email</b>, or both. At least one is required.
      </Alert>
      <form onSubmit={handleSubmit(onSubmit)} aria-label="OSINT gather form">
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                  Target (Domain or IP)
                </Typography>
                <Controller
                  name="target"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      label="Domain or IP"
                      fullWidth
                      error={!!errors.target}
                      helperText={errors.target?.message || 'Runs WHOIS and DNS checks.'}
                      inputRef={targetRef}
                      InputProps={{
                        startAdornment: (
                          <InputAdornment position="start">
                            <Tooltip title="Domain or IP address to scan" arrow>
                              <PublicIcon />
                            </Tooltip>
                          </InputAdornment>
                        ),
                      }}
                      inputProps={{ 'aria-label': 'Domain or IP' }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !field.value && emailRef.current) {
                          emailRef.current.focus();
                          e.preventDefault();
                        } else if (e.key === 'Enter' && field.value && (!control._formValues?.email || control._formValues?.email === '')) {
                          // If target is filled but email is empty, move to email
                          if (emailRef.current) emailRef.current.focus();
                          e.preventDefault();
                        }
                      }}
                    />
                  )}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                  Email
                </Typography>
                <Controller
                  name="email"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      label="Email address"
                      fullWidth
                      error={!!errors.email}
                      helperText={errors.email?.message || 'Runs EmailRep.io and Socialscan checks.'}
                      inputRef={emailRef}
                      InputProps={{
                        startAdornment: (
                          <InputAdornment position="start">
                            <Tooltip title="Email address to check" arrow>
                              <EmailIcon />
                            </Tooltip>
                          </InputAdornment>
                        ),
                      }}
                      inputProps={{ 'aria-label': 'Email address' }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !field.value && targetRef.current) {
                          targetRef.current.focus();
                          e.preventDefault();
                        } else if (e.key === 'Enter' && field.value && (!control._formValues?.target || control._formValues?.target === '')) {
                          // If email is filled but target is empty, move to target
                          if (targetRef.current) targetRef.current.focus();
                          e.preventDefault();
                        }
                      }}
                    />
                  )}
                />
              </Grid>
                <Grid item xs={12} md={12}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    Test URL (for SQL Injection)
                  </Typography>
                  <Controller
                    name="url"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Test URL (e.g. http://example.com/page?id=1)"
                        fullWidth
                        error={!!errors.url}
                        helperText={errors.url?.message || 'Runs sqlmap for SQL injection detection.'}
                        inputProps={{ 'aria-label': 'Test URL' }}
                      />
                    )}
                  />
                </Grid>
              <Grid item xs={12}>
                <Divider sx={{ my: 2 }} />
              </Grid>
              {errors?.root && (
                <Grid item xs={12}>
                  <AnimatedError message={errors.root.message} />
                </Grid>
              )}
              <Grid item xs={12}>
                {/* Show which checks will run based on input */}
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    {(() => {
                      const values = control._formValues || {};
                      const checks = getChecksToRun(values.target, values.email);
                      if (checks.length === 0) return null;
                      return (
                        <span>
                          <b>Will run:</b> {checks.join(', ')}
                        </span>
                      );
                    })()}
                  </Typography>
                </Box>
                <Button
                  type="submit"
                  variant="contained"
                  color="primary"
                  startIcon={<SearchIcon />}
                  fullWidth
                  disabled={osintMutation.isLoading}
                  aria-label="Submit OSINT gather form"
                >
                  {osintMutation.isLoading ? 'Gathering...' : 'Gather OSINT'}
                </Button>
              </Grid>
              <Grid item xs={12} sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
                <Button variant="outlined" color="secondary" onClick={handleClear} aria-label="Clear form and results">
                  Clear
                </Button>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </form>

        {osintMutation.error && <AnimatedError message={
          typeof osintMutation.error === 'string'
            ? osintMutation.error
            : osintMutation.error?.message
              ? osintMutation.error.message
              : osintMutation.error?.error
                ? osintMutation.error.error
                : JSON.stringify(osintMutation.error)
        } />}

      {/* Enhanced Live OSINT Preview Panel */}
      <Card sx={{ mb: 2, background: '#f8fafc' }} elevation={0} aria-label="OSINT checks preview">
        <CardContent>
          <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
            <InfoIcon fontSize="small" sx={{ mr: 1, verticalAlign: 'middle' }} />
            OSINT Checks Preview
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            {osintChecks.map((check) => {
              const values = control._formValues || {};
              const active = !!values[check.field];
              return (
                <Tooltip key={check.key} title={<span><b>{check.label}</b><br />{check.desc}</span>} arrow>
                  <Box
                    sx={{
                      opacity: active ? 1 : 0.3,
                      border: active ? '2px solid #1976d2' : '2px dashed #bdbdbd',
                      borderRadius: 2,
                      px: 2,
                      py: 1,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1,
                      transition: 'all 0.3s cubic-bezier(.4,2,.6,1)',
                      background: active ? '#e3f2fd' : 'transparent',
                      boxShadow: active ? '0 2px 8px #1976d220' : 'none',
                    }}
                    aria-label={check.label}
                    tabIndex={0}
                    role="button"
                  >
                    {check.icon}
                    <Box>
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>{check.label}</Typography>
                      <Typography variant="caption" color="text.secondary">{check.desc}</Typography>
                    </Box>
                  </Box>
                </Tooltip>
              );
            })}
          </Box>
        </CardContent>
      </Card>

      {/* Collapsible Results: Only show relevant sections, hide empty ones */}
      {showResults && osintResults && (
        <Fade in={showResults}>
          <Card aria-label="OSINT results">
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  OSINT Gathering Results
                </Typography>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Tooltip title="Download Report">
                    <IconButton onClick={handleDownloadReport} aria-label="Download OSINT report">
                      <DownloadIcon />
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
                role="status"
              >
                OSINT gathering completed successfully!
              </Alert>
              {/* Collapsible/conditional sections with contextual tooltips */}
              {osintResults.osint_data?.whois && Object.keys(osintResults.osint_data.whois).length > 0 && (
                <Accordion defaultExpanded aria-label="WHOIS results">
                  <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="whois-content" id="whois-header">
                    <Tooltip title="Domain registration and ownership info" arrow>
                      <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>WHOIS</Typography>
                    </Tooltip>
                  </AccordionSummary>
                  <AccordionDetails>
                    {renderWhoisData(osintResults.osint_data.whois)}
                  </AccordionDetails>
                </Accordion>
              )}
              {osintResults.osint_data?.dns && Object.keys(osintResults.osint_data.dns).length > 0 && (
                <Accordion defaultExpanded aria-label="DNS results">
                  <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="dns-content" id="dns-header">
                    <Tooltip title="DNS records and security checks" arrow>
                      <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>DNS</Typography>
                    </Tooltip>
                  </AccordionSummary>
                  <AccordionDetails>
                    {renderDnsData(osintResults.osint_data.dns)}
                  </AccordionDetails>
                </Accordion>
              )}
                {osintResults.osint_data?.hunterio && (
                  <Accordion defaultExpanded aria-label="Hunter.io results">
                    <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="hunterio-content" id="hunterio-header">
                      <Tooltip title="Hunter.io email discovery and verification" arrow>
                        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Hunter.io</Typography>
                    </Tooltip>
                  </AccordionSummary>
                  <AccordionDetails>
                      {/* Render Hunter.io results */}
                      {Array.isArray(osintResults.osint_data.hunterio.emails) && osintResults.osint_data.hunterio.emails.length > 0 ? (
                        <TableContainer component={Paper} sx={{ mb: 2, borderRadius: 2, boxShadow: 2 }}>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell>Email</TableCell>
                                <TableCell>Type</TableCell>
                                <TableCell>Confidence</TableCell>
                                <TableCell>Source</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {osintResults.osint_data.hunterio.emails.map((email: any, idx: number) => (
                                <TableRow key={idx}>
                                  <TableCell>{email.value}</TableCell>
                                  <TableCell>{email.type}</TableCell>
                                  <TableCell>{email.confidence}</TableCell>
                                  <TableCell>{email.sources?.map((s: any) => s.domain).join(', ')}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                    ) : (
                        <Alert severity="info">No emails found by Hunter.io.</Alert>
                    )}
                  </AccordionDetails>
                </Accordion>
              )}
                {niktoResult && (
                  <Accordion defaultExpanded aria-label="Nikto results">
                    <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="nikto-content" id="nikto-header">
                      <Tooltip title="Nikto web server vulnerability scan" arrow>
                        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Nikto</Typography>
                      </Tooltip>
                    </AccordionSummary>
                    <AccordionDetails>
                      {niktoError ? (
                        <Alert severity="error" sx={{ mb: 2 }}>{niktoError}</Alert>
                      ) : niktoResult ? (
                        <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13, background: '#f8fafc', padding: 12, borderRadius: 4, border: '1px solid #eee' }}>{niktoResult}</pre>
                      ) : (
                        <Alert severity="info">Nikto did not return any results.</Alert>
                      )}
                    </AccordionDetails>
                  </Accordion>
                )}
                {harvesterResults && (
                  <Accordion defaultExpanded aria-label="theHarvester results">
                    <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="theharvester-content" id="theharvester-header">
                      <Tooltip title="theHarvester email and host discovery" arrow>
                        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>theHarvester</Typography>
                      </Tooltip>
                    </AccordionSummary>
                    <AccordionDetails>
                      {harvesterError ? (
                        <Alert severity="error" sx={{ mb: 2 }}>{harvesterError}</Alert>
                      ) : Array.isArray(harvesterResults.emails) && harvesterResults.emails.length > 0 ? (
                        <List>
                          {harvesterResults.emails.map((email: string, idx: number) => (
                            <ListItem key={idx}>
                              <ListItemIcon>
                                <EmailIcon color="primary" />
                              </ListItemIcon>
                              <ListItemText primary={email} />
                            </ListItem>
                          ))}
                        </List>
                      ) : (
                        <Alert severity="info">No emails found by theHarvester.</Alert>
                      )}
                      {Array.isArray(harvesterResults.hosts) && harvesterResults.hosts.length > 0 && (
                        <>
                          <Divider sx={{ my: 2 }} />
                          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>Hosts</Typography>
                          <List>
                            {harvesterResults.hosts.map((host: string, idx: number) => (
                              <ListItem key={idx}>
                                <ListItemIcon>
                                  <DnsIcon color="primary" />
                                </ListItemIcon>
                                <ListItemText primary={host} />
                              </ListItem>
                            ))}
                          </List>
                        </>
                      )}
                    </AccordionDetails>
                  </Accordion>
                )}
                {sqlmapResult && (
                  <Accordion defaultExpanded aria-label="sqlmap results">
                    <AccordionSummary expandIcon={<ExpandMoreIcon />} aria-controls="sqlmap-content" id="sqlmap-header">
                      <Tooltip title="sqlmap SQL injection scan" arrow>
                        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>sqlmap</Typography>
                      </Tooltip>
                    </AccordionSummary>
                    <AccordionDetails>
                      <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 13, background: '#f8fafc', padding: 12, borderRadius: 4, border: '1px solid #eee' }}>{sqlmapResult}</pre>
                    </AccordionDetails>
                  </Accordion>
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
              title="OSINT Gathering Output"
            />
          </CardContent>
        </Card>
      )}
      </Box>
      {/* Process Details Panel */}
      <Box sx={{ width: 320, minWidth: 220, background: '#181c24', borderRadius: 2, p: 2, boxShadow: 2, height: 'fit-content', position: 'sticky', top: 32 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2, color: '#fff' }}>
          Process Details
        </Typography>
        {osintStepDetails.map(step => {
          // Determine if this step is active based on input
          let isActive = false;
          const values = control._formValues || {};
          if (step.key === 'whois' || step.key === 'dns' || step.key === 'nikto' || step.key === 'theharvester') {
            isActive = !!values.target;
          } else if (step.key === 'hunterio') {
            isActive = !!values.email;
          } else if (step.key === 'sqlmap') {
            isActive = !!values.url;
          }
          return (
            <Box key={step.key} sx={{ mb: 2, opacity: isActive ? 1 : 0.5 }}>
              <Typography variant="body2" sx={{ fontWeight: 600 }}>{step.label}</Typography>
              <Typography variant="caption" sx={{ display: 'block', mb: 0.5 }}>{step.desc}</Typography>
              <Typography variant="caption" sx={{ display: 'block', color: '#90caf9', mb: 0.5 }}>
                <b>Command/API:</b> <code>{
                  step.key === 'whois' || step.key === 'dns' || step.key === 'nikto' || step.key === 'theharvester'
                    ? step.command(values.target || '[target]')
                    : step.key === 'hunterio'
                      ? step.command(values.email || '[email]')
                      : step.key === 'sqlmap'
                        ? step.command(values.url || '[url]')
                        : ''
                }</code>
              </Typography>
              <Typography variant="caption" sx={{ display: 'block', color: '#a5d6a7' }}>{step.outcome}</Typography>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
};

export default OSINTGatherer;