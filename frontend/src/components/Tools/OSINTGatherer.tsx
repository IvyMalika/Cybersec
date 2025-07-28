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
  alpha,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  GetApp as DownloadIcon,
  Visibility as ViewIcon,
  PersonSearch as PersonSearchIcon,
  Security as SecurityIcon,
  ExpandMore as ExpandMoreIcon,
  ErrorOutline as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  MoreVert as MoreVertIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  Assessment as AssessmentIcon,
  Web as WebIcon,
  Email as EmailIcon,
  Phone as PhoneIcon,
  LocationOn as LocationIcon,
  Business as BusinessIcon,
  Link as LinkIcon,
  Public as PublicIcon,
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

const osintSchema = yup.object({
  target: yup.string().required('Target is required'),
  search_type: yup.string().required('Search type is required'),
  platforms: yup.array().min(1, 'Select at least one platform'),
});

interface OSINTFormData {
  target: string;
  search_type: 'username' | 'email' | 'domain' | 'phone';
  platforms: string[];
}

const searchTypes = [
  {
    value: 'username',
    label: 'Username Search',
    description: 'Find accounts across social platforms',
    icon: <PersonSearchIcon />,
    color: colors.primary.main,
  },
  {
    value: 'email',
    label: 'Email Search',
    description: 'Find email-related information',
    icon: <EmailIcon />,
    color: colors.accent.fuchsia,
  },
  {
    value: 'domain',
    label: 'Domain Search',
    description: 'Gather domain intelligence',
    icon: <WebIcon />,
    color: colors.accent.blue,
  },
  {
    value: 'phone',
    label: 'Phone Search',
    description: 'Find phone-related information',
    icon: <PhoneIcon />,
    color: colors.accent.orange,
  },
];

const platforms = [
  { value: 'twitter', label: 'Twitter', icon: <PublicIcon /> },
  { value: 'github', label: 'GitHub', icon: <BusinessIcon /> },
  { value: 'linkedin', label: 'LinkedIn', icon: <BusinessIcon /> },
  { value: 'instagram', label: 'Instagram', icon: <PublicIcon /> },
  { value: 'facebook', label: 'Facebook', icon: <PublicIcon /> },
  { value: 'reddit', label: 'Reddit', icon: <PublicIcon /> },
  { value: 'discord', label: 'Discord', icon: <PublicIcon /> },
  { value: 'telegram', label: 'Telegram', icon: <PublicIcon /> },
];

const OSINTStatCard: React.FC<{
  title: string;
  value: string | number;
  color: string;
  icon: React.ReactNode;
  subtitle?: string;
}> = ({ title, value, color, icon, subtitle }) => (
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
          <Typography variant="h5" sx={{ fontWeight: 700, color, mb: 0.5 }}>
            {value}
          </Typography>
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

const OSINTGatherer: React.FC = () => {
  const [osintResults, setOsintResults] = useState<OSINTResponse | null>(null);
  const [currentJobId, setCurrentJobId] = useState<number | null>(null);
  const [showResults, setShowResults] = useState(false);

  const {
    control,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<OSINTFormData>({
    resolver: yupResolver(osintSchema),
    defaultValues: {
      target: '',
      search_type: 'username',
      platforms: ['twitter', 'github'],
    },
  });

  const selectedSearchType = watch('search_type');
  const selectedSearchTypeData = searchTypes.find(type => type.value === selectedSearchType);

  const osintMutation = useMutation({
    mutationFn: (data: OSINTRequest) => apiClient.runOSINTSearch(data),
    onSuccess: (response) => {
      setCurrentJobId(response.job_id);
      setOsintResults(response);
    },
    onError: (error) => {
      console.error('OSINT search failed:', error);
    },
  });

  const { data: jobStatus } = useQuery({
    queryKey: ['job', currentJobId],
    queryFn: () => apiClient.getJobStatus(currentJobId!),
    enabled: !!currentJobId,
    refetchInterval: 2000,
  });

  const onSubmit = (data: OSINTFormData) => {
    osintMutation.mutate({
      target: data.target,
      search_type: data.search_type,
      platforms: data.platforms,
    });
  };

  const handleDownloadReport = async () => {
    if (osintResults) {
      try {
        const response = await apiClient.downloadReport(osintResults.job_id);
        const blob = new Blob([response], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `osint-search-${osintResults.job_id}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } catch (error) {
        console.error('Download failed:', error);
      }
    }
  };

  const getPlatformIcon = (platform: string) => {
    const platformData = platforms.find(p => p.value === platform);
    return platformData?.icon || <PublicIcon />;
  };

  const getPlatformColor = (platform: string) => {
    const colors = {
      twitter: '#1DA1F2',
      github: '#333',
      linkedin: '#0077B5',
      instagram: '#E4405F',
      facebook: '#1877F2',
      reddit: '#FF4500',
      discord: '#5865F2',
      telegram: '#0088CC',
    };
    return colors[platform as keyof typeof colors] || colors.twitter;
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 700, color: colors.text.primary }}>
          OSINT Intelligence Gatherer
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
        {/* Search Configuration Card */}
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
                <PersonSearchIcon sx={{ mr: 2, color: colors.accent.fuchsia, fontSize: 28 }} />
                <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                  Search Configuration
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
                        label="Target"
                        placeholder="Enter username, email, domain, or phone"
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
                    name="search_type"
                    control={control}
                    render={({ field }) => (
                      <FormControl fullWidth>
                        <InputLabel>Search Type</InputLabel>
                        <Select {...field} label="Search Type">
                          {searchTypes.map((type) => (
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

                <Box sx={{ mb: 3 }}>
                  <Controller
                    name="platforms"
                    control={control}
                    render={({ field }) => (
                      <FormControl fullWidth>
                        <InputLabel>Platforms</InputLabel>
                        <Select
                          {...field}
                          multiple
                          label="Platforms"
                          renderValue={(selected) => (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                              {selected.map((value) => (
                                <Chip
                                  key={value}
                                  label={platforms.find(p => p.value === value)?.label}
                                  size="small"
                                  sx={{
                                    backgroundColor: alpha(getPlatformColor(value), 0.2),
                                    color: getPlatformColor(value),
                                  }}
                                />
                              ))}
                            </Box>
                          )}
                        >
                          {platforms.map((platform) => (
                            <MenuItem key={platform.value} value={platform.value}>
                              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <Box
                                  sx={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    width: 24,
                                    height: 24,
                                    borderRadius: '50%',
                                    backgroundColor: alpha(getPlatformColor(platform.value), 0.2),
                                    color: getPlatformColor(platform.value),
                                    mr: 2,
                                  }}
                                >
                                  {platform.icon}
                                </Box>
                                <Typography variant="body2">{platform.label}</Typography>
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
                  disabled={osintMutation.isPending}
                  startIcon={osintMutation.isPending ? <CircularProgress size={20} /> : <PlayIcon />}
                  sx={{
                    backgroundColor: colors.accent.fuchsia,
                    '&:hover': {
                      backgroundColor: colors.accent.fuchsia + 'CC',
                    },
                    py: 1.5,
                  }}
                >
                  {osintMutation.isPending ? 'Starting Search...' : 'Start OSINT Search'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </Grid>

        {/* Search Progress and Results */}
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
                    Search Progress
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

          {/* Search Results */}
          {osintResults && jobStatus?.status === 'completed' && (
            <>
              {/* Search Statistics */}
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
                      Search Statistics
                    </Typography>
                    <IconButton size="small">
                      <MoreVertIcon sx={{ color: colors.text.secondary }} />
                    </IconButton>
                  </Box>

                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6} md={3}>
                      <OSINTStatCard
                        title="Platforms Searched"
                        value={osintResults.platforms_searched || 0}
                        color={colors.accent.blue}
                        icon={<WebIcon />}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                      <OSINTStatCard
                        title="Accounts Found"
                        value={osintResults.accounts_found || 0}
                        color={colors.primary.main}
                        icon={<PersonSearchIcon />}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                      <OSINTStatCard
                        title="Emails Found"
                        value={osintResults.emails_found || 0}
                        color={colors.accent.fuchsia}
                        icon={<EmailIcon />}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                      <OSINTStatCard
                        title="Domains Found"
                        value={osintResults.domains_found || 0}
                        color={colors.accent.orange}
                        icon={<WebIcon />}
                      />
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>

              {/* Platform Results */}
              {osintResults.platform_results && (
                <Card
                  sx={{
                    backgroundColor: colors.background.paper,
                    border: `1px solid ${colors.border.primary}`,
                    borderRadius: 2,
                    mb: 3,
                  }}
                >
                  <CardContent sx={{ p: 3 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600, mb: 3, color: colors.text.primary }}>
                      Platform Results
                    </Typography>

                    {Object.entries(osintResults.platform_results).map(([platform, results]: [string, any]) => (
                      <Accordion
                        key={platform}
                        sx={{
                          backgroundColor: colors.background.elevated,
                          mb: 1,
                          '&:before': { display: 'none' },
                        }}
                      >
                        <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: colors.text.secondary }} />}>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <Box
                              sx={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                width: 32,
                                height: 32,
                                borderRadius: '50%',
                                backgroundColor: alpha(getPlatformColor(platform), 0.2),
                                color: getPlatformColor(platform),
                                mr: 2,
                              }}
                            >
                              {getPlatformIcon(platform)}
                            </Box>
                            <Box>
                              <Typography sx={{ fontWeight: 600, color: colors.text.primary }}>
                                {platform.charAt(0).toUpperCase() + platform.slice(1)}
                              </Typography>
                              <Typography variant="caption" sx={{ color: colors.text.secondary }}>
                                {results.length} results found
                              </Typography>
                            </Box>
                          </Box>
                        </AccordionSummary>
                        <AccordionDetails>
                          <List>
                            {results.map((result: any, index: number) => (
                              <ListItem key={index} sx={{ py: 0.5 }}>
                                <ListItemIcon>
                                  <LinkIcon sx={{ color: colors.accent.blue, fontSize: 16 }} />
                                </ListItemIcon>
                                <ListItemText
                                  primary={result.username || result.email || result.url}
                                  secondary={result.bio || result.description}
                                  primaryTypographyProps={{
                                    variant: 'body2',
                                    color: colors.text.primary,
                                  }}
                                  secondaryTypographyProps={{
                                    variant: 'caption',
                                    color: colors.text.secondary,
                                  }}
                                />
                                {result.url && (
                                  <IconButton
                                    size="small"
                                    href={result.url}
                                    target="_blank"
                                    sx={{ color: colors.accent.blue }}
                                  >
                                    <ViewIcon />
                                  </IconButton>
                                )}
                              </ListItem>
                            ))}
                          </List>
                        </AccordionDetails>
                      </Accordion>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Email Intelligence */}
              {osintResults.email_intelligence && (
                <Card
                  sx={{
                    backgroundColor: colors.background.paper,
                    border: `1px solid ${colors.border.primary}`,
                    borderRadius: 2,
                    mb: 3,
                  }}
                >
                  <CardContent sx={{ p: 3 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600, mb: 3, color: colors.text.primary }}>
                      Email Intelligence
                    </Typography>

                    <TableContainer component={Paper} sx={{ backgroundColor: colors.background.elevated }}>
                      <Table>
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Email</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Domain</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Breach Status</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Risk Level</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {osintResults.email_intelligence.map((email: any, index: number) => (
                            <TableRow key={index}>
                              <TableCell sx={{ color: colors.text.primary }}>{email.email}</TableCell>
                              <TableCell sx={{ color: colors.text.primary }}>{email.domain}</TableCell>
                              <TableCell>
                                <Chip
                                  label={email.breached ? 'Breached' : 'Safe'}
                                  size="small"
                                  color={email.breached ? 'error' : 'success'}
                                  sx={{
                                    backgroundColor: email.breached ? colors.severity.critical : colors.severity.low,
                                    color: colors.text.primary,
                                  }}
                                />
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={email.risk_level}
                                  size="small"
                                  sx={{
                                    backgroundColor: getPlatformColor(email.risk_level),
                                    color: colors.text.primary,
                                  }}
                                />
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </CardContent>
                </Card>
              )}
            </>
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

export default OSINTGatherer;