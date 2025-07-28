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
  Lock as LockIcon,
  Security as SecurityIcon,
  ExpandMore as ExpandMoreIcon,
  ErrorOutline as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  MoreVert as MoreVertIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  Assessment as AssessmentIcon,
  Key as KeyIcon,
  Password as PasswordIcon,
  Speed as SpeedIcon,
  Timer as TimerIcon,
} from '@mui/icons-material';
import { useForm, Controller } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { useMutation, useQuery } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { PasswordCrackRequest, PasswordCrackResponse } from '../../types/api';
import TerminalOutput from '../Common/TerminalOutput';
import ScanProgress from '../Common/ScanProgress';

const passwordSchema = yup.object({
  hash: yup.string().required('Hash is required'),
  attack_type: yup.string().required('Attack type is required'),
  wordlist: yup.string().when('attack_type', {
    is: 'dictionary',
    then: yup.string().required('Wordlist is required'),
  }),
  min_length: yup.number().min(1).max(20).when('attack_type', {
    is: 'bruteforce',
    then: yup.number().required('Minimum length is required'),
  }),
  max_length: yup.number().min(1).max(20).when('attack_type', {
    is: 'bruteforce',
    then: yup.number().required('Maximum length is required'),
  }),
});

interface PasswordFormData {
  hash: string;
  attack_type: 'dictionary' | 'bruteforce' | 'rainbow';
  wordlist?: string;
  min_length?: number;
  max_length?: number;
}

const attackTypes = [
  {
    value: 'dictionary',
    label: 'Dictionary Attack',
    description: 'Use wordlists to crack passwords',
    icon: <PasswordIcon />,
    color: colors.primary.main,
  },
  {
    value: 'bruteforce',
    label: 'Brute Force',
    description: 'Try all possible combinations',
    icon: <KeyIcon />,
    color: colors.accent.fuchsia,
  },
  {
    value: 'rainbow',
    label: 'Rainbow Table',
    description: 'Use precomputed hash tables',
    icon: <SecurityIcon />,
    color: colors.accent.orange,
  },
];

const wordlists = [
  { value: 'rockyou.txt', label: 'RockYou', description: 'Popular password list' },
  { value: 'common.txt', label: 'Common', description: 'Common passwords' },
  { value: 'custom.txt', label: 'Custom', description: 'Custom wordlist' },
];

const PasswordStatCard: React.FC<{
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

const PasswordCracker: React.FC = () => {
  const [crackResults, setCrackResults] = useState<PasswordCrackResponse | null>(null);
  const [currentJobId, setCurrentJobId] = useState<number | null>(null);
  const [showResults, setShowResults] = useState(false);

  const {
    control,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<PasswordFormData>({
    resolver: yupResolver(passwordSchema),
    defaultValues: {
      hash: '',
      attack_type: 'dictionary',
      wordlist: 'rockyou.txt',
      min_length: 4,
      max_length: 8,
    },
  });

  const selectedAttackType = watch('attack_type');
  const selectedAttackTypeData = attackTypes.find(type => type.value === selectedAttackType);

  const crackMutation = useMutation({
    mutationFn: (data: PasswordCrackRequest) => apiClient.runPasswordCrack(data),
    onSuccess: (response) => {
      setCurrentJobId(response.job_id);
      setCrackResults(response);
    },
    onError: (error) => {
      console.error('Password cracking failed:', error);
    },
  });

  const { data: jobStatus } = useQuery({
    queryKey: ['job', currentJobId],
    queryFn: () => apiClient.getJobStatus(currentJobId!),
    enabled: !!currentJobId,
    refetchInterval: 2000,
  });

  const onSubmit = (data: PasswordFormData) => {
    crackMutation.mutate({
      hash: data.hash,
      attack_type: data.attack_type,
      wordlist: data.wordlist,
      min_length: data.min_length,
      max_length: data.max_length,
    });
  };

  const handleDownloadReport = async () => {
    if (crackResults) {
      try {
        const response = await apiClient.downloadReport(crackResults.job_id);
        const blob = new Blob([response], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `password-crack-${crackResults.job_id}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } catch (error) {
        console.error('Download failed:', error);
      }
    }
  };

  const getHashType = (hash: string) => {
    if (hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$')) return 'bcrypt';
    if (hash.startsWith('$1$')) return 'MD5 Crypt';
    if (hash.startsWith('$5$')) return 'SHA256 Crypt';
    if (hash.startsWith('$6$')) return 'SHA512 Crypt';
    if (hash.length === 32) return 'MD5';
    if (hash.length === 40) return 'SHA1';
    if (hash.length === 64) return 'SHA256';
    return 'Unknown';
  };

  const getPasswordStrength = (password: string) => {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    
    if (score <= 2) return { level: 'Weak', color: colors.severity.critical };
    if (score <= 3) return { level: 'Medium', color: colors.severity.high };
    if (score <= 4) return { level: 'Strong', color: colors.severity.medium };
    return { level: 'Very Strong', color: colors.severity.low };
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 700, color: colors.text.primary }}>
          Password Cracker
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
        {/* Crack Configuration Card */}
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
                <LockIcon sx={{ mr: 2, color: colors.accent.orange, fontSize: 28 }} />
                <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                  Crack Configuration
                </Typography>
              </Box>

              <form onSubmit={handleSubmit(onSubmit)}>
                <Box sx={{ mb: 3 }}>
                  <Controller
                    name="hash"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="Password Hash"
                        placeholder="Enter hash to crack"
                        fullWidth
                        multiline
                        rows={3}
                        error={!!errors.hash}
                        helperText={errors.hash?.message}
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
                    name="attack_type"
                    control={control}
                    render={({ field }) => (
                      <FormControl fullWidth>
                        <InputLabel>Attack Type</InputLabel>
                        <Select {...field} label="Attack Type">
                          {attackTypes.map((type) => (
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

                {selectedAttackType === 'dictionary' && (
                  <Box sx={{ mb: 3 }}>
                    <Controller
                      name="wordlist"
                      control={control}
                      render={({ field }) => (
                        <FormControl fullWidth>
                          <InputLabel>Wordlist</InputLabel>
                          <Select {...field} label="Wordlist">
                            {wordlists.map((wordlist) => (
                              <MenuItem key={wordlist.value} value={wordlist.value}>
                                <Box>
                                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                                    {wordlist.label}
                                  </Typography>
                                  <Typography variant="caption" sx={{ color: colors.text.secondary }}>
                                    {wordlist.description}
                                  </Typography>
                                </Box>
                              </MenuItem>
                            ))}
                          </Select>
                        </FormControl>
                      )}
                    />
                  </Box>
                )}

                {selectedAttackType === 'bruteforce' && (
                  <Grid container spacing={2} sx={{ mb: 3 }}>
                    <Grid item xs={6}>
                      <Controller
                        name="min_length"
                        control={control}
                        render={({ field }) => (
                          <TextField
                            {...field}
                            label="Min Length"
                            type="number"
                            fullWidth
                            error={!!errors.min_length}
                            helperText={errors.min_length?.message}
                            inputProps={{ min: 1, max: 20 }}
                            sx={{
                              '& .MuiOutlinedInput-root': {
                                backgroundColor: colors.background.elevated,
                              },
                            }}
                          />
                        )}
                      />
                    </Grid>
                    <Grid item xs={6}>
                      <Controller
                        name="max_length"
                        control={control}
                        render={({ field }) => (
                          <TextField
                            {...field}
                            label="Max Length"
                            type="number"
                            fullWidth
                            error={!!errors.max_length}
                            helperText={errors.max_length?.message}
                            inputProps={{ min: 1, max: 20 }}
                            sx={{
                              '& .MuiOutlinedInput-root': {
                                backgroundColor: colors.background.elevated,
                              },
                            }}
                          />
                        )}
                      />
                    </Grid>
                  </Grid>
                )}

                <Button
                  type="submit"
                  variant="contained"
                  fullWidth
                  disabled={crackMutation.isPending}
                  startIcon={crackMutation.isPending ? <CircularProgress size={20} /> : <PlayIcon />}
                  sx={{
                    backgroundColor: colors.accent.orange,
                    '&:hover': {
                      backgroundColor: colors.accent.orange + 'CC',
                    },
                    py: 1.5,
                  }}
                >
                  {crackMutation.isPending ? 'Starting Crack...' : 'Start Password Crack'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </Grid>

        {/* Crack Progress and Results */}
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
                    Crack Progress
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

          {/* Crack Results */}
          {crackResults && jobStatus?.status === 'completed' && (
            <>
              {/* Hash Information */}
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
                      Hash Information
                    </Typography>
                    <IconButton size="small">
                      <MoreVertIcon sx={{ color: colors.text.secondary }} />
                    </IconButton>
                  </Box>

                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6} md={3}>
                      <PasswordStatCard
                        title="Hash Type"
                        value={getHashType(crackResults.hash)}
                        color={colors.accent.blue}
                        icon={<SecurityIcon />}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                      <PasswordStatCard
                        title="Attempts Made"
                        value={crackResults.attempts_made || 0}
                        color={colors.primary.main}
                        icon={<SpeedIcon />}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                      <PasswordStatCard
                        title="Time Elapsed"
                        value={`${crackResults.time_elapsed || 0}s`}
                        color={colors.accent.teal}
                        icon={<TimerIcon />}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6} md={3}>
                      <PasswordStatCard
                        title="Success Rate"
                        value={crackResults.success ? '100%' : '0%'}
                        color={crackResults.success ? colors.severity.low : colors.severity.critical}
                        icon={<AssessmentIcon />}
                      />
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>

              {/* Crack Results */}
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
                    Crack Results
                  </Typography>

                  {crackResults.success ? (
                    <Box>
                      <Alert
                        severity="success"
                        sx={{
                          mb: 3,
                          backgroundColor: alpha(colors.severity.low, 0.1),
                          border: `1px solid ${colors.severity.low}40`,
                          color: colors.severity.low,
                        }}
                      >
                        Password successfully cracked!
                      </Alert>

                      <Card
                        sx={{
                          backgroundColor: alpha(colors.severity.low, 0.1),
                          border: `1px solid ${colors.severity.low}40`,
                          borderRadius: 2,
                          p: 3,
                        }}
                      >
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                          <KeyIcon sx={{ mr: 2, color: colors.severity.low }} />
                          <Typography variant="h6" sx={{ color: colors.text.primary, fontWeight: 600 }}>
                            Cracked Password
                          </Typography>
                        </Box>
                        
                        <Typography
                          variant="h4"
                          sx={{
                            fontFamily: 'monospace',
                            backgroundColor: colors.background.elevated,
                            p: 2,
                            borderRadius: 1,
                            color: colors.text.primary,
                            textAlign: 'center',
                            letterSpacing: 2,
                          }}
                        >
                          {crackResults.password}
                        </Typography>

                        <Box sx={{ mt: 2 }}>
                          {(() => {
                            const strength = getPasswordStrength(crackResults.password);
                            return (
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                                  Password Strength:
                                </Typography>
                                <Chip
                                  label={strength.level}
                                  size="small"
                                  sx={{
                                    backgroundColor: strength.color,
                                    color: colors.text.primary,
                                    fontWeight: 600,
                                  }}
                                />
                              </Box>
                            );
                          })()}
                        </Box>
                      </Card>
                    </Box>
                  ) : (
                    <Alert
                      severity="warning"
                      sx={{
                        backgroundColor: alpha(colors.severity.high, 0.1),
                        border: `1px solid ${colors.severity.high}40`,
                        color: colors.severity.high,
                      }}
                    >
                      Password could not be cracked with the current configuration.
                    </Alert>
                  )}
                </CardContent>
              </Card>

              {/* Performance Metrics */}
              {crackResults.performance_metrics && (
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
                      Performance Metrics
                    </Typography>

                    <TableContainer component={Paper} sx={{ backgroundColor: colors.background.elevated }}>
                      <Table>
                        <TableHead>
                          <TableRow>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Metric</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Value</TableCell>
                            <TableCell sx={{ color: colors.text.primary, fontWeight: 600 }}>Status</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {Object.entries(crackResults.performance_metrics).map(([key, value]) => (
                            <TableRow key={key}>
                              <TableCell sx={{ color: colors.text.primary }}>
                                {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                              </TableCell>
                              <TableCell sx={{ color: colors.text.secondary }}>
                                {typeof value === 'number' ? value.toLocaleString() : String(value)}
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label="Completed"
                                  size="small"
                                  color="success"
                                  sx={{
                                    backgroundColor: colors.severity.low,
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

export default PasswordCracker;