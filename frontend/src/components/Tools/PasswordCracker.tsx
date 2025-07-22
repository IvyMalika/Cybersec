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
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  LinearProgress,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  GetApp as DownloadIcon,
  Lock as LockIcon,
  Security as SecurityIcon,
  VpnKey as KeyIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
  Cancel as CancelIcon,
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

const passwordCrackSchema = yup.object({
  hash: yup.string().required('Hash is required').min(8, 'Hash must be at least 8 characters'),
  hash_type: yup.string().required('Hash type is required'),
  wordlist_id: yup.number().required('Wordlist is required'),
});

interface PasswordCrackFormData {
  hash: string;
  hash_type: string;
  wordlist_id: number;
}

const hashTypes = [
  { value: 'md5', label: 'MD5', description: '32-character hexadecimal hash' },
  { value: 'sha1', label: 'SHA1', description: '40-character hexadecimal hash' },
  { value: 'sha256', label: 'SHA256', description: '64-character hexadecimal hash' },
  { value: 'sha512', label: 'SHA512', description: '128-character hexadecimal hash' },
  { value: 'ntlm', label: 'NTLM', description: 'Windows NTLM hash' },
  { value: 'lm', label: 'LM', description: 'Windows LAN Manager hash' },
];

const wordlists = [
  { id: 1, name: 'rockyou.txt', description: 'Common passwords from data breaches', size: '14M entries' },
  { id: 2, name: 'common-passwords.txt', description: 'Most common passwords', size: '10K entries' },
  { id: 3, name: 'dictionary.txt', description: 'English dictionary words', size: '100K entries' },
  { id: 4, name: 'leaked-passwords.txt', description: 'Passwords from recent leaks', size: '50M entries' },
];

const PasswordCracker: React.FC = () => {
  const [crackResults, setCrackResults] = useState<PasswordCrackResponse | null>(null);
  const [currentJobId, setCurrentJobId] = useState<number | null>(null);
  const [showResults, setShowResults] = useState(false);
  const [isCracking, setIsCracking] = useState(false);
  const [progress, setProgress] = useState(0);

  const {
    control,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<PasswordCrackFormData>({
    resolver: yupResolver(passwordCrackSchema),
    defaultValues: {
      hash: '',
      hash_type: 'md5',
      wordlist_id: 1,
    },
  });

  const selectedHashType = watch('hash_type');
  const selectedWordlist = watch('wordlist_id');

  const crackMutation = useMutation({
    mutationFn: (data: PasswordCrackRequest) => apiClient.crackPassword(data),
    onSuccess: (data: PasswordCrackResponse) => {
      setCrackResults(data);
      setCurrentJobId(data.job_id);
      setShowResults(true);
      setIsCracking(false);
    },
    onError: (error) => {
      console.error('Password cracking failed:', error);
      setIsCracking(false);
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

  const onSubmit = (data: PasswordCrackFormData) => {
    setIsCracking(true);
    setProgress(0);
    
    // Simulate progress updates
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return prev;
        }
        return prev + Math.random() * 10;
      });
    }, 1000);

    crackMutation.mutate(data);
  };

  const handleStopCracking = () => {
    setIsCracking(false);
    setProgress(0);
    // In a real implementation, you would cancel the cracking job
  };

  const handleDownloadReport = async () => {
    if (!currentJobId) return;
    
    try {
      const reportData = await apiClient.getJobReport(currentJobId);
      const blob = new Blob([reportData], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `password_crack_${currentJobId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to download report:', error);
    }
  };

  const getHashTypeInfo = (type: string) => {
    return hashTypes.find(ht => ht.value === type);
  };

  const getWordlistInfo = (id: number) => {
    return wordlists.find(wl => wl.id === id);
  };

  const validateHash = (hash: string, type: string) => {
    const hashLengths: { [key: string]: number } = {
      md5: 32,
      sha1: 40,
      sha256: 64,
      sha512: 128,
      ntlm: 32,
      lm: 32,
    };

    const expectedLength = hashLengths[type];
    return hash.length === expectedLength && /^[a-fA-F0-9]+$/.test(hash);
  };

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Password Cracker
      </Typography>

      <Alert
        severity="warning"
        sx={{
          mb: 3,
          backgroundColor: colors.severity.high + '20',
          color: colors.severity.high,
          border: `1px solid ${colors.severity.high}40`,
        }}
      >
        <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
          Ethical Use Only
        </Typography>
        This tool should only be used for authorized penetration testing, security research, 
        or recovering your own passwords. Unauthorized password cracking is illegal.
      </Alert>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Crack Configuration
              </Typography>

              <form onSubmit={handleSubmit(onSubmit)}>
                <Controller
                  name="hash"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      fullWidth
                      label="Hash Value"
                      placeholder="Enter hash to crack"
                      error={!!errors.hash}
                      helperText={errors.hash?.message}
                      sx={{ mb: 2 }}
                      multiline
                      rows={3}
                      InputProps={{
                        style: { fontFamily: 'monospace' },
                      }}
                    />
                  )}
                />

                <Controller
                  name="hash_type"
                  control={control}
                  render={({ field }) => (
                    <FormControl fullWidth sx={{ mb: 2 }}>
                      <InputLabel>Hash Type</InputLabel>
                      <Select {...field} label="Hash Type">
                        {hashTypes.map((type) => (
                          <MenuItem key={type.value} value={type.value}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <LockIcon />
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
                  name="wordlist_id"
                  control={control}
                  render={({ field }) => (
                    <FormControl fullWidth sx={{ mb: 3 }}>
                      <InputLabel>Wordlist</InputLabel>
                      <Select {...field} label="Wordlist">
                        {wordlists.map((wordlist) => (
                          <MenuItem key={wordlist.id} value={wordlist.id}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <KeyIcon />
                              <Box>
                                <Typography variant="body1">{wordlist.name}</Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {wordlist.description} - {wordlist.size}
                                </Typography>
                              </Box>
                            </Box>
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  )}
                />

                {!isCracking ? (
                  <Button
                    type="submit"
                    fullWidth
                    variant="contained"
                    disabled={crackMutation.isPending}
                    startIcon={crackMutation.isPending ? <CircularProgress size={20} /> : <PlayIcon />}
                    sx={{
                      backgroundColor: colors.primary.main,
                      '&:hover': {
                        backgroundColor: colors.primary.dark,
                      },
                    }}
                  >
                    {crackMutation.isPending ? 'Starting...' : 'Start Cracking'}
                  </Button>
                ) : (
                  <Box>
                    <LinearProgress
                      variant="determinate"
                      value={progress}
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
                        Progress: {Math.round(progress)}%
                      </Typography>
                      <Chip
                        label="CRACKING"
                        size="small"
                        sx={{
                          backgroundColor: colors.status.warning + '30',
                          color: colors.status.warning,
                          animation: 'pulse 2s infinite',
                        }}
                      />
                    </Box>
                    <Button
                      fullWidth
                      variant="outlined"
                      onClick={handleStopCracking}
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
                      Stop Cracking
                    </Button>
                  </Box>
                )}
              </form>

              {crackMutation.error && (
                <Alert
                  severity="error"
                  sx={{
                    mt: 2,
                    backgroundColor: colors.severity.critical + '20',
                    color: colors.severity.critical,
                    border: `1px solid ${colors.severity.critical}40`,
                  }}
                >
                  {typeof crackMutation.error === 'string'
                    ? crackMutation.error
                    : crackMutation.error?.message
                      ? crackMutation.error.message
                      : crackMutation.error?.error
                        ? crackMutation.error.error
                        : JSON.stringify(crackMutation.error)}
                </Alert>
              )}
            </CardContent>
          </Card>

          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Hash Information
              </Typography>
              {getHashTypeInfo(selectedHashType) && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Selected Hash Type: {getHashTypeInfo(selectedHashType)?.label}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {getHashTypeInfo(selectedHashType)?.description}
                  </Typography>
                </Box>
              )}
              
              {getWordlistInfo(selectedWordlist) && (
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Selected Wordlist: {getWordlistInfo(selectedWordlist)?.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {getWordlistInfo(selectedWordlist)?.description}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Size: {getWordlistInfo(selectedWordlist)?.size}
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          {isCracking && (
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <ScanProgress 
                  jobId={currentJobId} 
                  isActive={isCracking}
                  onComplete={() => {
                    setIsCracking(false);
                  }}
                />
              </CardContent>
            </Card>
          )}

          {showResults && crackResults && (
            <Fade in={showResults}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      Password Cracking Results
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
                    severity={crackResults.cracked ? 'success' : 'info'}
                    sx={{
                      mb: 2,
                      backgroundColor: crackResults.cracked ? 
                        colors.severity.low + '20' : colors.severity.info + '20',
                      color: crackResults.cracked ? 
                        colors.severity.low : colors.severity.info,
                      border: `1px solid ${crackResults.cracked ? 
                        colors.severity.low : colors.severity.info}40`,
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {crackResults.cracked ? <CheckIcon /> : <CancelIcon />}
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                        {crackResults.cracked ? 'Password Successfully Cracked!' : 'Password Not Found'}
                      </Typography>
                    </Box>
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      {crackResults.cracked ? 
                        'The password has been successfully recovered from the hash.' :
                        'The password was not found in the selected wordlist. Try a different wordlist or hash type.'}
                    </Typography>
                  </Alert>

                  <Divider sx={{ mb: 2 }} />

                  <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                    Crack Details
                  </Typography>

                  <TableContainer component={Paper} sx={{ backgroundColor: colors.background.paper }}>
                    <Table>
                      <TableBody>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                          <TableCell>
                            <Chip
                              label={crackResults.cracked ? 'SUCCESS' : 'FAILED'}
                              size="small"
                              icon={crackResults.cracked ? <CheckIcon /> : <CancelIcon />}
                              sx={{
                                backgroundColor: crackResults.cracked ? 
                                  colors.severity.low + '30' : colors.severity.critical + '30',
                                color: crackResults.cracked ? 
                                  colors.severity.low : colors.severity.critical,
                              }}
                            />
                          </TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 600 }}>Job ID</TableCell>
                          <TableCell sx={{ fontFamily: 'monospace' }}>
                            {crackResults.job_id}
                          </TableCell>
                        </TableRow>
                        {crackResults.cracked && crackResults.password && (
                          <TableRow>
                            <TableCell sx={{ fontWeight: 600 }}>Cracked Password</TableCell>
                            <TableCell>
                              <Box
                                sx={{
                                  backgroundColor: colors.severity.low + '20',
                                  p: 2,
                                  borderRadius: 1,
                                  border: `1px solid ${colors.severity.low}40`,
                                  fontFamily: 'monospace',
                                  fontSize: '1.1rem',
                                  fontWeight: 600,
                                  color: colors.severity.low,
                                }}
                              >
                                {crackResults.password}
                              </Box>
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </TableContainer>

                  {crackResults.cracked && (
                    <Alert
                      severity="warning"
                      sx={{
                        mt: 2,
                        backgroundColor: colors.severity.high + '20',
                        color: colors.severity.high,
                        border: `1px solid ${colors.severity.high}40`,
                      }}
                    >
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                        Security Recommendations
                      </Typography>
                      <List dense>
                        <ListItem sx={{ pl: 0 }}>
                          <ListItemIcon>
                            <WarningIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText
                            primary="Use stronger passwords with mixed case, numbers, and symbols"
                            primaryTypographyProps={{ fontSize: '0.875rem' }}
                          />
                        </ListItem>
                        <ListItem sx={{ pl: 0 }}>
                          <ListItemIcon>
                            <WarningIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText
                            primary="Avoid common passwords and dictionary words"
                            primaryTypographyProps={{ fontSize: '0.875rem' }}
                          />
                        </ListItem>
                        <ListItem sx={{ pl: 0 }}>
                          <ListItemIcon>
                            <WarningIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText
                            primary="Consider using a password manager"
                            primaryTypographyProps={{ fontSize: '0.875rem' }}
                          />
                        </ListItem>
                      </List>
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
                  title="Password Cracking Output"
                />
              </CardContent>
            </Card>
          )}
        </Grid>
      </Grid>
    </Box>
  );
};

export default PasswordCracker;