import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  LinearProgress,
  Chip,
  Button,
  Alert,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  IconButton,
  Tooltip,
  Fade,
  CircularProgress,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Pause as PauseIcon,
  Stop as StopIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { Job } from '../../types/api';

interface ScanProgressProps {
  jobId: number | null;
  isActive: boolean;
  onComplete?: () => void;
  onError?: (error: string) => void;
}

const ScanProgress: React.FC<ScanProgressProps> = ({
  jobId,
  isActive,
  onComplete,
  onError,
}) => {
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);
  const [startTime, setStartTime] = useState<Date | null>(null);
  const [elapsedTime, setElapsedTime] = useState(0);

  const {
    data: job,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => apiClient.getJob(jobId!),
    enabled: !!jobId,
    refetchInterval: isActive ? 1000 : false,
  });

  const scanSteps = [
    'Initializing scan',
    'Resolving target',
    'Port scanning',
    'Service detection',
    'Vulnerability analysis',
    'Generating report',
    'Completed',
  ];

  useEffect(() => {
    if (isActive && !startTime) {
      setStartTime(new Date());
    }
  }, [isActive, startTime]);

  useEffect(() => {
    if (isActive && startTime) {
      const interval = setInterval(() => {
        setElapsedTime(Math.floor((new Date().getTime() - startTime.getTime()) / 1000));
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [isActive, startTime]);

  useEffect(() => {
    if (job) {
      switch (job.status) {
        case 'pending':
          setCurrentStep(0);
          setProgress(10);
          break;
        case 'running':
          setCurrentStep(Math.min(currentStep + 1, scanSteps.length - 2));
          setProgress(Math.min(progress + 15, 90));
          break;
        case 'completed':
          setCurrentStep(scanSteps.length - 1);
          setProgress(100);
          onComplete?.();
          break;
        case 'failed':
          onError?.(job.error || 'Scan failed');
          break;
      }
    }
  }, [job, currentStep, progress, onComplete, onError]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending':
        return colors.status.warning;
      case 'running':
        return colors.primary.main;
      case 'completed':
        return colors.severity.low;
      case 'failed':
        return colors.severity.critical;
      default:
        return colors.text.secondary;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending':
        return <PlayIcon />;
      case 'running':
        return <CircularProgress size={16} />;
      case 'completed':
        return <CheckIcon />;
      case 'failed':
        return <ErrorIcon />;
      default:
        return <PlayIcon />;
    }
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const handleCancel = async () => {
    if (jobId) {
      try {
        await apiClient.cancelJob(jobId);
        refetch();
      } catch (error) {
        console.error('Failed to cancel job:', error);
      }
    }
  };

  if (!jobId || !job) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <Typography variant="body2" color="text.secondary">
          No active scan
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Typography variant="h6" sx={{ fontWeight: 600 }}>
          Scan Progress
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Chip
            label={job.status}
            size="small"
            icon={getStatusIcon(job.status)}
            sx={{
              backgroundColor: getStatusColor(job.status) + '30',
              color: getStatusColor(job.status),
            }}
          />
          <Typography variant="body2" color="text.secondary">
            {formatTime(elapsedTime)}
          </Typography>
        </Box>
      </Box>

      <LinearProgress
        variant="determinate"
        value={progress}
        sx={{
          height: 8,
          borderRadius: 4,
          backgroundColor: colors.background.elevated,
          '& .MuiLinearProgress-bar': {
            backgroundColor: getStatusColor(job.status),
            borderRadius: 4,
          },
        }}
      />

      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 1 }}>
        <Typography variant="body2" color="text.secondary">
          {progress}% Complete
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh">
            <IconButton size="small" onClick={() => refetch()}>
              <RefreshIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          {job.status === 'running' && (
            <Tooltip title="Cancel Scan">
              <IconButton size="small" onClick={handleCancel}>
                <StopIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
        </Box>
      </Box>

      <Fade in={isActive}>
        <Box sx={{ mt: 2 }}>
          <Stepper activeStep={currentStep} orientation="vertical">
            {scanSteps.map((step, index) => (
              <Step key={step}>
                <StepLabel
                  StepIconProps={{
                    sx: {
                      color: index <= currentStep ? getStatusColor(job.status) : colors.text.secondary,
                    },
                  }}
                >
                  <Typography
                    variant="body2"
                    sx={{
                      color: index <= currentStep ? colors.text.primary : colors.text.secondary,
                      fontWeight: index === currentStep ? 600 : 400,
                    }}
                  >
                    {step}
                  </Typography>
                </StepLabel>
                {index === currentStep && job.status === 'running' && (
                  <StepContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <CircularProgress size={16} />
                      <Typography variant="body2" color="text.secondary">
                        Processing...
                      </Typography>
                    </Box>
                  </StepContent>
                )}
              </Step>
            ))}
          </Stepper>
        </Box>
      </Fade>

      {error && (
        <Alert
          severity="error"
          sx={{
            mt: 2,
            backgroundColor: colors.severity.critical + '20',
            color: colors.severity.critical,
            border: `1px solid ${colors.severity.critical}40`,
          }}
        >
          Failed to fetch scan progress: {error.message}
        </Alert>
      )}
    </Box>
  );
};

export default ScanProgress;