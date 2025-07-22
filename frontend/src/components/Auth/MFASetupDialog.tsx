import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  Box,
  Typography,
  Alert,
  CircularProgress,
  IconButton,
  Switch,
  FormControlLabel,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from '@mui/material';
import { Close as CloseIcon } from '@mui/icons-material';
import QRCode from 'qrcode.react';
import { useAuth } from '../../contexts/AuthContext';
import { colors } from '../../theme/theme';

interface MFASetupDialogProps {
  open: boolean;
  onClose: () => void;
}

const MFASetupDialog: React.FC<MFASetupDialogProps> = ({ open, onClose }) => {
  const [enabled, setEnabled] = useState(true);
  const [activeStep, setActiveStep] = useState(0);
  const [verificationCode, setVerificationCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mfaSecret, setMfaSecret] = useState<string | null>(null);
  const { setupMFA, verifyMFA, user } = useAuth();

  const steps = [
    {
      label: 'Enable MFA',
      description: 'Choose whether to enable multi-factor authentication',
    },
    {
      label: 'Scan QR Code',
      description: 'Scan the QR code with your authenticator app',
    },
    {
      label: 'Verify Setup',
      description: 'Enter the verification code from your app',
    },
  ];

  const handleSetupMFA = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await setupMFA(enabled);
      if (enabled && response.mfa_secret) {
        setMfaSecret(response.mfa_secret);
        setActiveStep(1);
      } else {
        onClose();
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'MFA setup failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyMFA = async () => {
    if (verificationCode.length !== 6) return;

    setIsLoading(true);
    setError(null);

    try {
      await verifyMFA(verificationCode);
      setActiveStep(2);
      setTimeout(() => {
        onClose();
      }, 1500);
    } catch (err: any) {
      setError(err.response?.data?.error || 'MFA verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClose = () => {
    setActiveStep(0);
    setVerificationCode('');
    setError(null);
    setMfaSecret(null);
    onClose();
  };

  const getQRCodeUri = () => {
    if (!mfaSecret || !user) return '';
    return `otpauth://totp/CyberSec%20Suite:${user.username}?secret=${mfaSecret}&issuer=CyberSec%20Suite`;
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="md"
      fullWidth
      PaperProps={{
        sx: {
          backgroundColor: colors.background.paper,
          border: `1px solid ${colors.border.primary}`,
          borderRadius: 2,
        },
      }}
    >
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h6" sx={{ fontWeight: 600 }}>
          Multi-Factor Authentication Setup
        </Typography>
        <IconButton onClick={handleClose} size="small">
          <CloseIcon />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ pt: 1 }}>
        {error && (
          <Alert
            severity="error"
            sx={{
              mb: 2,
              backgroundColor: colors.severity.critical + '20',
              color: colors.severity.critical,
              border: `1px solid ${colors.severity.critical}40`,
            }}
          >
            {error}
          </Alert>
        )}

        <Stepper activeStep={activeStep} orientation="vertical">
          <Step>
            <StepLabel>Enable MFA</StepLabel>
            <StepContent>
              <Typography variant="body2" sx={{ mb: 2, color: colors.text.secondary }}>
                Multi-factor authentication adds an extra layer of security to your account.
              </Typography>
              <FormControlLabel
                control={
                  <Switch
                    checked={enabled}
                    onChange={(e) => setEnabled(e.target.checked)}
                    sx={{
                      '& .MuiSwitch-switchBase.Mui-checked': {
                        color: colors.primary.main,
                      },
                      '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': {
                        backgroundColor: colors.primary.main,
                      },
                    }}
                  />
                }
                label="Enable MFA"
              />
              <Box sx={{ mt: 2 }}>
                <Button
                  variant="contained"
                  onClick={handleSetupMFA}
                  disabled={isLoading}
                  sx={{
                    backgroundColor: colors.primary.main,
                    '&:hover': {
                      backgroundColor: colors.primary.dark,
                    },
                  }}
                >
                  {isLoading ? (
                    <CircularProgress size={20} color="inherit" />
                  ) : (
                    'Continue'
                  )}
                </Button>
              </Box>
            </StepContent>
          </Step>

          <Step>
            <StepLabel>Scan QR Code</StepLabel>
            <StepContent>
              <Typography variant="body2" sx={{ mb: 2, color: colors.text.secondary }}>
                Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
              </Typography>
              {mfaSecret && (
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                  <Box
                    sx={{
                      p: 2,
                      backgroundColor: colors.background.default,
                      borderRadius: 1,
                      border: `1px solid ${colors.border.primary}`,
                    }}
                  >
                    <QRCode
                      value={getQRCodeUri()}
                      size={200}
                      bgColor={colors.background.default}
                      fgColor={colors.text.primary}
                    />
                  </Box>
                  <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                    Or enter this code manually: <strong>{mfaSecret}</strong>
                  </Typography>
                  <Button
                    variant="outlined"
                    onClick={() => setActiveStep(2)}
                    sx={{
                      borderColor: colors.border.secondary,
                      '&:hover': {
                        borderColor: colors.primary.main,
                      },
                    }}
                  >
                    I've Added the Account
                  </Button>
                </Box>
              )}
            </StepContent>
          </Step>

          <Step>
            <StepLabel>Verify Setup</StepLabel>
            <StepContent>
              <Typography variant="body2" sx={{ mb: 2, color: colors.text.secondary }}>
                Enter the 6-digit code from your authenticator app to verify the setup
              </Typography>
              <TextField
                fullWidth
                label="Verification Code"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                inputProps={{
                  maxLength: 6,
                  style: {
                    textAlign: 'center',
                    fontSize: '1.5rem',
                    letterSpacing: '0.5em',
                  },
                }}
                sx={{
                  mb: 2,
                  '& .MuiInputBase-input': {
                    fontFamily: 'monospace',
                  },
                }}
              />
              <Button
                variant="contained"
                onClick={handleVerifyMFA}
                disabled={isLoading || verificationCode.length !== 6}
                sx={{
                  backgroundColor: colors.primary.main,
                  '&:hover': {
                    backgroundColor: colors.primary.dark,
                  },
                }}
              >
                {isLoading ? (
                  <CircularProgress size={20} color="inherit" />
                ) : (
                  'Verify & Complete Setup'
                )}
              </Button>
            </StepContent>
          </Step>
        </Stepper>
      </DialogContent>
    </Dialog>
  );
};

export default MFASetupDialog;