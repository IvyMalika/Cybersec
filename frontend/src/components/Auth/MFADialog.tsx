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
  Fade,
} from '@mui/material';
import { Close as CloseIcon } from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import { colors } from '../../theme/theme';

interface MFADialogProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const MFADialog: React.FC<MFADialogProps> = ({ open, onClose, onSuccess }) => {
  const [code, setCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { verifyMFA } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (code.length !== 6) return;

    setIsLoading(true);
    setError(null);

    try {
      await verifyMFA(code);
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.response?.data?.error || 'MFA verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, '');
    if (value.length <= 6) {
      setCode(value);
    }
  };

  const handleClose = () => {
    setCode('');
    setError(null);
    onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="sm"
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
          Multi-Factor Authentication
        </Typography>
        <IconButton onClick={handleClose} size="small">
          <CloseIcon />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ pt: 1 }}>
        <Typography variant="body2" sx={{ mb: 3, color: colors.text.secondary }}>
          Enter the 6-digit code from your authenticator app
        </Typography>

        {error && (
          <Fade in={!!error}>
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
          </Fade>
        )}

        <form onSubmit={handleSubmit}>
          <TextField
            fullWidth
            label="MFA Code"
            value={code}
            onChange={handleCodeChange}
            placeholder="000000"
            error={!!error}
            inputProps={{
              maxLength: 6,
              style: {
                textAlign: 'center',
                fontSize: '1.5rem',
                letterSpacing: '0.5em',
              },
            }}
            sx={{
              mb: 3,
              '& .MuiInputBase-input': {
                fontFamily: 'monospace',
              },
            }}
          />

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            <Button
              onClick={handleClose}
              variant="outlined"
              disabled={isLoading}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="contained"
              disabled={isLoading || code.length !== 6}
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
                'Verify'
              )}
            </Button>
          </Box>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default MFADialog;