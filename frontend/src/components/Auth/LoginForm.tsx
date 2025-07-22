import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  CircularProgress,
  Link,
  InputAdornment,
  IconButton,
  Fade,
  useTheme,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Person as PersonIcon,
  Lock as LockIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useForm, Controller } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import { colors } from '../../theme/theme';

const loginSchema = yup.object({
  username: yup.string().required('Username is required'),
  password: yup.string().required('Password is required'),
  mfaCode: yup.string().when('$showMFA', {
    is: true,
    then: yup.string().required('MFA code is required').length(6, 'MFA code must be 6 digits'),
  }),
});

interface LoginFormData {
  username: string;
  password: string;
  mfaCode?: string;
}

const LoginForm: React.FC = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [showMFA, setShowMFA] = useState(false);
  const { login, isLoading, error, mfaRequired, user } = useAuth();
  const navigate = useNavigate();
  const theme = useTheme();

  const {
    control,
    handleSubmit,
    formState: { errors },
    getValues,
  } = useForm<LoginFormData>({
    resolver: yupResolver(loginSchema),
    context: { showMFA },
  });

  const onSubmit = async (data: LoginFormData) => {
    try {
      await login(data.username, data.password, data.mfaCode);
      if (mfaRequired && !data.mfaCode) {
        setShowMFA(true);
      } else {
        if (user?.is_admin) {
          navigate('/admin');
        } else {
          navigate('/dashboard');
        }
      }
    } catch (error) {
      console.error('Login failed:', error);
    }
  };

  const handleTogglePassword = () => {
    setShowPassword(!showPassword);
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: `linear-gradient(135deg, ${colors.background.default} 0%, ${colors.background.elevated} 100%)`,
        p: 2,
      }}
    >
      <Card
        sx={{
          maxWidth: 400,
          width: '100%',
          backgroundColor: colors.background.paper,
          border: `1px solid ${colors.border.primary}`,
          boxShadow: `0 8px 32px ${colors.background.default}80`,
          borderRadius: 2,
        }}
      >
        <CardContent sx={{ p: 4 }}>
          <Box sx={{ textAlign: 'center', mb: 4 }}>
            <SecurityIcon
              sx={{
                fontSize: 48,
                color: colors.primary.main,
                mb: 2,
              }}
            />
            <Typography variant="h4" sx={{ fontWeight: 600, mb: 1 }}>
              CyberSec Suite
            </Typography>
            <Typography variant="body2" sx={{ color: colors.text.secondary }}>
              {showMFA ? 'Enter your MFA code' : 'Sign in to your account'}
            </Typography>
          </Box>

          {error && (
            <Alert
              severity="error"
              sx={{
                mb: 3,
                backgroundColor: colors.severity.critical + '20',
                color: colors.severity.critical,
                border: `1px solid ${colors.severity.critical}40`,
              }}
            >
              {typeof error === 'string'
                ? error
                : error?.message
                  ? error.message
                  : error?.error
                    ? error.error
                    : JSON.stringify(error)}
            </Alert>
          )}

          <form onSubmit={handleSubmit(onSubmit)}>
            <Fade in={!showMFA}>
              <Box sx={{ display: showMFA ? 'none' : 'block' }}>
                <Controller
                  name="username"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      value={field.value ?? ""}
                      fullWidth
                      label="Username"
                      error={!!errors.username}
                      helperText={errors.username?.message}
                      sx={{ mb: 2 }}
                      InputProps={{
                        startAdornment: (
                          <InputAdornment position="start">
                            <PersonIcon sx={{ color: colors.text.secondary }} />
                          </InputAdornment>
                        ),
                      }}
                    />
                  )}
                />

                <Controller
                  name="password"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      value={field.value ?? ""}
                      fullWidth
                      label="Password"
                      type={showPassword ? 'text' : 'password'}
                      error={!!errors.password}
                      helperText={errors.password?.message}
                      sx={{ mb: 3 }}
                      InputProps={{
                        startAdornment: (
                          <InputAdornment position="start">
                            <LockIcon sx={{ color: colors.text.secondary }} />
                          </InputAdornment>
                        ),
                        endAdornment: (
                          <InputAdornment position="end">
                            <IconButton
                              onClick={handleTogglePassword}
                              edge="end"
                            >
                              {showPassword ? <VisibilityOff /> : <Visibility />}
                            </IconButton>
                          </InputAdornment>
                        ),
                      }}
                    />
                  )}
                />
              </Box>
            </Fade>

            <Fade in={showMFA}>
              <Box sx={{ display: showMFA ? 'block' : 'none' }}>
                <Controller
                  name="mfaCode"
                  control={control}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      value={field.value ?? ""}
                      fullWidth
                      label="MFA Code"
                      placeholder="Enter 6-digit code"
                      error={!!errors.mfaCode}
                      helperText={errors.mfaCode?.message}
                      sx={{ mb: 3 }}
                      inputProps={{
                        maxLength: 6,
                        style: { textAlign: 'center', fontSize: '1.2rem' },
                      }}
                    />
                  )}
                />
              </Box>
            </Fade>

            <Button
              type="submit"
              fullWidth
              variant="contained"
              size="large"
              disabled={isLoading}
              sx={{
                mb: 2,
                py: 1.5,
                backgroundColor: colors.primary.main,
                '&:hover': {
                  backgroundColor: colors.primary.dark,
                },
              }}
            >
              {isLoading ? (
                <CircularProgress size={24} color="inherit" />
              ) : showMFA ? (
                'Verify MFA'
              ) : (
                'Sign In'
              )}
            </Button>

            {showMFA && (
              <Button
                fullWidth
                variant="text"
                onClick={() => setShowMFA(false)}
                sx={{ mb: 2 }}
              >
                Back to Login
              </Button>
            )}
          </form>

          <Box sx={{ textAlign: 'center', mt: 3 }}>
            <Typography variant="body2" sx={{ color: colors.text.secondary }}>
              Don't have an account?{' '}
              <Link
                href="/register"
                sx={{
                  color: colors.primary.main,
                  textDecoration: 'none',
                  fontWeight: 600,
                  '&:hover': {
                    textDecoration: 'underline',
                  },
                }}
              >
                Sign up
              </Link>
            </Typography>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default LoginForm;