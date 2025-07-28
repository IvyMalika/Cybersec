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
  alpha,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Person as PersonIcon,
  Lock as LockIcon,
  Security as SecurityIcon,
  Shield as ShieldIcon,
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
          maxWidth: 450,
          width: '100%',
          backgroundColor: colors.background.paper,
          border: `1px solid ${colors.border.primary}`,
          borderRadius: 3,
          boxShadow: `0 8px 32px ${alpha(colors.background.default, 0.8)}`,
        }}
      >
        <CardContent sx={{ p: 4 }}>
          {/* Logo and Title */}
          <Box sx={{ textAlign: 'center', mb: 4 }}>
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                mb: 2,
              }}
            >
              <ShieldIcon sx={{ mr: 2, color: colors.primary.main, fontSize: 40 }} />
              <Typography variant="h4" sx={{ fontWeight: 700, color: colors.primary.main }}>
                VertexGuard
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ color: colors.text.secondary }}>
              Secure access to your cybersecurity dashboard
            </Typography>
          </Box>

          {error && (
            <Alert
              severity="error"
              sx={{
                mb: 3,
                backgroundColor: alpha(colors.severity.critical, 0.1),
                border: `1px solid ${colors.severity.critical}40`,
                color: colors.severity.critical,
              }}
            >
              {error}
            </Alert>
          )}

          <form onSubmit={handleSubmit(onSubmit)}>
            <Box sx={{ mb: 3 }}>
              <Controller
                name="username"
                control={control}
                render={({ field }) => (
                  <TextField
                    {...field}
                    label="Username"
                    placeholder="Enter your username"
                    fullWidth
                    error={!!errors.username}
                    helperText={errors.username?.message}
                    InputProps={{
                      startAdornment: (
                        <InputAdornment position="start">
                          <PersonIcon sx={{ color: colors.text.secondary }} />
                        </InputAdornment>
                      ),
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        backgroundColor: colors.background.elevated,
                        borderRadius: 2,
                      },
                    }}
                  />
                )}
              />
            </Box>

            <Box sx={{ mb: 3 }}>
              <Controller
                name="password"
                control={control}
                render={({ field }) => (
                  <TextField
                    {...field}
                    label="Password"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter your password"
                    fullWidth
                    error={!!errors.password}
                    helperText={errors.password?.message}
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
                            sx={{ color: colors.text.secondary }}
                          >
                            {showPassword ? <VisibilityOff /> : <Visibility />}
                          </IconButton>
                        </InputAdornment>
                      ),
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        backgroundColor: colors.background.elevated,
                        borderRadius: 2,
                      },
                    }}
                  />
                )}
              />
            </Box>

            {showMFA && (
              <Fade in={showMFA}>
                <Box sx={{ mb: 3 }}>
                  <Controller
                    name="mfaCode"
                    control={control}
                    render={({ field }) => (
                      <TextField
                        {...field}
                        label="MFA Code"
                        placeholder="Enter 6-digit code"
                        fullWidth
                        error={!!errors.mfaCode}
                        helperText={errors.mfaCode?.message}
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <SecurityIcon sx={{ color: colors.text.secondary }} />
                            </InputAdornment>
                          ),
                        }}
                        sx={{
                          '& .MuiOutlinedInput-root': {
                            backgroundColor: colors.background.elevated,
                            borderRadius: 2,
                          },
                        }}
                      />
                    )}
                  />
                </Box>
              </Fade>
            )}

            <Button
              type="submit"
              variant="contained"
              fullWidth
              disabled={isLoading}
              sx={{
                backgroundColor: colors.primary.main,
                '&:hover': {
                  backgroundColor: colors.primary.dark,
                },
                py: 1.5,
                borderRadius: 2,
                fontSize: '1rem',
                fontWeight: 600,
              }}
            >
              {isLoading ? (
                <CircularProgress size={24} sx={{ color: colors.text.primary }} />
              ) : (
                'Sign In'
              )}
            </Button>
          </form>

          <Box sx={{ textAlign: 'center', mt: 3 }}>
            <Typography variant="body2" sx={{ color: colors.text.secondary }}>
              Don't have an account?{' '}
              <Link
                href="/register"
                sx={{
                  color: colors.primary.main,
                  textDecoration: 'none',
                  '&:hover': {
                    textDecoration: 'underline',
                  },
                }}
              >
                Sign up
              </Link>
            </Typography>
          </Box>

          <Box sx={{ textAlign: 'center', mt: 2 }}>
            <Typography variant="caption" sx={{ color: colors.text.secondary }}>
              Security is a process, not a product
            </Typography>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default LoginForm;