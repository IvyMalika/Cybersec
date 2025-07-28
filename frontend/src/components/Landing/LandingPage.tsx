import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Container,
  Avatar,
  Chip,
  alpha,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Shield as ShieldIcon,
  School as SchoolIcon,
  AdminPanelSettings as AdminIcon,
  TrendingUp as TrendingUpIcon,
  BugReport as BugReportIcon,
  NetworkCheck as NetworkIcon,
  Psychology as PsychologyIcon,
  PersonSearch as PersonSearchIcon,
  Lock as LockIcon,
  Assessment as AssessmentIcon,
  WorkspacePremium as WorkspacePremiumIcon,
} from '@mui/icons-material';
import { colors } from '../../theme/theme';

const features = [
  {
    title: 'Advanced Threat Detection',
    description: 'Real-time monitoring and analysis of security threats with AI-powered detection.',
    icon: <ShieldIcon />,
    color: colors.primary.main,
  },
  {
    title: 'Network Security Scanning',
    description: 'Comprehensive network vulnerability assessment with Nmap and custom tools.',
    icon: <NetworkIcon />,
    color: colors.accent.blue,
  },
  {
    title: 'Social Engineering Tools',
    description: 'Advanced phishing and social engineering testing capabilities.',
    icon: <PsychologyIcon />,
    color: colors.accent.fuchsia,
  },
  {
    title: 'OSINT Intelligence',
    description: 'Open-source intelligence gathering and username enumeration.',
    icon: <PersonSearchIcon />,
    color: colors.accent.orange,
  },
  {
    title: 'Vulnerability Assessment',
    description: 'Automated vulnerability scanning and penetration testing tools.',
    icon: <BugReportIcon />,
    color: colors.severity.high,
  },
  {
    title: 'Security Education',
    description: 'Interactive cybersecurity courses and certification programs.',
    icon: <SchoolIcon />,
    color: colors.accent.teal,
  },
];

const testimonials = [
  {
    name: 'Alex Chen',
    role: 'Security Analyst',
    text: 'VertexGuard has transformed our security operations. The real-time threat detection is incredible.',
    avatar: 'AC',
  },
  {
    name: 'Sarah Johnson',
    role: 'IT Director',
    text: 'The comprehensive toolset and intuitive interface make security management effortless.',
    avatar: 'SJ',
  },
  {
    name: 'Michael Rodriguez',
    role: 'Penetration Tester',
    text: 'The advanced scanning capabilities and detailed reporting have improved our security posture significantly.',
    avatar: 'MR',
  },
];

const stats = [
  { label: 'Threats Detected', value: '10,000+', color: colors.accent.fuchsia },
  { label: 'Networks Scanned', value: '500+', color: colors.accent.blue },
  { label: 'Vulnerabilities Found', value: '2,500+', color: colors.severity.high },
  { label: 'Users Protected', value: '50,000+', color: colors.accent.teal },
];

const LandingPage: React.FC = () => {
  const { isAuthenticated, user } = useAuth();

  return (
    <Box
      sx={{
        minHeight: '100vh',
        background: `linear-gradient(135deg, ${colors.background.default} 0%, ${colors.background.elevated} 100%)`,
      }}
    >
      {/* Navigation */}
      <Box
        sx={{
          position: 'sticky',
          top: 0,
          zIndex: 1000,
          backgroundColor: alpha(colors.background.paper, 0.9),
          backdropFilter: 'blur(10px)',
          borderBottom: `1px solid ${colors.border.primary}`,
        }}
      >
        <Container maxWidth="lg">
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              py: 2,
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <ShieldIcon sx={{ mr: 2, color: colors.primary.main, fontSize: 32 }} />
              <Typography variant="h5" sx={{ fontWeight: 700, color: colors.primary.main }}>
                VertexGuard
              </Typography>
            </Box>
            
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              {isAuthenticated ? (
                <Button
                  component={Link}
                  to="/dashboard"
                  variant="contained"
                  sx={{
                    backgroundColor: colors.primary.main,
                    '&:hover': {
                      backgroundColor: colors.primary.dark,
                    },
                  }}
                >
                  Dashboard
                </Button>
              ) : (
                <>
                  <Button
                    component={Link}
                    to="/login"
                    variant="outlined"
                    sx={{
                      borderColor: colors.border.secondary,
                      color: colors.text.primary,
                      '&:hover': {
                        borderColor: colors.primary.main,
                      },
                    }}
                  >
                    Login
                  </Button>
                  <Button
                    component={Link}
                    to="/register"
                    variant="contained"
                    sx={{
                      backgroundColor: colors.primary.main,
                      '&:hover': {
                        backgroundColor: colors.primary.dark,
                      },
                    }}
                  >
                    Get Started
                  </Button>
                </>
              )}
            </Box>
          </Box>
        </Container>
      </Box>

      {/* Hero Section */}
      <Container maxWidth="lg" sx={{ py: 8 }}>
        <Box sx={{ textAlign: 'center', mb: 8 }}>
          <Typography
            variant="h2"
            sx={{
              fontWeight: 700,
              color: colors.text.primary,
              mb: 3,
              fontSize: { xs: '2.5rem', md: '3.5rem' },
            }}
          >
            Advanced Cybersecurity
            <br />
            <Box component="span" sx={{ color: colors.primary.main }}>
              Protection Platform
            </Box>
          </Typography>
          
          <Typography
            variant="h5"
            sx={{
              color: colors.text.secondary,
              mb: 4,
              maxWidth: 800,
              mx: 'auto',
              lineHeight: 1.6,
            }}
          >
            Comprehensive threat detection, network security scanning, and advanced penetration testing tools
            all in one powerful platform.
          </Typography>

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
            {!isAuthenticated && (
              <Button
                component={Link}
                to="/register"
                variant="contained"
                size="large"
                sx={{
                  backgroundColor: colors.primary.main,
                  px: 4,
                  py: 1.5,
                  fontSize: '1.1rem',
                  '&:hover': {
                    backgroundColor: colors.primary.dark,
                  },
                }}
              >
                Start Free Trial
              </Button>
            )}
            <Button
              component={Link}
              to={isAuthenticated ? "/dashboard" : "/login"}
              variant="outlined"
              size="large"
              sx={{
                borderColor: colors.border.secondary,
                color: colors.text.primary,
                px: 4,
                py: 1.5,
                fontSize: '1.1rem',
                '&:hover': {
                  borderColor: colors.primary.main,
                },
              }}
            >
              {isAuthenticated ? 'Go to Dashboard' : 'Login'}
            </Button>
          </Box>
        </Box>

        {/* Stats Section */}
        <Grid container spacing={3} sx={{ mb: 8 }}>
          {stats.map((stat, index) => (
            <Grid item xs={6} md={3} key={index}>
              <Card
                sx={{
                  backgroundColor: colors.background.paper,
                  border: `1px solid ${colors.border.primary}`,
                  borderRadius: 2,
                  textAlign: 'center',
                  p: 2,
                }}
              >
                <Typography
                  variant="h4"
                  sx={{
                    fontWeight: 700,
                    color: stat.color,
                    mb: 1,
                  }}
                >
                  {stat.value}
                </Typography>
                <Typography
                  variant="body2"
                  sx={{
                    color: colors.text.secondary,
                  }}
                >
                  {stat.label}
                </Typography>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Container>

      {/* Features Section */}
      <Container maxWidth="lg" sx={{ py: 8 }}>
        <Typography
          variant="h3"
          sx={{
            textAlign: 'center',
            fontWeight: 700,
            color: colors.text.primary,
            mb: 6,
          }}
        >
          Powerful Security Tools
        </Typography>

        <Grid container spacing={4}>
          {features.map((feature, index) => (
            <Grid item xs={12} md={6} lg={4} key={index}>
              <Card
                sx={{
                  backgroundColor: colors.background.paper,
                  border: `1px solid ${colors.border.primary}`,
                  borderRadius: 2,
                  height: '100%',
                  transition: 'all 0.3s ease-in-out',
                  '&:hover': {
                    transform: 'translateY(-4px)',
                    boxShadow: `0 8px 32px ${alpha(feature.color, 0.2)}`,
                  },
                }}
              >
                <CardContent sx={{ p: 3 }}>
                  <Box
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      width: 64,
                      height: 64,
                      borderRadius: '50%',
                      backgroundColor: alpha(feature.color, 0.2),
                      color: feature.color,
                      mb: 3,
                    }}
                  >
                    {feature.icon}
                  </Box>
                  
                  <Typography
                    variant="h6"
                    sx={{
                      fontWeight: 600,
                      color: colors.text.primary,
                      mb: 2,
                    }}
                  >
                    {feature.title}
                  </Typography>
                  
                  <Typography
                    variant="body2"
                    sx={{
                      color: colors.text.secondary,
                      lineHeight: 1.6,
                    }}
                  >
                    {feature.description}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Container>

      {/* Testimonials Section */}
      <Container maxWidth="lg" sx={{ py: 8 }}>
        <Typography
          variant="h3"
          sx={{
            textAlign: 'center',
            fontWeight: 700,
            color: colors.text.primary,
            mb: 6,
          }}
        >
          Trusted by Security Professionals
        </Typography>

        <Grid container spacing={4}>
          {testimonials.map((testimonial, index) => (
            <Grid item xs={12} md={4} key={index}>
              <Card
                sx={{
                  backgroundColor: colors.background.paper,
                  border: `1px solid ${colors.border.primary}`,
                  borderRadius: 2,
                  height: '100%',
                }}
              >
                <CardContent sx={{ p: 3 }}>
                  <Typography
                    variant="body1"
                    sx={{
                      color: colors.text.primary,
                      mb: 3,
                      fontStyle: 'italic',
                      lineHeight: 1.6,
                    }}
                  >
                    "{testimonial.text}"
                  </Typography>
                  
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Avatar
                      sx={{
                        backgroundColor: colors.primary.main,
                        mr: 2,
                      }}
                    >
                      {testimonial.avatar}
                    </Avatar>
                    <Box>
                      <Typography
                        variant="subtitle1"
                        sx={{
                          fontWeight: 600,
                          color: colors.text.primary,
                        }}
                      >
                        {testimonial.name}
                      </Typography>
                      <Typography
                        variant="body2"
                        sx={{
                          color: colors.text.secondary,
                        }}
                      >
                        {testimonial.role}
                      </Typography>
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Container>

      {/* CTA Section */}
      <Container maxWidth="lg" sx={{ py: 8 }}>
        <Card
          sx={{
            backgroundColor: alpha(colors.primary.main, 0.1),
            border: `1px solid ${colors.primary.main}40`,
            borderRadius: 3,
            textAlign: 'center',
            p: 4,
          }}
        >
          <Typography
            variant="h4"
            sx={{
              fontWeight: 700,
              color: colors.text.primary,
              mb: 2,
            }}
          >
            Ready to Secure Your Infrastructure?
          </Typography>
          
          <Typography
            variant="body1"
            sx={{
              color: colors.text.secondary,
              mb: 4,
              maxWidth: 600,
              mx: 'auto',
            }}
          >
            Join thousands of security professionals who trust VertexGuard for their cybersecurity needs.
          </Typography>

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
            {!isAuthenticated && (
              <Button
                component={Link}
                to="/register"
                variant="contained"
                size="large"
                sx={{
                  backgroundColor: colors.primary.main,
                  px: 4,
                  py: 1.5,
                  fontSize: '1.1rem',
                  '&:hover': {
                    backgroundColor: colors.primary.dark,
                  },
                }}
              >
                Start Free Trial
              </Button>
            )}
            <Button
              component={Link}
              to={isAuthenticated ? "/dashboard" : "/login"}
              variant="outlined"
              size="large"
              sx={{
                borderColor: colors.primary.main,
                color: colors.primary.main,
                px: 4,
                py: 1.5,
                fontSize: '1.1rem',
                '&:hover': {
                  backgroundColor: alpha(colors.primary.main, 0.1),
                },
              }}
            >
              {isAuthenticated ? 'Go to Dashboard' : 'Login'}
            </Button>
          </Box>
        </Card>
      </Container>

      {/* Footer */}
      <Box
        sx={{
          backgroundColor: colors.background.paper,
          borderTop: `1px solid ${colors.border.primary}`,
          py: 4,
        }}
      >
        <Container maxWidth="lg">
          <Box sx={{ textAlign: 'center' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 2 }}>
              <ShieldIcon sx={{ mr: 2, color: colors.primary.main, fontSize: 24 }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: colors.primary.main }}>
                VertexGuard
              </Typography>
            </Box>
            <Typography
              variant="body2"
              sx={{
                color: colors.text.secondary,
              }}
            >
              © 2024 VertexGuard. All rights reserved. Security is a process, not a product.
            </Typography>
          </Box>
        </Container>
      </Box>
    </Box>
  );
};

export default LandingPage; 