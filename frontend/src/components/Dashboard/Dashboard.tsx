import React, { useState, useEffect } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  Button,
  Alert,
  CircularProgress,
  IconButton,
  Tooltip,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  NetworkCheck as NetworkIcon,
  Assignment as AssignmentIcon,
  TrendingUp as TrendingUpIcon,
  Refresh as RefreshIcon,
  Speed as SpeedIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  BarChart,
  Bar,
  Area,
  AreaChart,
} from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { useAuth } from '../../contexts/AuthContext';
import { Job, Vulnerability, HealthStatus } from '../../types/api';

interface DashboardStats {
  totalJobs: number;
  runningJobs: number;
  completedJobs: number;
  failedJobs: number;
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities: number;
  lowVulnerabilities: number;
}

interface ActivityData {
  date: string;
  scans: number;
  vulnerabilities: number;
}

const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  const {
    data: jobs,
    isLoading: jobsLoading,
    error: jobsError,
    refetch: refetchJobs,
  } = useQuery({
    queryKey: ['jobs'],
    queryFn: () => apiClient.getJobs(),
    refetchInterval: 5000,
  });

  const {
    data: healthStatus,
    isLoading: healthLoading,
    error: healthError,
    refetch: refetchHealth,
  } = useQuery({
    queryKey: ['health'],
    queryFn: () => apiClient.getHealthStatus(),
    refetchInterval: 30000,
  });

  // Mock data for demonstration
  const mockStats: DashboardStats = {
    totalJobs: 156,
    runningJobs: 3,
    completedJobs: 142,
    failedJobs: 11,
    totalVulnerabilities: 89,
    criticalVulnerabilities: 12,
    highVulnerabilities: 23,
    mediumVulnerabilities: 34,
    lowVulnerabilities: 20,
  };

  const vulnerabilityData = [
    { name: 'Critical', value: mockStats.criticalVulnerabilities, color: colors.severity.critical },
    { name: 'High', value: mockStats.highVulnerabilities, color: colors.severity.high },
    { name: 'Medium', value: mockStats.mediumVulnerabilities, color: colors.severity.medium },
    { name: 'Low', value: mockStats.lowVulnerabilities, color: colors.severity.low },
  ];

  const activityData: ActivityData[] = [
    { date: '2024-01-15', scans: 12, vulnerabilities: 8 },
    { date: '2024-01-16', scans: 15, vulnerabilities: 12 },
    { date: '2024-01-17', scans: 8, vulnerabilities: 6 },
    { date: '2024-01-18', scans: 20, vulnerabilities: 15 },
    { date: '2024-01-19', scans: 18, vulnerabilities: 11 },
    { date: '2024-01-20', scans: 14, vulnerabilities: 9 },
    { date: '2024-01-21', scans: 22, vulnerabilities: 18 },
  ];

  const jobStatusData = [
    { name: 'Completed', value: mockStats.completedJobs, color: colors.severity.low },
    { name: 'Running', value: mockStats.runningJobs, color: colors.primary.main },
    { name: 'Failed', value: mockStats.failedJobs, color: colors.severity.critical },
  ];

  const StatCard: React.FC<{
    title: string;
    value: number;
    icon: React.ReactNode;
    color: string;
    subtitle?: string;
  }> = ({ title, value, icon, color, subtitle }) => (
    <Card
      sx={{
        height: '100%',
        background: `linear-gradient(135deg, ${color}20 0%, ${color}10 100%)`,
        border: `1px solid ${color}40`,
        transition: 'all 0.2s ease-in-out',
        '&:hover': {
          transform: 'translateY(-2px)',
          boxShadow: `0 8px 32px ${color}30`,
        },
      }}
    >
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="h3" sx={{ fontWeight: 600, color }}>
              {value}
            </Typography>
            <Typography variant="h6" sx={{ color: colors.text.primary, mb: 0.5 }}>
              {title}
            </Typography>
            {subtitle && (
              <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                {subtitle}
              </Typography>
            )}
          </Box>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 64,
              height: 64,
              borderRadius: '50%',
              backgroundColor: color + '30',
              color,
            }}
          >
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <Box
          sx={{
            backgroundColor: colors.background.paper,
            border: `1px solid ${colors.border.primary}`,
            borderRadius: 1,
            p: 1,
            boxShadow: `0 4px 16px ${colors.background.default}80`,
          }}
        >
          <Typography variant="body2" sx={{ mb: 1 }}>
            {label}
          </Typography>
          {payload.map((entry: any, index: number) => (
            <Typography
              key={index}
              variant="body2"
              sx={{ color: entry.color, fontWeight: 600 }}
            >
              {entry.name}: {entry.value}
            </Typography>
          ))}
        </Box>
      );
    }
    return null;
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          Welcome back, {user?.username}
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh Data">
            <IconButton
              onClick={() => {
                refetchJobs();
                refetchHealth();
              }}
              sx={{
                backgroundColor: colors.primary.main + '20',
                '&:hover': {
                  backgroundColor: colors.primary.main + '30',
                },
              }}
            >
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Health Status Alert */}
      {healthStatus && healthStatus.status === 'unhealthy' && (
        <Alert
          severity="warning"
          sx={{
            mb: 3,
            backgroundColor: colors.severity.high + '20',
            color: colors.severity.high,
            border: `1px solid ${colors.severity.high}40`,
          }}
        >
          Some services are experiencing issues. Check the system status for details.
        </Alert>
      )}

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Scans"
            value={mockStats.totalJobs}
            icon={<SecurityIcon fontSize="large" />}
            color={colors.primary.main}
            subtitle="All time"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Running Jobs"
            value={mockStats.runningJobs}
            icon={<SpeedIcon fontSize="large" />}
            color={colors.status.info}
            subtitle="Currently active"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Vulnerabilities"
            value={mockStats.totalVulnerabilities}
            icon={<BugReportIcon fontSize="large" />}
            color={colors.severity.high}
            subtitle="Total found"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Critical Issues"
            value={mockStats.criticalVulnerabilities}
            icon={<WarningIcon fontSize="large" />}
            color={colors.severity.critical}
            subtitle="Need attention"
          />
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Activity Timeline
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={activityData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={colors.border.primary} />
                  <XAxis
                    dataKey="date"
                    stroke={colors.text.secondary}
                    fontSize={12}
                    tickFormatter={(value) => new Date(value).toLocaleDateString()}
                  />
                  <YAxis stroke={colors.text.secondary} fontSize={12} />
                  <RechartsTooltip content={<CustomTooltip />} />
                  <Legend />
                  <Area
                    type="monotone"
                    dataKey="scans"
                    stackId="1"
                    stroke={colors.primary.main}
                    fill={colors.primary.main}
                    fillOpacity={0.6}
                    name="Scans"
                  />
                  <Area
                    type="monotone"
                    dataKey="vulnerabilities"
                    stackId="1"
                    stroke={colors.severity.high}
                    fill={colors.severity.high}
                    fillOpacity={0.6}
                    name="Vulnerabilities"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Vulnerability Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={vulnerabilityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={80}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {vulnerabilityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip content={<CustomTooltip />} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Job Status & Quick Actions */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Job Status Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={jobStatusData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={colors.border.primary} />
                  <XAxis dataKey="name" stroke={colors.text.secondary} fontSize={12} />
                  <YAxis stroke={colors.text.secondary} fontSize={12} />
                  <RechartsTooltip content={<CustomTooltip />} />
                  <Bar dataKey="value" fill={colors.primary.main} radius={[4, 4, 0, 0]}>
                    {jobStatusData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Quick Actions
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Button
                  variant="contained"
                  startIcon={<NetworkIcon />}
                  href="/tools/nmap"
                  sx={{
                    backgroundColor: colors.primary.main,
                    '&:hover': {
                      backgroundColor: colors.primary.dark,
                    },
                  }}
                >
                  Run Network Scan
                </Button>
                <Button
                  variant="contained"
                  startIcon={<BugReportIcon />}
                  href="/tools/vulnerability"
                  sx={{
                    backgroundColor: colors.severity.high,
                    '&:hover': {
                      backgroundColor: colors.severity.high + 'CC',
                    },
                  }}
                >
                  Vulnerability Assessment
                </Button>
                <Button
                  variant="contained"
                  startIcon={<AssignmentIcon />}
                  href="/reports"
                  sx={{
                    backgroundColor: colors.status.info,
                    '&:hover': {
                      backgroundColor: colors.status.info + 'CC',
                    },
                  }}
                >
                  Generate Report
                </Button>
                <Button
                  variant="contained"
                  startIcon={<ShieldIcon />}
                  href="/tools/sql-injection"
                  sx={{
                    backgroundColor: colors.severity.medium,
                    '&:hover': {
                      backgroundColor: colors.severity.medium + 'CC',
                    },
                  }}
                >
                  SQL Injection Scanner
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;