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
  Select,
  MenuItem,
  FormControl,
  InputLabel,
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
  PlayArrow as PlayIcon,
  Image as ImageIcon,
  Cloud as CloudIcon,
  Folder as FolderIcon,
  MoreVert as MoreVertIcon,
  Computer as ComputerIcon,
  CalendarToday as CalendarIcon,
  Description as DescriptionIcon,
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
import { alpha } from '@mui/material/styles';

interface CurrentRiskCard {
  title: string;
  percentage: number;
  icon: React.ReactNode;
  color: string;
}

interface ThreatData {
  date: string;
  threats: number;
}

interface VirusData {
  name: string;
  value: number;
  color: string;
}

interface ThreatDetail {
  date: string;
  deviceId: string;
  virusName: string;
  filePath: string;
  fileType: string;
}

interface DeviceThreat {
  deviceId: string;
  threatLevel: number;
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

  // Current Risk Cards Data
  const currentRiskCards: CurrentRiskCard[] = [
    {
      title: 'Total Threats',
      percentage: 132,
      icon: <BugReportIcon />,
      color: colors.accent.fuchsia,
    },
    {
      title: 'Video File Risk',
      percentage: 89,
      icon: <PlayIcon />,
      color: colors.primary.main,
    },
    {
      title: 'Image File Risk',
      percentage: 156,
      icon: <ImageIcon />,
      color: colors.accent.fuchsia,
    },
    {
      title: 'Docs File Risk',
      percentage: 78,
      icon: <CloudIcon />,
      color: colors.accent.blue,
    },
    {
      title: 'Folder File Risk',
      percentage: 95,
      icon: <FolderIcon />,
      color: colors.accent.blue,
    },
  ];

  // Threat Summary Data
  const threatData: ThreatData[] = [
    { date: 'Jan', threats: 15 },
    { date: 'Feb', threats: 22 },
    { date: 'Mar', threats: 18 },
    { date: 'Apr', threats: 25 },
    { date: 'May', threats: 30 },
    { date: 'Jun', threats: 29 },
    { date: 'Jul', threats: 35 },
    { date: 'Aug', threats: 28 },
    { date: 'Sep', threats: 32 },
    { date: 'Oct', threats: 38 },
    { date: 'Nov', threats: 42 },
    { date: 'Dec', threats: 45 },
  ];

  // Threats By Virus Data
  const virusData: VirusData[] = [
    { name: 'ILOVEYOU', value: 25, color: colors.primary.main },
    { name: 'Melissa', value: 20, color: colors.accent.fuchsia },
    { name: 'MyDoom', value: 15, color: colors.accent.blue },
    { name: 'Sasser', value: 5, color: colors.accent.orange },
  ];

  // Threat Details Data
  const threatDetails: ThreatDetail[] = [
    {
      date: '2024-01-15',
      deviceId: 'DEV-001',
      virusName: 'ILOVEYOU',
      filePath: '/usr/local/bin/',
      fileType: '.exe',
    },
    {
      date: '2024-01-14',
      deviceId: 'DEV-002',
      virusName: 'Melissa',
      filePath: '/home/user/',
      fileType: '.doc',
    },
    {
      date: '2024-01-13',
      deviceId: 'DEV-003',
      virusName: 'MyDoom',
      filePath: '/var/log/',
      fileType: '.zip',
    },
  ];

  // Device Threats Data
  const deviceThreats: DeviceThreat[] = [
    { deviceId: 'crazyfish228', threatLevel: 85 },
    { deviceId: 'angryswan732', threatLevel: 65 },
    { deviceId: 'silentwolf445', threatLevel: 92 },
    { deviceId: 'braveeagle123', threatLevel: 78 },
  ];

  const CurrentRiskCard: React.FC<{ card: CurrentRiskCard }> = ({ card }) => (
    <Card
      sx={{
        height: '100%',
        backgroundColor: colors.background.paper,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 2,
        transition: 'all 0.3s ease-in-out',
        '&:hover': {
          transform: 'translateY(-2px)',
          boxShadow: `0 8px 32px ${alpha(card.color, 0.2)}`,
        },
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 48,
              height: 48,
              borderRadius: '50%',
              backgroundColor: alpha(card.color, 0.2),
              color: card.color,
            }}
          >
            {card.icon}
          </Box>
          <IconButton size="small">
            <MoreVertIcon sx={{ color: colors.text.secondary }} />
          </IconButton>
        </Box>
        <Typography variant="h4" sx={{ fontWeight: 700, color: colors.text.primary, mb: 0.5 }}>
          {card.percentage}%
        </Typography>
        <Typography variant="body2" sx={{ color: colors.text.secondary }}>
          {card.title}
        </Typography>
      </CardContent>
    </Card>
  );

  const RiskScoreGauge: React.FC = () => (
    <Card
      sx={{
        height: '100%',
        backgroundColor: colors.background.paper,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 2,
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
            Risk Score
          </Typography>
          <IconButton size="small">
            <MoreVertIcon sx={{ color: colors.text.secondary }} />
          </IconButton>
        </Box>
        
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          {/* Semi-circular gauge */}
          <Box
            sx={{
              position: 'relative',
              width: 120,
              height: 60,
              mb: 2,
            }}
          >
            <Box
              sx={{
                position: 'absolute',
                width: '100%',
                height: '100%',
                borderRadius: '120px 120px 0 0',
                background: `conic-gradient(from 0deg, ${colors.accent.orange} 0deg, ${colors.accent.orange} 266deg, ${colors.border.secondary} 266deg, ${colors.border.secondary} 360deg)`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            />
            <Box
              sx={{
                position: 'absolute',
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                textAlign: 'center',
              }}
            >
              <Typography variant="h4" sx={{ fontWeight: 700, color: colors.text.primary }}>
                741
              </Typography>
              <Typography variant="caption" sx={{ color: colors.text.secondary }}>
                / 1000
              </Typography>
            </Box>
          </Box>
          
          <Chip
            label="High"
            sx={{
              backgroundColor: colors.accent.orange,
              color: colors.text.primary,
              fontWeight: 600,
            }}
          />
        </Box>
      </CardContent>
    </Card>
  );

  const ThreatSummaryChart: React.FC = () => (
    <Card
      sx={{
        height: '100%',
        backgroundColor: colors.background.paper,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 2,
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
            Threat Summary
          </Typography>
          <FormControl size="small" sx={{ minWidth: 100 }}>
            <Select
              value="yearly"
              sx={{
                color: colors.text.primary,
                '& .MuiOutlinedInput-notchedOutline': {
                  borderColor: colors.border.secondary,
                },
              }}
            >
              <MenuItem value="yearly">Yearly</MenuItem>
              <MenuItem value="monthly">Monthly</MenuItem>
              <MenuItem value="weekly">Weekly</MenuItem>
            </Select>
          </FormControl>
        </Box>
        
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={threatData}>
            <CartesianGrid strokeDasharray="3 3" stroke={colors.border.primary} />
            <XAxis
              dataKey="date"
              stroke={colors.text.secondary}
              fontSize={12}
            />
            <YAxis
              stroke={colors.text.secondary}
              fontSize={12}
              domain={[0, 500]}
            />
            <RechartsTooltip
              content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  return (
                    <Box
                      sx={{
                        backgroundColor: colors.background.paper,
                        border: `1px solid ${colors.border.primary}`,
                        borderRadius: 1,
                        p: 1,
                        boxShadow: `0 4px 16px ${alpha(colors.background.default, 0.8)}`,
                      }}
                    >
                      <Typography variant="body2" sx={{ mb: 1, color: colors.primary.main }}>
                        {label} 2024
                      </Typography>
                      <Typography variant="body2" sx={{ color: colors.primary.main, fontWeight: 600 }}>
                        Threats {payload[0]?.value}
                      </Typography>
                    </Box>
                  );
                }
                return null;
              }}
            />
            <Line
              type="monotone"
              dataKey="threats"
              stroke={colors.primary.main}
              strokeWidth={3}
              dot={{ fill: colors.primary.main, strokeWidth: 2, r: 4 }}
              activeDot={{ r: 6, stroke: colors.primary.main, strokeWidth: 2 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );

  const ThreatsByVirusChart: React.FC = () => (
    <Card
      sx={{
        height: '100%',
        backgroundColor: colors.background.paper,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 2,
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
            Threats By Virus
          </Typography>
          <IconButton size="small">
            <MoreVertIcon sx={{ color: colors.text.secondary }} />
          </IconButton>
        </Box>
        
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Box sx={{ flex: 1 }}>
            <ResponsiveContainer width="100%" height={150}>
              <PieChart>
                <Pie
                  data={virusData}
                  cx="50%"
                  cy="50%"
                  innerRadius={30}
                  outerRadius={60}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {virusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <Box sx={{ textAlign: 'center', mt: 1 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: colors.text.primary }}>
                Total 65%
              </Typography>
            </Box>
          </Box>
          
          <Box sx={{ ml: 2 }}>
            {virusData.map((virus, index) => (
              <Box key={index} sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Box
                  sx={{
                    width: 12,
                    height: 12,
                    borderRadius: '50%',
                    backgroundColor: virus.color,
                    mr: 1,
                  }}
                />
                <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                  {virus.name}
                </Typography>
              </Box>
            ))}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );

  const ThreatDetailsTable: React.FC = () => (
    <Card
      sx={{
        height: '100%',
        backgroundColor: colors.background.paper,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 2,
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
            Threat Details
          </Typography>
          <FormControl size="small" sx={{ minWidth: 100 }}>
            <Select
              value="daily"
              sx={{
                color: colors.text.primary,
                '& .MuiOutlinedInput-notchedOutline': {
                  borderColor: colors.border.secondary,
                },
              }}
            >
              <MenuItem value="daily">Daily</MenuItem>
              <MenuItem value="weekly">Weekly</MenuItem>
              <MenuItem value="monthly">Monthly</MenuItem>
            </Select>
          </FormControl>
        </Box>
        
        <Box sx={{ overflowX: 'auto' }}>
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 2, mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <CalendarIcon sx={{ mr: 1, color: colors.text.secondary, fontSize: 16 }} />
              <Typography variant="body2" sx={{ fontWeight: 600, color: colors.text.primary }}>
                Date
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <ComputerIcon sx={{ mr: 1, color: colors.text.secondary, fontSize: 16 }} />
              <Typography variant="body2" sx={{ fontWeight: 600, color: colors.text.primary }}>
                Device ID
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <BugReportIcon sx={{ mr: 1, color: colors.text.secondary, fontSize: 16 }} />
              <Typography variant="body2" sx={{ fontWeight: 600, color: colors.text.primary }}>
                Virus name
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <FolderIcon sx={{ mr: 1, color: colors.text.secondary, fontSize: 16 }} />
              <Typography variant="body2" sx={{ fontWeight: 600, color: colors.text.primary }}>
                File Path
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <DescriptionIcon sx={{ mr: 1, color: colors.text.secondary, fontSize: 16 }} />
              <Typography variant="body2" sx={{ fontWeight: 600, color: colors.text.primary }}>
                File Type
              </Typography>
            </Box>
          </Box>
          
          {threatDetails.map((detail, index) => (
            <Box
              key={index}
              sx={{
                display: 'grid',
                gridTemplateColumns: 'repeat(5, 1fr)',
                gap: 2,
                py: 1,
                borderBottom: `1px solid ${colors.border.primary}`,
              }}
            >
              <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                {detail.date}
              </Typography>
              <Typography variant="body2" sx={{ color: colors.text.primary }}>
                {detail.deviceId}
              </Typography>
              <Typography variant="body2" sx={{ color: colors.text.primary }}>
                {detail.virusName}
              </Typography>
              <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                {detail.filePath}
              </Typography>
              <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                {detail.fileType}
              </Typography>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  );

  const DeviceThreatsList: React.FC = () => (
    <Card
      sx={{
        height: '100%',
        backgroundColor: colors.background.paper,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 2,
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
            Threat by device
          </Typography>
          <IconButton size="small">
            <MoreVertIcon sx={{ color: colors.text.secondary }} />
          </IconButton>
        </Box>
        
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {deviceThreats.map((device, index) => (
            <Box
              key={index}
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                p: 1,
                borderRadius: 1,
                backgroundColor: alpha(colors.background.elevated, 0.5),
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <ComputerIcon sx={{ mr: 1, color: colors.text.secondary }} />
                <Typography variant="body2" sx={{ color: colors.text.primary }}>
                  {device.deviceId}
                </Typography>
              </Box>
              <Box
                sx={{
                  width: 40,
                  height: 40,
                  borderRadius: '50%',
                  background: `conic-gradient(from 0deg, ${colors.accent.orange} 0deg, ${colors.accent.orange} ${device.threatLevel * 3.6}deg, ${colors.border.secondary} ${device.threatLevel * 3.6}deg, ${colors.border.secondary} 360deg)`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Typography variant="caption" sx={{ color: colors.text.primary, fontWeight: 600 }}>
                  {device.threatLevel}%
                </Typography>
              </Box>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  );

  return (
    <Box sx={{ flexGrow: 1 }}>
      {/* Current Risk Section */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {currentRiskCards.map((card, index) => (
          <Grid item xs={12} sm={6} md={2.4} key={index}>
            <CurrentRiskCard card={card} />
          </Grid>
        ))}
      </Grid>

      {/* Risk Score and Charts */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={8}>
          <ThreatSummaryChart />
        </Grid>
        <Grid item xs={12} md={4}>
          <RiskScoreGauge />
        </Grid>
      </Grid>

      {/* Threats By Virus and Threat Details */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <ThreatsByVirusChart />
        </Grid>
        <Grid item xs={12} md={6}>
          <ThreatDetailsTable />
        </Grid>
      </Grid>

      {/* Device Threats */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <DeviceThreatsList />
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;