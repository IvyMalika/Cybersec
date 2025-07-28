import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Grid,
  Chip,
  IconButton,
  Tooltip,
  alpha,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  TextField,
  InputAdornment,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  Assessment as AssessmentIcon,
  GetApp as DownloadIcon,
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  MoreVert as MoreVertIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  BugReport as BugReportIcon,
  Security as SecurityIcon,
  NetworkCheck as NetworkIcon,
  Memory as MemoryIcon,
  PersonSearch as PersonSearchIcon,
  Lock as LockIcon,
  Psychology as PsychologyIcon,
  Gavel as GavelIcon,
  School as SchoolIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { Report } from '../../types/api';

interface ReportFilters {
  type: string;
  status: string;
  dateRange: string;
  search: string;
}

const reportTypes = [
  { value: 'vulnerability', label: 'Vulnerability Scan', icon: <BugReportIcon />, color: colors.severity.high },
  { value: 'network', label: 'Network Scan', icon: <NetworkIcon />, color: colors.accent.blue },
  { value: 'malware', label: 'Malware Analysis', icon: <MemoryIcon />, color: colors.accent.orange },
  { value: 'osint', label: 'OSINT Search', icon: <PersonSearchIcon />, color: colors.accent.fuchsia },
  { value: 'password', label: 'Password Crack', icon: <LockIcon />, color: colors.accent.teal },
  { value: 'social', label: 'Social Engineering', icon: <PsychologyIcon />, color: colors.primary.main },
  { value: 'mass-report', label: 'Mass Report', icon: <GavelIcon />, color: colors.accent.orange },
  { value: 'education', label: 'Education', icon: <SchoolIcon />, color: colors.accent.teal },
];

const statusOptions = [
  { value: 'all', label: 'All Status' },
  { value: 'completed', label: 'Completed' },
  { value: 'running', label: 'Running' },
  { value: 'failed', label: 'Failed' },
];

const dateRanges = [
  { value: 'all', label: 'All Time' },
  { value: 'today', label: 'Today' },
  { value: 'week', label: 'This Week' },
  { value: 'month', label: 'This Month' },
  { value: 'year', label: 'This Year' },
];

const ReportCard: React.FC<{ report: Report }> = ({ report }) => {
  const queryClient = useQueryClient();
  const reportType = reportTypes.find(type => type.value === report.type);

  const deleteMutation = useMutation({
    mutationFn: () => apiClient.deleteReport(report.id),
    onSuccess: () => {
      queryClient.invalidateQueries(['reports']);
    },
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return colors.severity.low;
      case 'running':
        return colors.primary.main;
      case 'failed':
        return colors.severity.critical;
      default:
        return colors.text.secondary;
    }
  };

  const handleDownload = async () => {
    try {
      const response = await apiClient.downloadReport(report.id);
      const blob = new Blob([response], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report-${report.id}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
    }
  };

  return (
    <Card
      sx={{
        backgroundColor: colors.background.paper,
        border: `1px solid ${colors.border.primary}`,
        borderRadius: 2,
        height: '100%',
        transition: 'all 0.3s ease-in-out',
        '&:hover': {
          transform: 'translateY(-2px)',
          boxShadow: `0 8px 32px ${alpha(reportType?.color || colors.primary.main, 0.2)}`,
        },
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 40,
                height: 40,
                borderRadius: '50%',
                backgroundColor: alpha(reportType?.color || colors.primary.main, 0.2),
                color: reportType?.color || colors.primary.main,
                mr: 2,
              }}
            >
              {reportType?.icon}
            </Box>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 600, color: colors.text.primary }}>
                {report.title}
              </Typography>
              <Typography variant="body2" sx={{ color: colors.text.secondary }}>
                {reportType?.label}
              </Typography>
            </Box>
          </Box>
          <IconButton size="small">
            <MoreVertIcon sx={{ color: colors.text.secondary }} />
          </IconButton>
        </Box>

        <Typography variant="body2" sx={{ color: colors.text.secondary, mb: 2, lineHeight: 1.6 }}>
          {report.description}
        </Typography>

        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Chip
            label={report.status}
            size="small"
            sx={{
              backgroundColor: getStatusColor(report.status),
              color: colors.text.primary,
              fontWeight: 600,
            }}
          />
          <Typography variant="caption" sx={{ color: colors.text.secondary }}>
            {new Date(report.created_at).toLocaleDateString()}
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            size="small"
            startIcon={<ViewIcon />}
            sx={{
              borderColor: colors.border.secondary,
              color: colors.text.primary,
              '&:hover': {
                borderColor: colors.primary.main,
              },
            }}
          >
            View
          </Button>
          <Button
            variant="outlined"
            size="small"
            startIcon={<DownloadIcon />}
            onClick={handleDownload}
            sx={{
              borderColor: colors.border.secondary,
              color: colors.text.primary,
              '&:hover': {
                borderColor: colors.primary.main,
              },
            }}
          >
            Download
          </Button>
          <IconButton
            size="small"
            onClick={() => deleteMutation.mutate()}
            disabled={deleteMutation.isPending}
            sx={{
              color: colors.severity.critical,
              '&:hover': {
                backgroundColor: alpha(colors.severity.critical, 0.1),
              },
            }}
          >
            <DeleteIcon />
          </IconButton>
        </Box>
      </CardContent>
    </Card>
  );
};

const ReportsManager: React.FC = () => {
  const [filters, setFilters] = useState<ReportFilters>({
    type: 'all',
    status: 'all',
    dateRange: 'all',
    search: '',
  });

  const {
    data: reports,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['reports'],
    queryFn: () => apiClient.getReports(),
  });

  const filteredReports = reports?.filter(report => {
    if (filters.type !== 'all' && report.type !== filters.type) return false;
    if (filters.status !== 'all' && report.status !== filters.status) return false;
    if (filters.search && !report.title.toLowerCase().includes(filters.search.toLowerCase())) return false;
    return true;
  }) || [];

  const getReportStats = () => {
    if (!reports) return { total: 0, completed: 0, running: 0, failed: 0 };
    
    return reports.reduce((acc, report) => {
      acc.total++;
      acc[report.status as keyof typeof acc]++;
      return acc;
    }, { total: 0, completed: 0, running: 0, failed: 0 });
  };

  const stats = getReportStats();

  const StatCard: React.FC<{
    title: string;
    value: number;
    icon: React.ReactNode;
    color: string;
  }> = ({ title, value, icon, color }) => (
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
            <Typography variant="h4" sx={{ fontWeight: 700, color, mb: 0.5 }}>
              {value}
            </Typography>
            <Typography variant="body2" sx={{ color: colors.text.secondary }}>
              {title}
            </Typography>
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

  return (
    <Box sx={{ flexGrow: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 700, color: colors.text.primary }}>
          Reports Manager
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

      {/* Report Statistics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Reports"
            value={stats.total}
            icon={<AssessmentIcon />}
            color={colors.primary.main}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Completed"
            value={stats.completed}
            icon={<TrendingUpIcon />}
            color={colors.severity.low}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Running"
            value={stats.running}
            icon={<SecurityIcon />}
            color={colors.primary.main}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Failed"
            value={stats.failed}
            icon={<BugReportIcon />}
            color={colors.severity.critical}
          />
        </Grid>
      </Grid>

      {/* Filters */}
      <Card
        sx={{
          backgroundColor: colors.background.paper,
          border: `1px solid ${colors.border.primary}`,
          borderRadius: 2,
          mb: 4,
        }}
      >
        <CardContent sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 600, mb: 3, color: colors.text.primary }}>
            Filters
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} sm={6} md={3}>
              <TextField
                placeholder="Search reports..."
                value={filters.search}
                onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                fullWidth
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon sx={{ color: colors.text.secondary }} />
                    </InputAdornment>
                  ),
                }}
                sx={{
                  '& .MuiOutlinedInput-root': {
                    backgroundColor: colors.background.elevated,
                  },
                }}
              />
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Report Type</InputLabel>
                <Select
                  value={filters.type}
                  onChange={(e) => setFilters({ ...filters, type: e.target.value })}
                  label="Report Type"
                >
                  <MenuItem value="all">All Types</MenuItem>
                  {reportTypes.map((type) => (
                    <MenuItem key={type.value} value={type.value}>
                      {type.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select
                  value={filters.status}
                  onChange={(e) => setFilters({ ...filters, status: e.target.value })}
                  label="Status"
                >
                  {statusOptions.map((status) => (
                    <MenuItem key={status.value} value={status.value}>
                      {status.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <FormControl fullWidth>
                <InputLabel>Date Range</InputLabel>
                <Select
                  value={filters.dateRange}
                  onChange={(e) => setFilters({ ...filters, dateRange: e.target.value })}
                  label="Date Range"
                >
                  {dateRanges.map((range) => (
                    <MenuItem key={range.value} value={range.value}>
                      {range.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Reports Grid */}
      <Grid container spacing={3}>
        {filteredReports.map((report) => (
          <Grid item xs={12} sm={6} md={4} key={report.id}>
            <ReportCard report={report} />
          </Grid>
        ))}
      </Grid>

      {filteredReports.length === 0 && (
        <Card
          sx={{
            backgroundColor: colors.background.paper,
            border: `1px solid ${colors.border.primary}`,
            borderRadius: 2,
            mt: 3,
          }}
        >
          <CardContent sx={{ p: 4, textAlign: 'center' }}>
            <AssessmentIcon sx={{ fontSize: 64, color: colors.text.secondary, mb: 2 }} />
            <Typography variant="h6" sx={{ color: colors.text.secondary, mb: 1 }}>
              No Reports Found
            </Typography>
            <Typography variant="body2" sx={{ color: colors.text.secondary }}>
              Try adjusting your filters or run some scans to generate reports.
            </Typography>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default ReportsManager;