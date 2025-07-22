import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
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
  Chip,
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
  Button,
  Alert,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
} from '@mui/material';
import {
  Visibility as ViewIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Search as SearchIcon,
  PlayArrow as PlayIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Schedule as ScheduleIcon,
  Cancel as CancelIcon,
  Assessment as ReportIcon,
  GetApp as DownloadIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { Job, JobResult, Vulnerability, MITRETechnique } from '../../types/api';

interface JobDetailsResponse {
  job: Job;
  results: JobResult[];
  vulnerabilities: Vulnerability[];
  mitre_mappings: MITRETechnique[];
}

const JobsManager: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [toolFilter, setToolFilter] = useState('all');
  const [selectedJob, setSelectedJob] = useState<JobDetailsResponse | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const queryClient = useQueryClient();

  const {
    data: jobs,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['jobs'],
    queryFn: () => apiClient.getJobs(),
    refetchInterval: 5000, // Auto-refresh every 5 seconds
  });

  const jobDetailsMutation = useMutation({
    mutationFn: (jobId: number) => apiClient.getJob(jobId),
    onSuccess: (data) => {
      setSelectedJob(data);
      setDetailsOpen(true);
    },
  });

  const cancelJobMutation = useMutation({
    mutationFn: (jobId: number) => apiClient.cancelJob(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
    },
  });

  const downloadReportMutation = useMutation({
    mutationFn: (jobId: number) => apiClient.getJobReport(jobId),
    onSuccess: (data, jobId) => {
      const blob = new Blob([data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `job_report_${jobId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    },
  });

  const handleViewJob = (jobId: number) => {
    jobDetailsMutation.mutate(jobId);
  };

  const handleCancelJob = (jobId: number) => {
    cancelJobMutation.mutate(jobId);
  };

  const handleDownloadReport = (jobId: number) => {
    downloadReportMutation.mutate(jobId);
  };

  const handleCloseDetails = () => {
    setDetailsOpen(false);
    setSelectedJob(null);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return colors.severity.low;
      case 'running':
        return colors.primary.main;
      case 'failed':
        return colors.severity.critical;
      case 'pending':
        return colors.severity.medium;
      case 'cancelled':
        return colors.text.secondary;
      default:
        return colors.text.secondary;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckIcon />;
      case 'running':
        return <PlayIcon />;
      case 'failed':
        return <ErrorIcon />;
      case 'pending':
        return <ScheduleIcon />;
      case 'cancelled':
        return <CancelIcon />;
      default:
        return <ScheduleIcon />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return colors.severity.critical;
      case 'high':
        return colors.severity.high;
      case 'medium':
        return colors.severity.medium;
      case 'low':
        return colors.severity.low;
      default:
        return colors.severity.info;
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const filteredJobs = jobs?.data?.filter((job: Job) => {
    const matchesSearch = job.tool_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         job.target_value?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         job.job_id.toString().includes(searchTerm);
    const matchesStatus = statusFilter === 'all' || job.status === statusFilter;
    const matchesTool = toolFilter === 'all' || job.tool_name === toolFilter;
    
    return matchesSearch && matchesStatus && matchesTool;
  }) || [];

  const uniqueTools = [...new Set(jobs?.data?.map((job: Job) => job.tool_name).filter(Boolean))] || [];

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Jobs Manager
      </Typography>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ backgroundColor: colors.primary.main + '20' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: colors.primary.main, fontWeight: 600 }}>
                {filteredJobs.length}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Total Jobs
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ backgroundColor: colors.severity.low + '20' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: colors.severity.low, fontWeight: 600 }}>
                {filteredJobs.filter((job: Job) => job.status === 'completed').length}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Completed
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ backgroundColor: colors.severity.high + '20' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: colors.severity.high, fontWeight: 600 }}>
                {filteredJobs.filter((job: Job) => job.status === 'running').length}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Running
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ backgroundColor: colors.severity.critical + '20' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: colors.severity.critical, fontWeight: 600 }}>
                {filteredJobs.filter((job: Job) => job.status === 'failed').length}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Failed
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              Job History
            </Typography>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Tooltip title="Refresh">
                <IconButton onClick={() => refetch()}>
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
            </Box>
          </Box>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} sm={6} md={4}>
              <TextField
                fullWidth
                size="small"
                placeholder="Search jobs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
              <FormControl fullWidth size="small">
                <InputLabel>Status</InputLabel>
                <Select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  label="Status"
                >
                  <MenuItem value="all">All Status</MenuItem>
                  <MenuItem value="completed">Completed</MenuItem>
                  <MenuItem value="running">Running</MenuItem>
                  <MenuItem value="failed">Failed</MenuItem>
                  <MenuItem value="pending">Pending</MenuItem>
                  <MenuItem value="cancelled">Cancelled</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
              <FormControl fullWidth size="small">
                <InputLabel>Tool</InputLabel>
                <Select
                  value={toolFilter}
                  onChange={(e) => setToolFilter(e.target.value)}
                  label="Tool"
                >
                  <MenuItem value="all">All Tools</MenuItem>
                  {uniqueTools.map((tool) => (
                    <MenuItem key={tool} value={tool}>
                      {tool}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
          </Grid>

          {isLoading && <LinearProgress sx={{ mb: 2 }} />}

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              Failed to load jobs: {error.message}
            </Alert>
          )}

          <TableContainer component={Paper} sx={{ backgroundColor: colors.background.paper }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 600 }}>Job ID</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Tool</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Target</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Created</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Completed</TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredJobs.map((job: Job) => (
                  <TableRow key={job.job_id} hover>
                    <TableCell sx={{ fontFamily: 'monospace', fontWeight: 600 }}>
                      #{job.job_id}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={job.tool_name || 'Unknown'}
                        size="small"
                        sx={{
                          backgroundColor: colors.primary.main + '30',
                          color: colors.primary.main,
                        }}
                      />
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                      {job.target_value || 'N/A'}
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={job.status.toUpperCase()}
                        size="small"
                        icon={getStatusIcon(job.status)}
                        sx={{
                          backgroundColor: getStatusColor(job.status) + '30',
                          color: getStatusColor(job.status),
                        }}
                      />
                    </TableCell>
                    <TableCell sx={{ fontSize: '0.875rem' }}>
                      {formatDate(job.created_at)}
                    </TableCell>
                    <TableCell sx={{ fontSize: '0.875rem' }}>
                      {job.completed_at ? formatDate(job.completed_at) : '-'}
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Tooltip title="View Details">
                          <IconButton
                            size="small"
                            onClick={() => handleViewJob(job.job_id)}
                            disabled={jobDetailsMutation.isPending}
                          >
                            <ViewIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        {job.status === 'running' && (
                          <Tooltip title="Cancel Job">
                            <IconButton
                              size="small"
                              onClick={() => handleCancelJob(job.job_id)}
                              disabled={cancelJobMutation.isPending}
                            >
                              <StopIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                        {job.status === 'completed' && (
                          <Tooltip title="Download Report">
                            <IconButton
                              size="small"
                              onClick={() => handleDownloadReport(job.job_id)}
                              disabled={downloadReportMutation.isPending}
                            >
                              <DownloadIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {filteredJobs.length === 0 && !isLoading && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="body1" color="text.secondary">
                No jobs found matching your criteria.
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Job Details Dialog */}
      <Dialog
        open={detailsOpen}
        onClose={handleCloseDetails}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: {
            backgroundColor: colors.background.paper,
            border: `1px solid ${colors.border.primary}`,
            maxHeight: '90vh',
          },
        }}
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ReportIcon />
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              Job Details #{selectedJob?.job.job_id}
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedJob && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Tool
                  </Typography>
                  <Chip
                    label={selectedJob.job.tool_name}
                    sx={{
                      backgroundColor: colors.primary.main + '30',
                      color: colors.primary.main,
                    }}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Status
                  </Typography>
                  <Chip
                    label={selectedJob.job.status.toUpperCase()}
                    icon={getStatusIcon(selectedJob.job.status)}
                    sx={{
                      backgroundColor: getStatusColor(selectedJob.job.status) + '30',
                      color: getStatusColor(selectedJob.job.status),
                    }}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Target
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {selectedJob.job.target_value || 'N/A'}
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Parameters
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {JSON.stringify(selectedJob.job.parameters)}
                  </Typography>
                </Grid>
              </Grid>

              <Divider sx={{ mb: 2 }} />

              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                Vulnerabilities Found ({selectedJob.vulnerabilities.length})
              </Typography>
              {selectedJob.vulnerabilities.length > 0 ? (
                <List>
                  {selectedJob.vulnerabilities.map((vuln) => (
                    <ListItem
                      key={vuln.vulnerability_id}
                      sx={{
                        mb: 1,
                        backgroundColor: colors.background.elevated,
                        borderRadius: 1,
                        border: `1px solid ${getSeverityColor(vuln.severity)}40`,
                      }}
                    >
                      <ListItemIcon>
                        <ErrorIcon sx={{ color: getSeverityColor(vuln.severity) }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                              {vuln.name}
                            </Typography>
                            <Chip
                              label={vuln.severity.toUpperCase()}
                              size="small"
                              sx={{
                                backgroundColor: getSeverityColor(vuln.severity) + '30',
                                color: getSeverityColor(vuln.severity),
                              }}
                            />
                          </Box>
                        }
                        secondary={
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="body2" sx={{ mb: 1 }}>
                              {vuln.description}
                            </Typography>
                            {vuln.cve && (
                              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                CVE: {vuln.cve}
                              </Typography>
                            )}
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Alert severity="success">No vulnerabilities found</Alert>
              )}

              <Divider sx={{ my: 2 }} />

              <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                MITRE ATT&CK Mappings ({selectedJob.mitre_mappings.length})
              </Typography>
              {selectedJob.mitre_mappings.length > 0 ? (
                <List>
                  {selectedJob.mitre_mappings.map((technique, index) => (
                    <ListItem
                      key={index}
                      sx={{
                        mb: 1,
                        backgroundColor: colors.background.elevated,
                        borderRadius: 1,
                      }}
                    >
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                              {technique.technique_name}
                            </Typography>
                            <Chip
                              label={technique.technique_id}
                              size="small"
                              sx={{
                                backgroundColor: colors.primary.main + '30',
                                color: colors.primary.main,
                              }}
                            />
                          </Box>
                        }
                        secondary={technique.description}
                      />
                    </ListItem>
                  ))}
                </List>
              ) : (
                <Alert severity="info">No MITRE ATT&CK mappings available</Alert>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDetails}>Close</Button>
          {selectedJob?.job.status === 'completed' && (
            <Button
              variant="contained"
              onClick={() => handleDownloadReport(selectedJob.job.job_id)}
              sx={{
                backgroundColor: colors.primary.main,
                '&:hover': {
                  backgroundColor: colors.primary.dark,
                },
              }}
            >
              Download Report
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default JobsManager;