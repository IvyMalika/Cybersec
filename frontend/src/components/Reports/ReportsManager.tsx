import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
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
  Alert,
  LinearProgress,
  Fade,
} from '@mui/material';
import {
  GetApp as DownloadIcon,
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  Assessment as ReportIcon,
  PictureAsPdf as PdfIcon,
  Description as DocIcon,
  TableChart as CsvIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { Job } from '../../types/api';

interface ReportPreview {
  job_id: number;
  title: string;
  tool_name: string;
  target: string;
  status: string;
  created_at: string;
  completed_at: string;
  vulnerabilities_count: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

const ReportsManager: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [toolFilter, setToolFilter] = useState('all');
  const [selectedReport, setSelectedReport] = useState<ReportPreview | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const queryClient = useQueryClient();

  const {
    data: jobs,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['jobs'],
    queryFn: () => apiClient.getJobs(),
  });

  const downloadMutation = useMutation({
    mutationFn: (jobId: number) => apiClient.getJobReport(jobId),
    onSuccess: (data, jobId) => {
      const blob = new Blob([data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${jobId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    },
    onError: (error) => {
      console.error('Failed to download report:', error);
    },
  });

  const handleDownloadReport = (jobId: number) => {
    downloadMutation.mutate(jobId);
  };

  const handleViewReport = (job: Job) => {
    const reportPreview: ReportPreview = {
      job_id: job.job_id,
      title: `${job.tool_name} - ${job.target_value}`,
      tool_name: job.tool_name || 'Unknown Tool',
      target: job.target_value || 'Unknown Target',
      status: job.status,
      created_at: job.created_at,
      completed_at: job.completed_at || '',
      vulnerabilities_count: 0, // This would come from the API
      severity_breakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
    };
    setSelectedReport(reportPreview);
    setPreviewOpen(true);
  };

  const handleClosePreview = () => {
    setPreviewOpen(false);
    setSelectedReport(null);
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
      default:
        return colors.text.secondary;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return '✓';
      case 'running':
        return '⟳';
      case 'failed':
        return '✗';
      case 'pending':
        return '⏳';
      default:
        return '?';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const filteredJobs = jobs?.data?.filter((job: Job) => {
    const matchesSearch = job.tool_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         job.target_value?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || job.status === statusFilter;
    const matchesTool = toolFilter === 'all' || job.tool_name === toolFilter;
    
    return matchesSearch && matchesStatus && matchesTool;
  }) || [];

  const uniqueTools = [...new Set(jobs?.data?.map((job: Job) => job.tool_name).filter(Boolean))] || [];

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Reports Manager
      </Typography>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ backgroundColor: colors.primary.main + '20' }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: colors.primary.main, fontWeight: 600 }}>
                {filteredJobs.length}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Total Reports
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
              Available Reports
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
                placeholder="Search reports..."
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
              Failed to load reports: {error.message}
            </Alert>
          )}

          <TableContainer component={Paper} sx={{ backgroundColor: colors.background.paper }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 600 }}>Report</TableCell>
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
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <ReportIcon />
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>
                          Report #{job.job_id}
                        </Typography>
                      </Box>
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
                        label={`${getStatusIcon(job.status)} ${job.status.toUpperCase()}`}
                        size="small"
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
                        <Tooltip title="View Report">
                          <IconButton
                            size="small"
                            onClick={() => handleViewReport(job)}
                          >
                            <ViewIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        {job.status === 'completed' && (
                          <Tooltip title="Download PDF">
                            <IconButton
                              size="small"
                              onClick={() => handleDownloadReport(job.job_id)}
                              disabled={downloadMutation.isPending}
                            >
                              {downloadMutation.isPending ? (
                                <RefreshIcon fontSize="small" sx={{ animation: 'spin 1s linear infinite' }} />
                              ) : (
                                <DownloadIcon fontSize="small" />
                              )}
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
                No reports found matching your criteria.
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Report Preview Dialog */}
      <Dialog
        open={previewOpen}
        onClose={handleClosePreview}
        maxWidth="md"
        fullWidth
        PaperProps={{
          sx: {
            backgroundColor: colors.background.paper,
            border: `1px solid ${colors.border.primary}`,
          },
        }}
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ReportIcon />
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              Report Preview
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedReport && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Report Title
                  </Typography>
                  <Typography variant="body2">{selectedReport.title}</Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Tool Used
                  </Typography>
                  <Chip
                    label={selectedReport.tool_name}
                    size="small"
                    sx={{
                      backgroundColor: colors.primary.main + '30',
                      color: colors.primary.main,
                    }}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Target
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {selectedReport.target}
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Status
                  </Typography>
                  <Chip
                    label={selectedReport.status.toUpperCase()}
                    size="small"
                    sx={{
                      backgroundColor: getStatusColor(selectedReport.status) + '30',
                      color: getStatusColor(selectedReport.status),
                    }}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Created
                  </Typography>
                  <Typography variant="body2">
                    {formatDate(selectedReport.created_at)}
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                    Completed
                  </Typography>
                  <Typography variant="body2">
                    {selectedReport.completed_at ? formatDate(selectedReport.completed_at) : 'Not completed'}
                  </Typography>
                </Grid>
              </Grid>

              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 2 }}>
                Available Formats
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
                <Button
                  variant="outlined"
                  startIcon={<PdfIcon />}
                  onClick={() => handleDownloadReport(selectedReport.job_id)}
                  disabled={selectedReport.status !== 'completed'}
                  sx={{
                    borderColor: colors.severity.critical,
                    color: colors.severity.critical,
                    '&:hover': {
                      borderColor: colors.severity.critical,
                      backgroundColor: colors.severity.critical + '10',
                    },
                  }}
                >
                  PDF Report
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<DocIcon />}
                  disabled
                  sx={{ opacity: 0.5 }}
                >
                  Word Document (Coming Soon)
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<CsvIcon />}
                  disabled
                  sx={{ opacity: 0.5 }}
                >
                  CSV Export (Coming Soon)
                </Button>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClosePreview}>Close</Button>
          {selectedReport && selectedReport.status === 'completed' && (
            <Button
              variant="contained"
              onClick={() => handleDownloadReport(selectedReport.job_id)}
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

export default ReportsManager;