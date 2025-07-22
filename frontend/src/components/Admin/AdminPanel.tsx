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
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  Tabs,
  Tab,
  Switch,
  FormControlLabel,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
} from '@mui/material';
import {
  Edit as EditIcon,
  Block as BlockIcon,
  CheckCircle as CheckIcon,
  Cancel as CancelIcon,
  Person as PersonIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  Settings as SettingsIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../utils/api';
import { colors } from '../../theme/theme';
import { User, Job, AuditLog } from '../../types/api';

// --- Helper Functions ---
const getRoleColor = (role: string) => {
  switch (role) {
    case 'admin':
      return colors.severity.critical;
    case 'analyst':
      return colors.severity.high;
    case 'user':
      return colors.primary.main;
    default:
      return colors.text.secondary;
  }
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

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleString();
};

// --- Target Approval Tab ---
const TargetApprovalTab: React.FC = () => {
  const queryClient = useQueryClient();
  const {
    data: targets,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['targets'],
    queryFn: () => apiClient.getTargets(),
  });

  const approveMutation = useMutation({
    mutationFn: (targetId: number) => apiClient.approveTarget(targetId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
    },
  });

  if (isLoading) return <Typography>Loading targets...</Typography>;
  if (error) return <Alert severity="error">Failed to load targets</Alert>;
  if (!targets || !Array.isArray(targets)) return <Typography>No targets found.</Typography>;

  return (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>ID</TableCell>
            <TableCell>Target Value</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Action</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {targets.map((target: any) => (
            <TableRow key={target.target_id}>
              <TableCell>{target.target_id}</TableCell>
              <TableCell>{target.target_value}</TableCell>
              <TableCell>
                <Chip
                  label={target.authorization_status}
                  color={target.authorization_status === 'approved' ? 'success' : 'warning'}
                />
              </TableCell>
              <TableCell>
                {target.authorization_status !== 'approved' && (
                  <Button
                    variant="contained"
                    color="primary"
                    size="small"
                    onClick={() => approveMutation.mutate(target.target_id)}
                    disabled={approveMutation.isPending}
                  >
                    Approve
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
};

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function CustomTabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`admin-tabpanel-${index}`}
      aria-labelledby={`admin-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const AdminPanel: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [editUserOpen, setEditUserOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [userRole, setUserRole] = useState('');
  const [userActive, setUserActive] = useState(true);
  const queryClient = useQueryClient();

  // Data fetching
  const {
    data: users,
    isLoading: usersLoading,
    error: usersError,
  } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => apiClient.getUsers(),
  });

  const {
    data: adminJobs,
    isLoading: jobsLoading,
    error: jobsError,
  } = useQuery({
    queryKey: ['admin-jobs'],
    queryFn: () => apiClient.getAdminJobs(),
  });

  const {
    data: auditLogs,
    isLoading: logsLoading,
    error: logsError,
  } = useQuery({
    queryKey: ['audit-logs'],
    queryFn: () => apiClient.getAuditLogs(),
  });

  // Mutations
  const updateUserMutation = useMutation({
    mutationFn: ({ userId, data }: { userId: number; data: { role: string; is_active: boolean } }) =>
      apiClient.updateUser(userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      setEditUserOpen(false);
      setSelectedUser(null);
    },
  });

  const cancelJobMutation = useMutation({
    mutationFn: (jobId: number) => apiClient.cancelJob(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-jobs'] });
    },
  });

  // Handlers
  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => setTabValue(newValue);

  const handleEditUser = (user: User) => {
    setSelectedUser(user);
    setUserRole(user.role);
    setUserActive(user.is_active);
    setEditUserOpen(true);
  };

  const handleUpdateUser = () => {
    if (selectedUser) {
      updateUserMutation.mutate({
        userId: selectedUser.user_id,
        data: { role: userRole, is_active: userActive },
      });
    }
  };

  const handleCancelJob = (jobId: number) => cancelJobMutation.mutate(jobId);

  // --- RENDER ---
  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <Tabs value={tabValue} onChange={handleTabChange} aria-label="Admin Panel Tabs">
        <Tab label="Users" />
        <Tab label="Jobs" />
        <Tab label="Audit Logs" />
        <Tab label="System" />
        <Tab label="Target Approval" />
      </Tabs>

      {/* Users Tab */}
      <CustomTabPanel value={tabValue} index={0}>
        <Card>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
              User Management
            </Typography>
            <div className="card-grid" sx={{ mb: 3 }}>
              <div className="card-grid-item">
                <Card sx={{ backgroundColor: colors.primary.main + '20' }}>
                  <CardContent sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" sx={{ color: colors.primary.main, fontWeight: 600 }}>
                      {users?.users?.length || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Total Users
                    </Typography>
                  </CardContent>
                </Card>
              </div>
              <div className="card-grid-item">
                <Card sx={{ backgroundColor: colors.severity.critical + '20' }}>
                  <CardContent sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" sx={{ color: colors.severity.critical, fontWeight: 600 }}>
                      {users?.users?.filter((u: User) => u.role === 'admin').length || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Administrators
                    </Typography>
                  </CardContent>
                </Card>
              </div>
              <div className="card-grid-item">
                <Card sx={{ backgroundColor: colors.severity.high + '20' }}>
                  <CardContent sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" sx={{ color: colors.severity.high, fontWeight: 600 }}>
                      {users?.users?.filter((u: User) => u.role === 'analyst').length || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Analysts
                    </Typography>
                  </CardContent>
                </Card>
              </div>
              <div className="card-grid-item">
                <Card sx={{ backgroundColor: colors.severity.low + '20' }}>
                  <CardContent sx={{ textAlign: 'center' }}>
                    <Typography variant="h4" sx={{ color: colors.severity.low, fontWeight: 600 }}>
                      {users?.users?.filter((u: User) => u.is_active).length || 0}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Active Users
                    </Typography>
                  </CardContent>
                </Card>
              </div>
            </div>
            <TableContainer component={Paper} sx={{ backgroundColor: colors.background.paper }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600 }}>User</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Email</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Role</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Created</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Last Login</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>MFA</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {users?.users?.map((user: User) => (
                    <TableRow key={user.user_id} hover>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <PersonIcon />
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>
                            {user.username}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>{user.email}</TableCell>
                      <TableCell>
                        <Chip
                          label={user.role.toUpperCase()}
                          size="small"
                          sx={{
                            backgroundColor: getRoleColor(user.role) + '30',
                            color: getRoleColor(user.role),
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={user.is_active ? 'ACTIVE' : 'INACTIVE'}
                          size="small"
                          icon={user.is_active ? <CheckIcon /> : <BlockIcon />}
                          sx={{
                            backgroundColor: user.is_active ? colors.severity.low + '30' : colors.severity.critical + '30',
                            color: user.is_active ? colors.severity.low : colors.severity.critical,
                          }}
                        />
                      </TableCell>
                      <TableCell sx={{ fontSize: '0.875rem' }}>
                        {formatDate(user.created_at)}
                      </TableCell>
                      <TableCell sx={{ fontSize: '0.875rem' }}>
                        {user.last_login ? formatDate(user.last_login) : 'Never'}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={user.mfa_enabled ? 'ENABLED' : 'DISABLED'}
                          size="small"
                          sx={{
                            backgroundColor: user.mfa_enabled ? colors.severity.low + '30' : colors.severity.medium + '30',
                            color: user.mfa_enabled ? colors.severity.low : colors.severity.medium,
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Tooltip title="Edit User">
                          <IconButton size="small" onClick={() => handleEditUser(user)}>
                            <EditIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      </CustomTabPanel>

      {/* Jobs Tab */}
      <CustomTabPanel value={tabValue} index={1}>
        <Card>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
              Job Management
            </Typography>
            <TableContainer component={Paper} sx={{ backgroundColor: colors.background.paper }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600 }}>Job ID</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>User</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Tool</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Target</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Created</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Completed</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {adminJobs?.jobs?.map((job: Job) => (
                    <TableRow key={job.job_id} hover>
                      <TableCell sx={{ fontFamily: 'monospace' }}>#{job.job_id}</TableCell>
                      <TableCell>{job.username}</TableCell>
                      <TableCell>
                        <Chip
                          label={job.tool_name}
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
                        {job.status === 'running' && (
                          <Tooltip title="Cancel Job">
                            <IconButton
                              size="small"
                              onClick={() => handleCancelJob(job.job_id)}
                              disabled={cancelJobMutation.isPending}
                            >
                              <CancelIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      </CustomTabPanel>

      {/* Audit Logs Tab */}
      <CustomTabPanel value={tabValue} index={2}>
        <Card>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
              Audit Logs
            </Typography>
            <TableContainer component={Paper} sx={{ backgroundColor: colors.background.paper, maxHeight: 600 }}>
              <Table stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600 }}>Timestamp</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>User</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Action</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>Entity</TableCell>
                    <TableCell sx={{ fontWeight: 600 }}>IP Address</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {auditLogs?.logs?.map((log: AuditLog) => (
                    <TableRow key={log.log_id} hover>
                      <TableCell sx={{ fontSize: '0.875rem' }}>
                        {formatDate(log.timestamp)}
                      </TableCell>
                      <TableCell>{log.username}</TableCell>
                      <TableCell>
                        <Chip
                          label={log.action}
                          size="small"
                          sx={{
                            backgroundColor: colors.primary.main + '30',
                            color: colors.primary.main,
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        {log.entity_type && log.entity_id
                          ? `${log.entity_type} #${log.entity_id}`
                          : '-'}
                      </TableCell>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                        {log.ip_address}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      </CustomTabPanel>

      {/* System Tab */}
      <CustomTabPanel value={tabValue} index={3}>
        <div className="admin-panel-grid">
          <div className="admin-panel-grid-item">
  <Card>
    <CardContent>
      <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
        System Settings
      </Typography>
      <List>
        <ListItem>
          <ListItemIcon>
            <SecurityIcon />
          </ListItemIcon>
          <ListItemText
            primary="Security Settings"
            secondary="Configure authentication and security policies"
          />
        </ListItem>
        <Divider />
        <ListItem>
          <ListItemIcon>
            <AssessmentIcon />
          </ListItemIcon>
          <ListItemText
            primary="Report Settings"
            secondary="Configure report generation and retention"
          />
        </ListItem>
        <Divider />
        <ListItem>
          <ListItemIcon>
            <SettingsIcon />
          </ListItemIcon>
          <ListItemText
            primary="Tool Configuration"
            secondary="Configure security tools and integrations"
          />
        </ListItem>
      </List>
    </CardContent>
  </Card>
</div>
          <div className="admin-panel-grid-item">
  <Card>
    <CardContent>
      <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
        System Status
      </Typography>
      <Alert severity="success" sx={{ mb: 2 }}>
        All systems operational
      </Alert>
      <List>
        <ListItem>
          <ListItemText
            primary="Database"
            secondary="Connected and operational"
          />
          <CheckIcon sx={{ color: colors.severity.low }} />
        </ListItem>
        <ListItem>
          <ListItemText
            primary="API Services"
            secondary="All endpoints responding"
          />
          <CheckIcon sx={{ color: colors.severity.low }} />
        </ListItem>
        <ListItem>
          <ListItemText
            primary="Background Jobs"
            secondary="Processing normally"
          />
          <CheckIcon sx={{ color: colors.severity.low }} />
        </ListItem>
      </List>
    </CardContent>
  </Card>
</div>
        </div>
      </CustomTabPanel>

      {/* Target Approval Tab */}
      <CustomTabPanel value={tabValue} index={4}>
        <TargetApprovalTab />
      </CustomTabPanel>

      {/* Edit User Dialog */}
      <Dialog
        open={editUserOpen}
        onClose={() => setEditUserOpen(false)}
        maxWidth="sm"
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
            <EditIcon />
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              Edit User
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedUser && (
            <Box sx={{ pt: 1 }}>
              <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 600 }}>
                User: {selectedUser.username}
              </Typography>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Role</InputLabel>
                <Select
                  value={userRole}
                  onChange={(e) => setUserRole(e.target.value)}
                  label="Role"
                >
                  <MenuItem value="user">User</MenuItem>
                  <MenuItem value="analyst">Analyst</MenuItem>
                  <MenuItem value="admin">Administrator</MenuItem>
                </Select>
              </FormControl>
              <FormControlLabel
                control={
                  <Switch
                    checked={userActive}
                    onChange={(e) => setUserActive(e.target.checked)}
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
                label="Active User"
              />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditUserOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleUpdateUser}
            disabled={updateUserMutation.isPending}
            sx={{
              backgroundColor: colors.primary.main,
              '&:hover': {
                backgroundColor: colors.primary.dark,
              },
            }}
          >
            Update User
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

// Add responsive card grid styles
const style = document.createElement('style');
style.textContent = `
.card-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
}
.card-grid-item {
  flex: 1 1 100%;
  max-width: 100%;
}
@media (min-width: 600px) {
  .card-grid-item { flex: 1 1 48%; max-width: 48%; }
}
@media (min-width: 900px) {
  .card-grid-item { flex: 1 1 23%; max-width: 23%; }
}
`;
document.head.appendChild(style);

export default AdminPanel;