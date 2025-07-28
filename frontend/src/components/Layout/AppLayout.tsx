import React, { useState } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Box,
  Badge,
  Avatar,
  Menu,
  MenuItem,
  Divider,
  Tooltip,
  useTheme,
  useMediaQuery,
  TextField,
  InputAdornment,
  Button,
  Card,
  CardContent,
} from '@mui/material';
import ListItemButton from '@mui/material/ListItemButton';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  NetworkCheck as NetworkIcon,
  Memory as MemoryIcon,
  Assessment as AssessmentIcon,
  Settings as SettingsIcon,
  Logout as LogoutIcon,
  Notifications as NotificationsIcon,
  Person as PersonIcon,
  Shield as ShieldIcon,
  Terminal as TerminalIcon,
  Search as SearchIcon,
  Lock as LockIcon,
  AdminPanelSettings as AdminIcon,
  Wifi as WifiIcon,
  Phishing as PhishingIcon,
  School as SchoolIcon,
  Description as DescriptionIcon,
  WorkspacePremium as WorkspacePremiumIcon,
  Psychology as PsychologyIcon,
  PersonSearch as PersonSearchIcon,
  Gavel as GavelIcon,
  KeyboardArrowRight as ArrowRightIcon,
  KeyboardArrowUp as ArrowUpIcon,
  KeyboardArrowDown as ArrowDownIcon,
  Chat as ChatIcon,
  Upgrade as UpgradeIcon,
} from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate, useLocation } from 'react-router-dom';
import { colors } from '../../theme/theme';
import { alpha } from '@mui/material/styles';
import WarningIcon from '@mui/icons-material/Warning';

const drawerWidth = 280;

interface NavigationItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  path: string;
  roles?: string[];
  hasSubmenu?: boolean;
}

const navigationItems: NavigationItem[] = [
  {
    id: 'dashboard',
    label: 'Overview',
    icon: <DashboardIcon />,
    path: '/dashboard',
  },
  {
    id: 'reports',
    label: 'Reports',
    icon: <AssessmentIcon />,
    path: '/reports',
    hasSubmenu: true,
  },
  {
    id: 'threats',
    label: 'Threats',
    icon: <BugReportIcon />,
    path: '/threats',
    hasSubmenu: true,
  },
  {
    id: 'issues',
    label: 'Issues',
    icon: <WarningIcon />,
    path: '/issues',
    hasSubmenu: true,
  },
  {
    id: 'nmap',
    label: 'Network Scanner',
    icon: <NetworkIcon />,
    path: '/tools/nmap',
  },
  {
    id: 'vulnerability',
    label: 'Vulnerability Scanner',
    icon: <BugReportIcon />,
    path: '/tools/vulnerability',
  },
  {
    id: 'malware',
    label: 'Malware Analyzer',
    icon: <MemoryIcon />,
    path: '/tools/malware',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'network-monitor',
    label: 'Network Monitor',
    icon: <TerminalIcon />,
    path: '/tools/network-monitor',
    roles: ['admin'],
  },
  {
    id: 'wifi',
    label: 'WiFi Tool',
    icon: <WifiIcon />,
    path: '/tools/wifi',
    roles: ['admin'],
  },
  {
    id: 'osint',
    label: 'OSINT Gather',
    icon: <SearchIcon />,
    path: '/tools/osint',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'password-crack',
    label: 'Password Cracker',
    icon: <LockIcon />,
    path: '/tools/password-crack',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'threat-intel',
    label: 'Threat Intelligence',
    icon: <ShieldIcon />,
    path: '/tools/threat-intel',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'sql-injection',
    label: 'SQL Injection Scanner',
    icon: <ShieldIcon />,
    path: '/tools/sql-injection',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'social-engineering',
    label: 'Social Engineering',
    icon: <PsychologyIcon />,
    path: '/tools/social-engineering',
    roles: ['admin', 'analyst', 'user'],
  },
  {
    id: 'sherlock',
    label: 'Username Enumeration',
    icon: <PersonSearchIcon />,
    path: '/tools/sherlock',
    roles: ['admin', 'analyst', 'user'],
  },
  {
    id: 'metasploit',
    label: 'Metasploit Framework',
    icon: <SecurityIcon />,
    path: '/tools/metasploit',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'zap',
    label: 'OWASP ZAP Scanner',
    icon: <BugReportIcon />,
    path: '/tools/zap',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'set',
    label: 'Social Engineer Toolkit',
    icon: <PsychologyIcon />,
    path: '/tools/set',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'mass-report',
    label: 'Mass Report Tool',
    icon: <GavelIcon />,
    path: '/tools/mass-report',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'jobs',
    label: 'Jobs',
    icon: <AssessmentIcon />,
    path: '/jobs',
  },
  {
    id: 'admin',
    label: 'Administration',
    icon: <AdminIcon />,
    path: '/admin',
    roles: ['admin'],
  },
  {
    id: 'education-dashboard',
    label: 'Education',
    icon: <SchoolIcon />,
    path: '/education',
  },
  {
    id: 'education-documents',
    label: 'Document Review',
    icon: <DescriptionIcon />,
    path: '/education/documents',
    roles: ['admin', 'analyst', 'user'],
  },
  {
    id: 'admin-education',
    label: 'Admin Education',
    icon: <WorkspacePremiumIcon />,
    path: '/admin/education',
    roles: ['admin'],
  },
];

interface AppLayoutProps {
  children: React.ReactNode;
}

const AppLayout: React.FC<AppLayoutProps> = ({ children }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const handleProfileMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleProfileMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
    handleProfileMenuClose();
  };

  const handleNavigate = (path: string) => {
    navigate(path);
    if (isMobile) {
      setMobileOpen(false);
    }
  };

  const filteredNavItems = navigationItems.filter(item => {
    if (item.id === 'sql-injection') {
      return ['admin', 'analyst'].includes(user?.role || '');
    }
    if (!item.roles) return true;
    return item.roles.includes(user?.role || '');
  });

  const drawer = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Logo Section */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          p: 3,
          borderBottom: `1px solid ${colors.border.primary}`,
          backgroundColor: colors.background.paper,
        }}
      >
        <ShieldIcon sx={{ mr: 1, color: colors.primary.main, fontSize: 32 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, color: colors.primary.main }}>
          VertexGuard
        </Typography>
      </Box>

      {/* Navigation Sections */}
      <Box sx={{ flexGrow: 1, p: 2 }}>
        {/* General Section */}
        <Typography
          variant="overline"
          sx={{
            color: colors.text.secondary,
            fontWeight: 600,
            fontSize: '0.75rem',
            mb: 1,
            display: 'block',
          }}
        >
          GENERAL
        </Typography>
        <List sx={{ mb: 3 }}>
          {filteredNavItems.slice(0, 4).map((item) => (
            <ListItemButton
              key={item.id}
              onClick={() => handleNavigate(item.path)}
              selected={location.pathname === item.path}
              sx={{
                borderRadius: 2,
                mb: 0.5,
                backgroundColor: location.pathname === item.path ? 
                  colors.primary.main : 'transparent',
                '&:hover': {
                  backgroundColor: location.pathname === item.path ? 
                    colors.primary.dark : alpha(colors.primary.main, 0.1),
                },
                transition: 'all 0.3s ease-in-out',
              }}
            >
              <ListItemIcon
                sx={{
                  color: location.pathname === item.path ? 
                    colors.text.primary : colors.text.secondary,
                  minWidth: 40,
                }}
              >
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  fontSize: '0.875rem',
                  fontWeight: location.pathname === item.path ? 600 : 400,
                  color: location.pathname === item.path ? 
                    colors.text.primary : colors.text.primary,
                }}
              />
              {item.hasSubmenu && (
                <ArrowRightIcon sx={{ color: colors.text.secondary, fontSize: 16 }} />
              )}
            </ListItemButton>
          ))}
        </List>

        {/* Tools Section */}
        <Typography
          variant="overline"
          sx={{
            color: colors.text.secondary,
            fontWeight: 600,
            fontSize: '0.75rem',
            mb: 1,
            display: 'block',
          }}
        >
          TOOLS
        </Typography>
        <List sx={{ mb: 3 }}>
          {filteredNavItems.slice(4, -3).map((item) => (
            <ListItemButton
              key={item.id}
              onClick={() => handleNavigate(item.path)}
              selected={location.pathname === item.path}
              sx={{
                borderRadius: 2,
                mb: 0.5,
                backgroundColor: location.pathname === item.path ? 
                  colors.primary.main : 'transparent',
                '&:hover': {
                  backgroundColor: location.pathname === item.path ? 
                    colors.primary.dark : alpha(colors.primary.main, 0.1),
                },
                transition: 'all 0.3s ease-in-out',
              }}
            >
              <ListItemIcon
                sx={{
                  color: location.pathname === item.path ? 
                    colors.text.primary : colors.text.secondary,
                  minWidth: 40,
                }}
              >
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  fontSize: '0.875rem',
                  fontWeight: location.pathname === item.path ? 600 : 400,
                  color: location.pathname === item.path ? 
                    colors.text.primary : colors.text.primary,
                }}
              />
            </ListItemButton>
          ))}
        </List>

        {/* Settings Section */}
        <Typography
          variant="overline"
          sx={{
            color: colors.text.secondary,
            fontWeight: 600,
            fontSize: '0.75rem',
            mb: 1,
            display: 'block',
          }}
        >
          SETTINGS
        </Typography>
        <List sx={{ mb: 3 }}>
          {filteredNavItems.slice(-3).map((item) => (
            <ListItemButton
              key={item.id}
              onClick={() => handleNavigate(item.path)}
              selected={location.pathname === item.path}
              sx={{
                borderRadius: 2,
                mb: 0.5,
                backgroundColor: location.pathname === item.path ? 
                  colors.primary.main : 'transparent',
                '&:hover': {
                  backgroundColor: location.pathname === item.path ? 
                    colors.primary.dark : alpha(colors.primary.main, 0.1),
                },
                transition: 'all 0.3s ease-in-out',
              }}
            >
              <ListItemIcon
                sx={{
                  color: location.pathname === item.path ? 
                    colors.text.primary : colors.text.secondary,
                  minWidth: 40,
                }}
              >
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  fontSize: '0.875rem',
                  fontWeight: location.pathname === item.path ? 600 : 400,
                  color: location.pathname === item.path ? 
                    colors.text.primary : colors.text.primary,
                }}
              />
            </ListItemButton>
          ))}
        </List>
      </Box>

      {/* Upgrade Card */}
      <Box sx={{ p: 2 }}>
        <Card
          sx={{
            backgroundColor: alpha(colors.primary.main, 0.1),
            border: `1px solid ${colors.primary.main}40`,
            borderRadius: 2,
          }}
        >
          <CardContent sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <UpgradeIcon sx={{ color: colors.accent.teal, mr: 1, fontSize: 20 }} />
              <Typography variant="body2" sx={{ fontWeight: 600, color: colors.text.primary }}>
                Upgrade to Pro
              </Typography>
            </Box>
            <Typography variant="caption" sx={{ color: colors.text.secondary, mb: 2, display: 'block' }}>
              Get advanced features and priority support
            </Typography>
            <Button
              variant="contained"
              size="small"
              endIcon={<ArrowRightIcon />}
              sx={{
                backgroundColor: colors.primary.main,
                '&:hover': {
                  backgroundColor: colors.primary.dark,
                },
                fontSize: '0.75rem',
                py: 0.5,
                px: 1.5,
              }}
            >
              Upgrade
            </Button>
          </CardContent>
        </Card>
      </Box>

      {/* Logout Button */}
      <Box sx={{ p: 2, borderTop: `1px solid ${colors.border.primary}` }}>
        <Button
          fullWidth
          variant="outlined"
          startIcon={<LogoutIcon />}
          onClick={handleLogout}
          sx={{
            borderColor: colors.border.secondary,
            color: colors.text.primary,
            '&:hover': {
              borderColor: colors.severity.critical,
              color: colors.severity.critical,
            },
          }}
        >
          Log Out
        </Button>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          width: { md: `calc(100% - ${drawerWidth}px)` },
          ml: { md: `${drawerWidth}px` },
          backgroundColor: colors.background.paper,
          boxShadow: `0 2px 8px ${alpha(colors.background.default, 0.4)}`,
        }}
      >
        <Toolbar sx={{ px: 3 }}>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { md: 'none' } }}
          >
            <MenuIcon />
          </IconButton>

          {/* Header Content */}
          <Box sx={{ display: 'flex', alignItems: 'center', flexGrow: 1 }}>
            {/* User Welcome */}
            <Box sx={{ display: 'flex', alignItems: 'center', mr: 4 }}>
              <Avatar
                sx={{
                  width: 40,
                  height: 40,
                  backgroundColor: colors.accent.teal,
                  fontSize: '1rem',
                  mr: 2,
                }}
              >
                {user?.username?.charAt(0).toUpperCase()}
              </Avatar>
              <Box>
                <Typography variant="body1" sx={{ fontWeight: 600, color: colors.text.primary }}>
                  Welcome! {user?.username}
                </Typography>
                <Typography variant="caption" sx={{ color: colors.text.secondary }}>
                  Security is a process, not a product.
                </Typography>
              </Box>
            </Box>

            {/* Search Bar */}
            <TextField
              placeholder="Search Here"
              variant="outlined"
              size="small"
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon sx={{ color: colors.text.secondary }} />
                  </InputAdornment>
                ),
              }}
              sx={{
                minWidth: 300,
                '& .MuiOutlinedInput-root': {
                  backgroundColor: colors.background.elevated,
                  '& fieldset': {
                    borderColor: colors.border.secondary,
                  },
                  '&:hover fieldset': {
                    borderColor: colors.border.accent,
                  },
                },
              }}
            />
          </Box>

          {/* Header Actions */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Tooltip title="Notifications">
              <IconButton color="inherit">
                <Badge badgeContent={3} color="error">
                  <NotificationsIcon />
                </Badge>
              </IconButton>
            </Tooltip>
            <Tooltip title="Messages">
              <IconButton color="inherit">
                <Badge badgeContent={1} color="error">
                  <ChatIcon />
                </Badge>
              </IconButton>
            </Tooltip>
          </Box>
        </Toolbar>
      </AppBar>

      <Box
        component="nav"
        sx={{ width: { md: drawerWidth }, flexShrink: { md: 0 } }}
      >
        <Drawer
          variant={isMobile ? 'temporary' : 'permanent'}
          open={isMobile ? mobileOpen : true}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true,
          }}
          sx={{
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
              backgroundColor: colors.background.paper,
              borderRight: `1px solid ${colors.border.primary}`,
            },
          }}
        >
          {drawer}
        </Drawer>
      </Box>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { md: `calc(100% - ${drawerWidth}px)` },
          mt: '64px',
          minHeight: 'calc(100vh - 64px)',
          backgroundColor: colors.background.default,
        }}
      >
        {children}
      </Box>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleProfileMenuClose}
        PaperProps={{
          sx: {
            mt: 1,
            minWidth: 200,
            backgroundColor: colors.background.paper,
            border: `1px solid ${colors.border.primary}`,
            borderRadius: 2,
          },
        }}
      >
        <MenuItem onClick={handleProfileMenuClose}>
          <PersonIcon sx={{ mr: 2, fontSize: 20 }} />
          Profile
        </MenuItem>
        <MenuItem onClick={handleProfileMenuClose}>
          <SettingsIcon sx={{ mr: 2, fontSize: 20 }} />
          Settings
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleLogout}>
          <LogoutIcon sx={{ mr: 2, fontSize: 20 }} />
          Logout
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default AppLayout;