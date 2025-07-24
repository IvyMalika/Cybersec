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
} from '@mui/material';
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
} from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate, useLocation } from 'react-router-dom';
import { colors } from '../../theme/theme';

const drawerWidth = 260;

interface NavigationItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  path: string;
  roles?: string[];
}

const navigationItems: NavigationItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: <DashboardIcon />,
    path: '/dashboard',
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
    icon: <PhishingIcon />,
    path: '/tools/social-engineering',
    roles: ['admin', 'analyst'],
  },
  {
    id: 'reports',
    label: 'Reports',
    icon: <AssessmentIcon />,
    path: '/reports',
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
      // Always allow access to SQL Injection Scanner for admin and analyst
      return ['admin', 'analyst'].includes(user?.role || '');
    }
    if (!item.roles) return true;
    return item.roles.includes(user?.role || '');
  });

  const drawer = (
    <Box>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          p: 2,
          borderBottom: `1px solid ${colors.border.primary}`,
        }}
      >
        <SecurityIcon sx={{ mr: 1, color: colors.primary.main, fontSize: 28 }} />
        <Typography variant="h6" sx={{ fontWeight: 600, color: colors.primary.main }}>
          CyberSec Suite
        </Typography>
      </Box>
      <List sx={{ pt: 2 }}>
        {filteredNavItems.map((item) => (
          <ListItem
            key={item.id}
            button={true} // Explicitly set for MUI ListItem, not native <li>
            onClick={() => handleNavigate(item.path)}
            sx={{
              mx: 1,
              mb: 0.5,
              borderRadius: 1,
              backgroundColor: location.pathname === item.path ? 
                colors.primary.main + '20' : 'transparent',
              '&:hover': {
                backgroundColor: location.pathname === item.path ? 
                  colors.primary.main + '30' : colors.background.elevated,
              },
              transition: 'background-color 0.2s ease-in-out',
            }}
          >
            <ListItemIcon
              sx={{
                color: location.pathname === item.path ? 
                  colors.primary.main : colors.text.secondary,
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
                  colors.primary.main : colors.text.primary,
              }}
            />
          </ListItem>
        ))}
      </List>
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
          boxShadow: `0 2px 8px ${colors.background.default}40`,
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { md: 'none' } }}
          >
            <MenuIcon />
          </IconButton>
          <Typography
            variant="h6"
            sx={{
              flexGrow: 1,
              fontWeight: 600,
              color: colors.text.primary,
            }}
          >
            {filteredNavItems.find(item => item.path === location.pathname)?.label || 'Dashboard'}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Tooltip title="Notifications">
              <IconButton color="inherit">
                <Badge badgeContent={3} color="error">
                  <NotificationsIcon />
                </Badge>
              </IconButton>
            </Tooltip>
            <Tooltip title="Profile">
              <IconButton onClick={handleProfileMenuOpen}>
                <Avatar
                  sx={{
                    width: 32,
                    height: 32,
                    backgroundColor: colors.primary.main,
                    fontSize: '0.875rem',
                  }}
                >
                  {user?.username?.charAt(0).toUpperCase()}
                </Avatar>
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