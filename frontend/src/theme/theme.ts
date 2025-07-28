import { createTheme, ThemeOptions } from '@mui/material/styles';
import { alpha } from '@mui/material/styles';

// VertexGuard-inspired color palette
const colors = {
  primary: {
    main: '#8B5CF6', // Purple from the image
    light: '#A78BFA',
    dark: '#7C3AED',
    contrastText: '#FFFFFF',
  },
  secondary: {
    main: '#EC4899', // Fuchsia/Pink from the image
    light: '#F472B6',
    dark: '#DB2777',
    contrastText: '#FFFFFF',
  },
  background: {
    default: '#1A1A2E', // Dark charcoal from the image
    paper: '#2C2C4A', // Slightly lighter card background
    elevated: '#3A3A5A',
  },
  text: {
    primary: '#FFFFFF',
    secondary: '#B3B3B3',
    disabled: '#666666',
  },
  severity: {
    critical: '#FF4444',
    high: '#FF6B35', // Orange from the image
    medium: '#FFDD59',
    low: '#4CAF50',
    info: '#2196F3',
  },
  status: {
    success: '#4CAF50',
    warning: '#FF9800',
    error: '#F44336',
    info: '#2196F3',
  },
  accent: {
    purple: '#8B5CF6',
    fuchsia: '#EC4899',
    orange: '#FF6B35',
    blue: '#3B82F6',
    teal: '#14B8A6',
  },
  border: {
    primary: '#333333',
    secondary: '#444444',
    accent: '#555555',
  },
};

const themeOptions: ThemeOptions = {
  palette: {
    mode: 'dark',
    primary: colors.primary,
    secondary: colors.secondary,
    background: {
      default: colors.background.default,
      paper: colors.background.paper,
    },
    text: colors.text,
    error: {
      main: colors.severity.critical,
    },
    warning: {
      main: colors.status.warning,
    },
    info: {
      main: colors.status.info,
    },
    success: {
      main: colors.status.success,
    },
    divider: colors.border.primary,
  },
  typography: {
    fontFamily: '"Inter", "Poppins", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontSize: '2.5rem',
      fontWeight: 700,
      lineHeight: 1.2,
      color: colors.text.primary,
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 600,
      lineHeight: 1.3,
      color: colors.text.primary,
    },
    h3: {
      fontSize: '1.5rem',
      fontWeight: 600,
      lineHeight: 1.4,
      color: colors.text.primary,
    },
    h4: {
      fontSize: '1.25rem',
      fontWeight: 600,
      lineHeight: 1.4,
      color: colors.text.primary,
    },
    h5: {
      fontSize: '1.125rem',
      fontWeight: 600,
      lineHeight: 1.5,
      color: colors.text.primary,
    },
    h6: {
      fontSize: '1rem',
      fontWeight: 600,
      lineHeight: 1.5,
      color: colors.text.primary,
    },
    body1: {
      fontSize: '0.875rem',
      lineHeight: 1.6,
      color: colors.text.primary,
    },
    body2: {
      fontSize: '0.75rem',
      lineHeight: 1.6,
      color: colors.text.secondary,
    },
    code: {
      fontFamily: '"Roboto Mono", "JetBrains Mono", "Fira Code", monospace',
      fontSize: '0.875rem',
      backgroundColor: alpha(colors.background.elevated, 0.6),
      padding: '2px 4px',
      borderRadius: '4px',
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          scrollbarColor: `${colors.border.secondary} ${colors.background.default}`,
          '&::-webkit-scrollbar': {
            width: '8px',
          },
          '&::-webkit-scrollbar-track': {
            backgroundColor: colors.background.default,
          },
          '&::-webkit-scrollbar-thumb': {
            backgroundColor: colors.border.secondary,
            borderRadius: '4px',
            '&:hover': {
              backgroundColor: colors.border.accent,
            },
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: colors.background.paper,
          border: `1px solid ${colors.border.primary}`,
          borderRadius: '12px',
          boxShadow: `0 4px 20px ${alpha(colors.background.default, 0.8)}`,
          transition: 'all 0.3s ease-in-out',
          '&:hover': {
            boxShadow: `0 8px 32px ${alpha(colors.primary.main, 0.15)}`,
            borderColor: colors.border.secondary,
            transform: 'translateY(-2px)',
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundColor: colors.background.paper,
          backgroundImage: 'none',
        },
        elevation1: {
          boxShadow: `0 2px 8px ${alpha(colors.background.default, 0.6)}`,
        },
        elevation2: {
          boxShadow: `0 4px 16px ${alpha(colors.background.default, 0.8)}`,
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
          borderRadius: '8px',
          padding: '10px 20px',
          transition: 'all 0.3s ease-in-out',
          fontSize: '0.875rem',
        },
        contained: {
          backgroundColor: colors.primary.main,
          boxShadow: `0 2px 8px ${alpha(colors.primary.main, 0.3)}`,
          '&:hover': {
            backgroundColor: colors.primary.dark,
            boxShadow: `0 4px 16px ${alpha(colors.primary.main, 0.4)}`,
            transform: 'translateY(-1px)',
          },
        },
        outlined: {
          borderColor: colors.border.secondary,
          color: colors.text.primary,
          '&:hover': {
            borderColor: colors.primary.main,
            backgroundColor: alpha(colors.primary.main, 0.05),
          },
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            borderRadius: '8px',
            '& fieldset': {
              borderColor: colors.border.secondary,
            },
            '&:hover fieldset': {
              borderColor: colors.border.accent,
            },
            '&.Mui-focused fieldset': {
              borderColor: colors.primary.main,
            },
          },
        },
      },
    },
    MuiDataGrid: {
      styleOverrides: {
        root: {
          border: `1px solid ${colors.border.primary}`,
          backgroundColor: colors.background.paper,
          borderRadius: '8px',
          '& .MuiDataGrid-cell': {
            borderColor: colors.border.primary,
          },
          '& .MuiDataGrid-columnHeaders': {
            backgroundColor: colors.background.elevated,
            borderBottom: `1px solid ${colors.border.secondary}`,
          },
          '& .MuiDataGrid-row': {
            '&:hover': {
              backgroundColor: alpha(colors.primary.main, 0.05),
            },
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: '16px',
          fontWeight: 600,
          fontSize: '0.75rem',
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: '8px',
          '& .MuiAlert-icon': {
            marginRight: '12px',
          },
        },
      },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: {
          borderRadius: '4px',
          backgroundColor: colors.background.elevated,
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        root: {
          '& .MuiTabs-indicator': {
            backgroundColor: colors.primary.main,
          },
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: colors.background.paper,
          borderBottom: `1px solid ${colors.border.primary}`,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: colors.background.paper,
          borderRight: `1px solid ${colors.border.primary}`,
        },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: '8px',
          margin: '4px 8px',
          '&.Mui-selected': {
            backgroundColor: colors.primary.main,
            '&:hover': {
              backgroundColor: colors.primary.dark,
            },
          },
          '&:hover': {
            backgroundColor: alpha(colors.primary.main, 0.1),
          },
        },
      },
    },
  },
};

export const theme = createTheme(themeOptions);

export { colors };

export default theme;