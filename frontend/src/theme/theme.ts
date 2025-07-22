import { createTheme, ThemeOptions } from '@mui/material/styles';
import { alpha } from '@mui/material/styles';

// Cybersecurity color palette
const colors = {
  primary: {
    main: '#00D4FF',
    light: '#33DCFF',
    dark: '#0094CC',
    contrastText: '#000000',
  },
  secondary: {
    main: '#FF6B35',
    light: '#FF8F5C',
    dark: '#CC5527',
    contrastText: '#FFFFFF',
  },
  background: {
    default: '#0A0A0A',
    paper: '#1A1A1A',
    elevated: '#2A2A2A',
  },
  text: {
    primary: '#FFFFFF',
    secondary: '#B3B3B3',
    disabled: '#666666',
  },
  severity: {
    critical: '#FF4444',
    high: '#FFBB33',
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
  terminal: {
    background: '#000000',
    text: '#00FF00',
    prompt: '#00D4FF',
    error: '#FF4444',
    warning: '#FFBB33',
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
    fontFamily: '"Roboto Mono", "JetBrains Mono", "Fira Code", monospace',
    h1: {
      fontSize: '2.5rem',
      fontWeight: 600,
      lineHeight: 1.2,
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 600,
      lineHeight: 1.3,
    },
    h3: {
      fontSize: '1.5rem',
      fontWeight: 600,
      lineHeight: 1.4,
    },
    h4: {
      fontSize: '1.25rem',
      fontWeight: 600,
      lineHeight: 1.4,
    },
    h5: {
      fontSize: '1.125rem',
      fontWeight: 600,
      lineHeight: 1.5,
    },
    h6: {
      fontSize: '1rem',
      fontWeight: 600,
      lineHeight: 1.5,
    },
    body1: {
      fontSize: '0.875rem',
      lineHeight: 1.6,
    },
    body2: {
      fontSize: '0.75rem',
      lineHeight: 1.6,
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
          borderRadius: '8px',
          boxShadow: `0 4px 20px ${alpha(colors.background.default, 0.8)}`,
          transition: 'box-shadow 0.2s ease-in-out, border-color 0.2s ease-in-out',
          '&:hover': {
            boxShadow: `0 8px 32px ${alpha(colors.primary.main, 0.1)}`,
            borderColor: colors.border.secondary,
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
          borderRadius: '6px',
          padding: '8px 16px',
          transition: 'all 0.2s ease-in-out',
        },
        contained: {
          boxShadow: `0 2px 8px ${alpha(colors.primary.main, 0.3)}`,
          '&:hover': {
            boxShadow: `0 4px 16px ${alpha(colors.primary.main, 0.4)}`,
            transform: 'translateY(-1px)',
          },
        },
        outlined: {
          borderColor: colors.border.secondary,
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
  },
};

export const theme = createTheme(themeOptions);

export { colors };

export default theme;