/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // VertexGuard Color Palette
        vertex: {
          primary: '#8B5CF6',
          secondary: '#EC4899',
          background: {
            default: '#1A1A2E',
            paper: '#2C2C4A',
            elevated: '#3A3A5A',
          },
          text: {
            primary: '#FFFFFF',
            secondary: '#B3B3B3',
            disabled: '#666666',
          },
          severity: {
            critical: '#FF4444',
            high: '#FF6B35',
            medium: '#FFDD59',
            low: '#4CAF50',
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
        },
      },
      fontFamily: {
        'inter': ['Inter', 'sans-serif'],
        'poppins': ['Poppins', 'sans-serif'],
      },
      animation: {
        'fade-in': 'fadeIn 0.6s ease-out',
        'slide-in': 'slideIn 0.6s ease-out',
        'bounce-slow': 'bounce 2s infinite',
        'pulse-slow': 'pulse 3s infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideIn: {
          '0%': { opacity: '0', transform: 'translateX(-20px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
      },
      boxShadow: {
        'vertex': '0 8px 32px rgba(139, 92, 246, 0.2)',
        'vertex-lg': '0 16px 64px rgba(139, 92, 246, 0.3)',
      },
      backdropBlur: {
        'xs': '2px',
      },
    },
  },
  plugins: [],
};
