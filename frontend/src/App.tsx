import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { ThemeProvider, CssBaseline } from '@mui/material';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { theme } from './theme/theme';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import AppLayout from './components/Layout/AppLayout';
import LoginForm from './components/Auth/LoginForm';
import RegisterForm from './components/Auth/RegisterForm';
import Dashboard from './components/Dashboard/Dashboard';
import NmapScanner from './components/Tools/NmapScanner';
import VulnerabilityScanner from './components/Tools/VulnerabilityScanner';
import MalwareAnalyzer from './components/Tools/MalwareAnalyzer';
import NetworkMonitor from './components/Tools/NetworkMonitor';
import OSINTGatherer from './components/Tools/OSINTGatherer';
import PasswordCracker from './components/Tools/PasswordCracker';
import ThreatIntelligence from './components/Tools/ThreatIntelligence';
import JobsManager from './components/Jobs/JobsManager';
import ReportsManager from './components/Reports/ReportsManager';
import AdminPanel from './components/Admin/AdminPanel';
import WiFiTool from './components/Tools/WiFiTool';
import SQLInjectionScanner from './components/Tools/SQLInjectionScanner';
import ZphisherSocialEngineering from './components/Tools/ZphisherSocialEngineering';
import EducationDashboard from './components/Education/EducationDashboard';
import CourseDetail from './components/Education/CourseDetail';
import QuizInterface from './components/Education/QuizInterface';
import DocumentUpload from './components/Education/DocumentUpload';
import CertificatePreview from './components/Education/CertificatePreview';
import AdminEducationPanel from './components/Education/Admin/AdminEducationPanel';
import LandingPage from './components/Landing/LandingPage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh' 
      }}>
        Loading...
      </div>
    );
  }

  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
};

const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isAdmin, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh' 
      }}>
        Loading...
      </div>
    );
  }

  return isAuthenticated && isAdmin ? <>{children}</> : <Navigate to="/dashboard" />;
};

const PublicRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh' 
      }}>
        Loading...
      </div>
    );
  }

  return !isAuthenticated ? <>{children}</> : <Navigate to="/dashboard" />;
};

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <Router>
            <Routes>
              {/* Public routes */}
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={
                <PublicRoute>
                  <LoginForm />
                </PublicRoute>
              } />
              <Route path="/register" element={
                <PublicRoute>
                  <RegisterForm />
                </PublicRoute>
              } />

              {/* Protected routes with AppLayout */}
              <Route element={
                <ProtectedRoute>
                  <AppLayout>
                    <Outlet />
                  </AppLayout>
                </ProtectedRoute>
              }>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/tools/nmap" element={<NmapScanner />} />
                <Route path="/tools/vulnerability-scanner" element={<VulnerabilityScanner />} />
                <Route path="/tools/malware-analyzer" element={<MalwareAnalyzer />} />
                <Route path="/tools/network-monitor" element={<NetworkMonitor />} />
                <Route path="/tools/osint-gatherer" element={<OSINTGatherer />} />
                <Route path="/tools/password-cracker" element={<PasswordCracker />} />
                <Route path="/tools/threat-intelligence" element={<ThreatIntelligence />} />
                <Route path="/tools/wifi" element={<WiFiTool />} />
                <Route path="/tools/sql-injection" element={<SQLInjectionScanner />} />
                <Route path="/tools/zphisher" element={<ZphisherSocialEngineering />} />
                <Route path="/jobs" element={<JobsManager />} />
                <Route path="/reports" element={<ReportsManager />} />
                
                {/* Education routes */}
                <Route path="/education" element={<EducationDashboard />} />
                <Route path="/education/course/:id" element={<CourseDetail />} />
                <Route path="/education/quiz/:id" element={<QuizInterface />} />
                <Route path="/education/upload" element={<DocumentUpload />} />
                <Route path="/education/certificate" element={<CertificatePreview />} />
              </Route>

              {/* Admin-only routes */}
              <Route path="/admin" element={
                <AdminRoute>
                  <AdminPanel />
                </AdminRoute>
              } />
              <Route path="/admin/education" element={
                <AdminRoute>
                  <AdminEducationPanel />
                </AdminRoute>
              } />

              {/* Fallback route */}
              <Route path="*" element={<Navigate to="/" />} />
            </Routes>
          </Router>
        </AuthProvider>
        <ReactQueryDevtools initialIsOpen={false} />
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;