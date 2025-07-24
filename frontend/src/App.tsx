import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from 'react-router-dom';
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
  const { isAdmin } = useAuth();
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <Router>
            <div>
              {/* Navigation Bar */}
              <nav style={{ padding: 16, background: '#f8fafc', borderBottom: '1px solid #eee', marginBottom: 24 }}>
                <Link to="/" style={{ marginRight: 16 }}>Dashboard</Link>
                <Link to="/education" style={{ marginRight: 16 }}>Education</Link>
                <Link to="/education/documents" style={{ marginRight: 16 }}>Documents</Link>
                {isAdmin && (
                  <Link to="/admin/education" style={{ marginRight: 16, color: '#1976d2', fontWeight: 600 }}>Admin Education</Link>
                )}
                <Link to="/tools/osint">OSINT Gatherer</Link>
                <Link to="/tools/sql-injection" style={{ marginLeft: 16, fontWeight: 600, color: '#1976d2' }}>SQL Injection Scanner</Link>
                {/* Add other tool links here */}
              </nav>
              <Routes>
                <Route
                  path="/login"
                  element={
                    <PublicRoute>
                      <LoginForm />
                    </PublicRoute>
                  }
                />
                <Route
                  path="/register"
                  element={
                    <PublicRoute>
                      <RegisterForm />
                    </PublicRoute>
                  }
                />
                <Route
                  path="/dashboard"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <Dashboard />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/nmap"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <NmapScanner />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/vulnerability"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <VulnerabilityScanner />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/malware"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <MalwareAnalyzer />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/network-monitor"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <NetworkMonitor />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/osint"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <OSINTGatherer />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/password-crack"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <PasswordCracker />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/threat-intel"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <ThreatIntelligence />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/wifi"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <WiFiTool />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/sql-injection"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <SQLInjectionScanner />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/tools/social-engineering"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <ZphisherSocialEngineering />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/education"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <EducationDashboard />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/education/courses/:course_id"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <CourseDetail />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/education/quizzes/:quiz_id"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <QuizInterface />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/education/documents"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <DocumentUpload />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/education/certificate/:course_id"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <CertificatePreview />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/jobs"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <JobsManager />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/reports"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <ReportsManager />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/admin"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <AdminPanel />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/admin/education"
                  element={
                    <ProtectedRoute>
                      <AppLayout>
                        <AdminEducationPanel />
                      </AppLayout>
                    </ProtectedRoute>
                  }
                />
                <Route path="/" element={<Navigate to="/dashboard" />} />
              </Routes>
            </div>
          </Router>
        </AuthProvider>
        <ReactQueryDevtools initialIsOpen={false} />
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;