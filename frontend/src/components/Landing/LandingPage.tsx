import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

const features = [
  {
    title: 'Cybersecurity Education',
    description: 'Interactive courses, quizzes, and certification to boost your skills.',
    icon: '🎓',
  },
  {
    title: 'Automated Scanning Tools',
    description: 'Nmap, Vulnerability, Malware, OSINT, and more — all in one place.',
    icon: '🛡️',
  },
  {
    title: 'Admin Panel',
    description: 'Manage users, review documents, and control platform content.',
    icon: '🛠️',
  },
  {
    title: 'Real-Time Progress',
    description: 'Track your learning and job results with instant feedback.',
    icon: '📈',
  },
];

const testimonials = [
  {
    name: 'Alex (Analyst)',
    text: 'The education modules and live tools helped me land my first cybersecurity job! Highly recommended.',
    avatar: '🧑‍💻',
  },
  {
    name: 'Morgan (Admin)',
    text: 'Managing users and reviewing documents is a breeze. The certificate system is a game changer.',
    avatar: '👩‍💼',
  },
  {
    name: 'Taylor (Student)',
    text: 'The quizzes and instant feedback made learning fun and effective. Love the UI!',
    avatar: '🧑‍🎓',
  },
];

const LandingPage: React.FC = () => {
  const { isAuthenticated, user } = useAuth();

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-blue-50 to-blue-200 relative overflow-x-hidden">
      {/* Animated SVG Wave Background */}
      <div className="absolute inset-0 -z-10">
        <svg viewBox="0 0 1440 320" className="w-full h-64 md:h-96">
          <path fill="#2563eb" fillOpacity="0.2" d="M0,160L60,170.7C120,181,240,203,360,197.3C480,192,600,160,720,133.3C840,107,960,85,1080,101.3C1200,117,1320,171,1380,197.3L1440,224L1440,0L1380,0C1320,0,1200,0,1080,0C960,0,840,0,720,0C600,0,480,0,360,0C240,0,120,0,60,0L0,0Z"></path>
        </svg>
      </div>

      {/* Navigation Bar */}
      <nav className="flex justify-between items-center px-6 py-4 bg-white/80 shadow-md sticky top-0 z-20">
        <div className="flex items-center space-x-4">
          <span className="text-2xl font-extrabold text-blue-700 tracking-tight">CyberSec Suite</span>
        </div>
        <div className="flex items-center space-x-4">
          <Link to="/" className="hover:text-blue-600 font-medium">Home</Link>
          <Link to="/education" className="hover:text-blue-600 font-medium">Education</Link>
          <Link to="/education/documents" className="hover:text-blue-600 font-medium">Documents</Link>
          {user?.role === 'admin' && (
            <Link to="/admin/education" className="hover:text-blue-600 font-medium">Admin</Link>
          )}
          {isAuthenticated ? (
            <Link to="/dashboard" className="ml-2 px-4 py-2 bg-blue-600 text-white rounded-lg font-semibold shadow hover:bg-blue-700 transition">Go to Dashboard</Link>
          ) : (
            <>
              <Link to="/login" className="px-4 py-2 bg-white text-blue-700 border border-blue-600 rounded-lg font-semibold shadow hover:bg-blue-50 transition">Login</Link>
              <Link to="/register" className="px-4 py-2 bg-blue-600 text-white rounded-lg font-semibold shadow hover:bg-blue-700 transition">Get Started</Link>
            </>
          )}
        </div>
      </nav>

      {/* Hero Section */}
      <header className="flex-1 flex flex-col justify-center items-center text-center py-20 px-4 animate-fade-in">
        <h1 className="text-4xl md:text-6xl font-extrabold mb-4 text-blue-900 drop-shadow-lg animate-hero-slide">CyberSec Automation Suite</h1>
        <p className="text-lg md:text-2xl text-blue-700 mb-8 max-w-2xl mx-auto animate-fade-in-delay">Empowering analysts and admins with cutting-edge cybersecurity tools, education, and automation — all in one platform.</p>
        <div className="flex flex-col md:flex-row gap-4 justify-center animate-fade-in-delay2">
          {!isAuthenticated && <Link to="/register" className="px-8 py-3 bg-blue-600 text-white rounded-lg font-semibold shadow hover:bg-blue-700 transition">Get Started</Link>}
          {!isAuthenticated && <Link to="/login" className="px-8 py-3 bg-white text-blue-700 border border-blue-600 rounded-lg font-semibold shadow hover:bg-blue-50 transition">Login</Link>}
          {isAuthenticated && <Link to="/dashboard" className="px-8 py-3 bg-blue-600 text-white rounded-lg font-semibold shadow hover:bg-blue-700 transition">Go to Dashboard</Link>}
        </div>
      </header>

      {/* Features Section */}
      <section className="py-16 bg-white">
        <div className="max-w-5xl mx-auto px-4">
          <h2 className="text-2xl md:text-3xl font-bold text-center mb-10 text-blue-900">Platform Features</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {features.map((f, i) => (
              <div key={i} className="bg-blue-50 rounded-xl shadow p-8 flex items-start space-x-4 hover:shadow-lg transition transform hover:-translate-y-1 animate-fade-in" style={{ animationDelay: `${0.2 + i * 0.1}s` }}>
                <span className="text-4xl animate-bounce-slow">{f.icon}</span>
                <div>
                  <h3 className="text-xl font-semibold text-blue-800 mb-1">{f.title}</h3>
                  <p className="text-blue-700">{f.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section className="py-16 bg-gradient-to-r from-blue-100 to-blue-200">
        <div className="max-w-4xl mx-auto px-4 text-center">
          <h2 className="text-2xl md:text-3xl font-bold text-blue-900 mb-8">What Our Users Say</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {testimonials.map((t, i) => (
              <div key={i} className="bg-white rounded-xl shadow p-6 flex flex-col items-center animate-fade-in" style={{ animationDelay: `${0.3 + i * 0.1}s` }}>
                <span className="text-5xl mb-2 animate-bounce-slow">{t.avatar}</span>
                <p className="text-blue-800 mb-2">“{t.text}”</p>
                <span className="text-blue-600 font-semibold">{t.name}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section className="py-16 bg-white">
        <div className="max-w-4xl mx-auto px-4 text-center">
          <h2 className="text-2xl md:text-3xl font-bold text-blue-900 mb-8">How It Works</h2>
          <div className="flex flex-col md:flex-row justify-center items-center gap-8">
            <div className="flex flex-col items-center">
              <span className="text-3xl mb-2">📝</span>
              <span className="font-semibold text-blue-800">Register & Login</span>
            </div>
            <span className="text-2xl text-blue-400 hidden md:inline">→</span>
            <div className="flex flex-col items-center">
              <span className="text-3xl mb-2">🎓</span>
              <span className="font-semibold text-blue-800">Learn & Practice</span>
            </div>
            <span className="text-2xl text-blue-400 hidden md:inline">→</span>
            <div className="flex flex-col items-center">
              <span className="text-3xl mb-2">🚀</span>
              <span className="font-semibold text-blue-800">Scan & Analyze</span>
            </div>
            <span className="text-2xl text-blue-400 hidden md:inline">→</span>
            <div className="flex flex-col items-center">
              <span className="text-3xl mb-2">🏆</span>
              <span className="font-semibold text-blue-800">Get Certified</span>
            </div>
          </div>
        </div>
      </section>

      {/* Call to Action */}
      <section className="py-12 bg-gradient-to-r from-blue-600 to-blue-400 text-center">
        <h2 className="text-2xl md:text-3xl font-bold text-white mb-4">Ready to get started?</h2>
        {!isAuthenticated && <Link to="/register" className="px-8 py-3 bg-white text-blue-700 rounded-lg font-semibold shadow hover:bg-blue-50 transition">Create Your Account</Link>}
        {isAuthenticated && <Link to="/dashboard" className="px-8 py-3 bg-white text-blue-700 rounded-lg font-semibold shadow hover:bg-blue-50 transition">Go to Dashboard</Link>}
      </section>

      {/* Footer */}
      <footer className="py-6 bg-blue-900 text-blue-100 text-center text-sm mt-auto">
        &copy; {new Date().getFullYear()} CyberSec Automation Suite. All rights reserved.
      </footer>

      {/* Animations (Tailwind custom classes) */}
      <style>{`
        .animate-fade-in { animation: fadeIn 1s ease both; }
        .animate-fade-in-delay { animation: fadeIn 1.5s 0.3s ease both; }
        .animate-fade-in-delay2 { animation: fadeIn 2s 0.6s ease both; }
        .animate-hero-slide { animation: heroSlide 1.2s cubic-bezier(.4,2,.6,1) both; }
        .animate-bounce-slow { animation: bounce 2.5s infinite alternate; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(30px);} to { opacity: 1; transform: none; } }
        @keyframes heroSlide { from { opacity: 0; transform: translateY(-40px);} to { opacity: 1; transform: none; } }
      `}</style>
    </div>
  );
};

export default LandingPage; 