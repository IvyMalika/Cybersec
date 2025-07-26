import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

interface Course {
  course_id: number;
  title: string;
  description: string;
  video_url: string;
  created_at: string;
  progress?: number;
  completed?: boolean;
  certificate_url?: string;
}

const EducationDashboard: React.FC = () => {
  const [courses, setCourses] = useState<Course[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchCourses = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch('/api/education/courses');
        if (!res.ok) {
          throw new Error(`HTTP error! status: ${res.status}`);
        }
        const data = await res.json();
        if (data.courses && data.courses.length > 0) {
          // For each course, fetch progress
          const coursesWithProgress = await Promise.all(
            data.courses.map(async (course: Course) => {
              try {
                const progressRes = await fetch(`/api/education/courses/${course.course_id}/progress`, {
                  headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                });
                const progressData = await progressRes.json();
                return { ...course, ...progressData.progress };
              } catch (error) {
                // If progress fetch fails, return course without progress
                return { ...course, progress: 0, completed: false };
              }
            })
          );
          setCourses(coursesWithProgress);
        } else {
          // If no courses from API, show sample courses for demonstration
          setCourses([
            {
              course_id: 1,
              title: 'Introduction to Cybersecurity',
              description: 'Learn the fundamentals of cybersecurity including threats, vulnerabilities, and basic defense strategies.',
              video_url: 'https://example.com/videos/intro-cybersecurity.mp4',
              created_at: new Date().toISOString(),
              progress: 0,
              completed: false
            },
            {
              course_id: 2,
              title: 'Network Security Fundamentals',
              description: 'Understand network protocols, common attacks, and how to secure network infrastructure.',
              video_url: 'https://example.com/videos/network-security.mp4',
              created_at: new Date().toISOString(),
              progress: 0.3,
              completed: false
            },
            {
              course_id: 3,
              title: 'Web Application Security',
              description: 'Learn about OWASP Top 10 vulnerabilities, SQL injection, XSS, and secure coding practices.',
              video_url: 'https://example.com/videos/web-security.mp4',
              created_at: new Date().toISOString(),
              progress: 0.8,
              completed: false
            },
            {
              course_id: 4,
              title: 'Ethical Hacking Basics',
              description: 'Learn penetration testing methodologies, tools, and techniques for security assessment.',
              video_url: 'https://example.com/videos/ethical-hacking.mp4',
              created_at: new Date().toISOString(),
              progress: 1.0,
              completed: true,
              certificate_url: 'https://example.com/certificates/ethical-hacking.pdf'
            },
            {
              course_id: 5,
              title: 'Incident Response & Forensics',
              description: 'Learn how to respond to security incidents and conduct digital forensics investigations.',
              video_url: 'https://example.com/videos/incident-response.mp4',
              created_at: new Date().toISOString(),
              progress: 0,
              completed: false
            }
          ]);
        }
      } catch (err) {
        console.error('Error fetching courses:', err);
        setError('Failed to load courses. Showing sample content.');
        // Show sample courses even if API fails
        setCourses([
          {
            course_id: 1,
            title: 'Introduction to Cybersecurity',
            description: 'Learn the fundamentals of cybersecurity including threats, vulnerabilities, and basic defense strategies.',
            video_url: 'https://example.com/videos/intro-cybersecurity.mp4',
            created_at: new Date().toISOString(),
            progress: 0,
            completed: false
          },
          {
            course_id: 2,
            title: 'Network Security Fundamentals',
            description: 'Understand network protocols, common attacks, and how to secure network infrastructure.',
            video_url: 'https://example.com/videos/network-security.mp4',
            created_at: new Date().toISOString(),
            progress: 0.3,
            completed: false
          },
          {
            course_id: 3,
            title: 'Web Application Security',
            description: 'Learn about OWASP Top 10 vulnerabilities, SQL injection, XSS, and secure coding practices.',
            video_url: 'https://example.com/videos/web-security.mp4',
            created_at: new Date().toISOString(),
            progress: 0.8,
            completed: false
          },
          {
            course_id: 4,
            title: 'Ethical Hacking Basics',
            description: 'Learn penetration testing methodologies, tools, and techniques for security assessment.',
            video_url: 'https://example.com/videos/ethical-hacking.mp4',
            created_at: new Date().toISOString(),
            progress: 1.0,
            completed: true,
            certificate_url: 'https://example.com/certificates/ethical-hacking.pdf'
          },
          {
            course_id: 5,
            title: 'Incident Response & Forensics',
            description: 'Learn how to respond to security incidents and conduct digital forensics investigations.',
            video_url: 'https://example.com/videos/incident-response.mp4',
            created_at: new Date().toISOString(),
            progress: 0,
            completed: false
          }
        ]);
      } finally {
        setLoading(false);
      }
    };
    fetchCourses();
  }, []);

  return (
    <div className="max-w-4xl mx-auto py-8 px-4">
      <h1 className="text-3xl font-bold mb-6 text-center">Cybersecurity Education</h1>
      
      {error && (
        <div className="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded mb-6">
          <p>{error}</p>
        </div>
      )}
      
      {loading ? (
        <div className="flex justify-center items-center h-32">
          <span className="loading loading-spinner loading-lg"></span>
        </div>
      ) : (
        <div className="space-y-6">
          {courses.length === 0 ? (
            <div className="text-center py-12">
              <h3 className="text-xl font-semibold mb-2">No courses available</h3>
              <p className="text-gray-600">Check back later for new cybersecurity courses.</p>
            </div>
          ) : (
            courses.map(course => (
              <div key={course.course_id} className="bg-white rounded-lg shadow p-6 flex flex-col md:flex-row md:items-center md:justify-between">
                <div>
                  <h2 className="text-xl font-semibold mb-1">{course.title}</h2>
                  <p className="text-gray-600 mb-2">{course.description}</p>
                  <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
                    <div
                      className={`h-3 rounded-full ${course.completed ? 'bg-green-500' : 'bg-blue-500'}`}
                      style={{ width: `${Math.round((course.progress || 0) * 100)}%` }}
                    ></div>
                  </div>
                  <span className="text-sm text-gray-500">
                    {course.completed ? 'Completed' : `Progress: ${Math.round((course.progress || 0) * 100)}%`}
                  </span>
                </div>
                <div className="mt-4 md:mt-0 flex flex-col items-end space-y-2">
                  <Link
                    to={`/education/courses/${course.course_id}`}
                    className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition"
                  >
                    {course.completed ? 'Review Course' : 'Continue Learning'}
                  </Link>
                  {course.completed && course.certificate_url && (
                    <a
                      href={course.certificate_url}
                      className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 transition"
                      download
                    >
                      Download Certificate
                    </a>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};

export default EducationDashboard; 