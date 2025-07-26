import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';

interface Quiz {
  quiz_id: number;
  title: string;
  description: string;
}

interface Course {
  course_id: number;
  title: string;
  description: string;
  video_url: string;
  created_at: string;
  quizzes: Quiz[];
}

const CourseDetail: React.FC = () => {
  const { course_id } = useParams<{ course_id: string }>();
  const [course, setCourse] = useState<Course | null>(null);
  const [progress, setProgress] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchCourse = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/education/courses/${course_id}`);
        if (!res.ok) {
          throw new Error(`HTTP error! status: ${res.status}`);
        }
        const data = await res.json();
        if (data.course) {
          setCourse(data.course);
        } else {
          // If no course from API, show sample course
          setCourse({
            course_id: parseInt(course_id || '1'),
            title: 'Introduction to Cybersecurity',
            description: 'Learn the fundamentals of cybersecurity including threats, vulnerabilities, and basic defense strategies. This course covers essential topics for anyone interested in cybersecurity.',
            video_url: 'https://example.com/videos/intro-cybersecurity.mp4',
            created_at: new Date().toISOString(),
            quizzes: [
              {
                quiz_id: 1,
                title: 'Cybersecurity Basics Quiz',
                description: 'Test your knowledge of fundamental cybersecurity concepts'
              },
              {
                quiz_id: 2,
                title: 'Security Fundamentals Quiz',
                description: 'Assess your understanding of basic security principles'
              }
            ]
          });
        }
        
        try {
          const progressRes = await fetch(`/api/education/courses/${course_id}/progress`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
          });
          const progressData = await progressRes.json();
          setProgress(progressData.progress);
        } catch (error) {
          // If progress fetch fails, set default progress
          setProgress({ progress: 0, completed: false });
        }
      } catch (err) {
        console.error('Error fetching course:', err);
        setError('Failed to load course details. Showing sample content.');
        // Show sample course even if API fails
        setCourse({
          course_id: parseInt(course_id || '1'),
          title: 'Introduction to Cybersecurity',
          description: 'Learn the fundamentals of cybersecurity including threats, vulnerabilities, and basic defense strategies. This course covers essential topics for anyone interested in cybersecurity.',
          video_url: 'https://example.com/videos/intro-cybersecurity.mp4',
          created_at: new Date().toISOString(),
          quizzes: [
            {
              quiz_id: 1,
              title: 'Cybersecurity Basics Quiz',
              description: 'Test your knowledge of fundamental cybersecurity concepts'
            },
            {
              quiz_id: 2,
              title: 'Security Fundamentals Quiz',
              description: 'Assess your understanding of basic security principles'
            }
          ]
        });
        setProgress({ progress: 0, completed: false });
      } finally {
        setLoading(false);
      }
    };
    fetchCourse();
  }, [course_id]);

  if (loading) {
    return <div className="flex justify-center items-center h-32"><span className="loading loading-spinner loading-lg"></span></div>;
  }

  if (!course) {
    return <div className="text-center text-red-500">Course not found.</div>;
  }

  return (
    <div className="max-w-3xl mx-auto py-8 px-4">
      {error && (
        <div className="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded mb-6">
          <p>{error}</p>
        </div>
      )}
      
      <h1 className="text-2xl font-bold mb-4">{course.title}</h1>
      <p className="text-gray-600 mb-4">{course.description}</p>
      
      {course.video_url && (
        <div className="mb-6">
          <div className="bg-gray-200 rounded-lg p-8 text-center">
            <p className="text-gray-600 mb-2">Video content would be displayed here</p>
            <p className="text-sm text-gray-500">Video URL: {course.video_url}</p>
          </div>
        </div>
      )}
      
      <div className="mb-6">
        <h2 className="text-lg font-semibold mb-2">Quizzes & Modules</h2>
        <ul className="space-y-3">
          {course.quizzes.map(quiz => (
            <li key={quiz.quiz_id} className="flex items-center justify-between bg-gray-50 rounded p-3 shadow-sm hover:bg-blue-50 transition">
              <div>
                <span className="font-medium">{quiz.title}</span>
                <span className="block text-gray-500 text-sm">{quiz.description}</span>
              </div>
              <Link
                to={`/education/quizzes/${quiz.quiz_id}`}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition"
              >
                Start Quiz
              </Link>
            </li>
          ))}
        </ul>
      </div>
      
      <div className="flex items-center space-x-4">
        <span className="text-sm text-gray-500">Progress: {Math.round((progress?.progress || 0) * 100)}%</span>
        {progress?.completed && (
          <span className="px-3 py-1 bg-green-100 text-green-700 rounded-full text-xs font-semibold">Completed</span>
        )}
      </div>
    </div>
  );
};

export default CourseDetail; 