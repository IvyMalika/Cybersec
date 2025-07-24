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

  useEffect(() => {
    const fetchCourse = async () => {
      setLoading(true);
      const res = await fetch(`/api/education/courses/${course_id}`);
      const data = await res.json();
      setCourse(data.course);
      const progressRes = await fetch(`/api/education/courses/${course_id}/progress`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      const progressData = await progressRes.json();
      setProgress(progressData.progress);
      setLoading(false);
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
      <h1 className="text-2xl font-bold mb-4">{course.title}</h1>
      <p className="text-gray-600 mb-4">{course.description}</p>
      {course.video_url && (
        <div className="mb-6">
          <video
            className="w-full rounded shadow-lg"
            controls
            poster="/static/education-video-poster.png"
          >
            <source src={course.video_url} type="video/mp4" />
            Your browser does not support the video tag.
          </video>
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