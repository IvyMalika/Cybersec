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

  useEffect(() => {
    const fetchCourses = async () => {
      setLoading(true);
      const res = await fetch('/api/education/courses');
      const data = await res.json();
      if (data.courses) {
        // For each course, fetch progress
        const coursesWithProgress = await Promise.all(
          data.courses.map(async (course: Course) => {
            const progressRes = await fetch(`/api/education/courses/${course.course_id}/progress`, {
              headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
            });
            const progressData = await progressRes.json();
            return { ...course, ...progressData.progress };
          })
        );
        setCourses(coursesWithProgress);
      }
      setLoading(false);
    };
    fetchCourses();
  }, []);

  return (
    <div className="max-w-4xl mx-auto py-8 px-4">
      <h1 className="text-3xl font-bold mb-6 text-center">Cybersecurity Education</h1>
      {loading ? (
        <div className="flex justify-center items-center h-32">
          <span className="loading loading-spinner loading-lg"></span>
        </div>
      ) : (
        <div className="space-y-6">
          {courses.map(course => (
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
          ))}
        </div>
      )}
    </div>
  );
};

export default EducationDashboard; 