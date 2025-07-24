import React, { useEffect, useState } from 'react';
import { FaEdit, FaTrash } from 'react-icons/fa';

interface Course {
  course_id: number;
  title: string;
  description: string;
  video_url: string;
}

interface Quiz {
  quiz_id: number;
  title: string;
  description: string;
}

interface Document {
  document_id: number;
  user_id: number;
  document_type: string;
  file_url: string;
  status: string;
  reviewed_by: number | null;
  reviewed_at: string | null;
  uploaded_at: string;
}

const AdminEducationPanel: React.FC = () => {
  const [tab, setTab] = useState<'courses' | 'quizzes' | 'documents' | 'certificates'>('courses');
  const [courses, setCourses] = useState<Course[]>([]);
  const [quizzes, setQuizzes] = useState<Quiz[]>([]);
  const [documents, setDocuments] = useState<Document[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCourseModal, setShowCourseModal] = useState(false);
  const [newCourse, setNewCourse] = useState({ title: '', description: '', video_url: '' });
  const [creatingCourse, setCreatingCourse] = useState(false);
  const [showQuizModal, setShowQuizModal] = useState(false);
  const [newQuiz, setNewQuiz] = useState({ title: '', description: '', course_id: '' });
  const [creatingQuiz, setCreatingQuiz] = useState(false);
  const [selectedCourseId, setSelectedCourseId] = useState<string>('');

  const [showQuestionModal, setShowQuestionModal] = useState(false);
  const [newQuestion, setNewQuestion] = useState({ question_text: '', question_type: 'multiple_choice', quiz_id: '' });
  const [creatingQuestion, setCreatingQuestion] = useState(false);
  const [selectedQuizId, setSelectedQuizId] = useState<string>('');

  const [showOptionModal, setShowOptionModal] = useState(false);
  const [newOption, setNewOption] = useState({ option_text: '', is_correct: false, question_id: '' });
  const [creatingOption, setCreatingOption] = useState(false);
  const [selectedQuestionId, setSelectedQuestionId] = useState<string>('');

  const [showEditCourseModal, setShowEditCourseModal] = useState(false);
  const [editCourse, setEditCourse] = useState<Course | null>(null);
  const [deletingCourseId, setDeletingCourseId] = useState<number | null>(null);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const [showEditQuizModal, setShowEditQuizModal] = useState(false);
  const [editQuiz, setEditQuiz] = useState<Quiz | null>(null);
  const [deletingQuizId, setDeletingQuizId] = useState<number | null>(null);

  const [questionsByQuiz, setQuestionsByQuiz] = useState<{ [quizId: number]: any[] }>({});
  const [showQuestionsForQuiz, setShowQuestionsForQuiz] = useState<{ [quizId: number]: boolean }>({});
  const [showEditQuestionModal, setShowEditQuestionModal] = useState(false);
  const [editQuestion, setEditQuestion] = useState<any>(null);
  const [deletingQuestionId, setDeletingQuestionId] = useState<number | null>(null);
  const [showEditOptionModal, setShowEditOptionModal] = useState(false);
  const [editOption, setEditOption] = useState<any>(null);
  const [deletingOptionId, setDeletingOptionId] = useState<number | null>(null);

  // Fetch courses
  const fetchCourses = async () => {
    setLoading(true);
    const res = await fetch('/api/education/courses');
    const data = await res.json();
    setCourses(data.courses || []);
    setLoading(false);
  };

  // Fetch quizzes for first course (for demo)
  const fetchQuizzes = async (course_id: number) => {
    setLoading(true);
    const res = await fetch(`/api/education/courses/${course_id}`);
    const data = await res.json();
    setQuizzes(data.course?.quizzes || []);
    setLoading(false);
  };

  // Fetch documents
  const fetchDocuments = async () => {
    setLoading(true);
    const res = await fetch('/api/admin/education/documents', {
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    const data = await res.json();
    setDocuments(data.documents || []);
    setLoading(false);
  };

  const fetchQuestionsForQuiz = async (quiz_id: number) => {
    const res = await fetch(`/api/education/quizzes/${quiz_id}`);
    const data = await res.json();
    setQuestionsByQuiz(q => ({ ...q, [quiz_id]: data.quiz?.questions || [] }));
  };

  const handleToggleQuestions = (quiz_id: number) => {
    setShowQuestionsForQuiz(s => ({ ...s, [quiz_id]: !s[quiz_id] }));
    if (!questionsByQuiz[quiz_id]) fetchQuestionsForQuiz(quiz_id);
  };

  const handleCreateCourse = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingCourse(true);
    await fetch('/api/admin/education/courses', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify(newCourse)
    });
    setCreatingCourse(false);
    setShowCourseModal(false);
    setNewCourse({ title: '', description: '', video_url: '' });
    fetchCourses();
  };

  const handleCreateQuiz = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingQuiz(true);
    await fetch('/api/admin/education/quizzes', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        ...newQuiz,
        course_id: selectedCourseId || courses[0]?.course_id
      })
    });
    setCreatingQuiz(false);
    setShowQuizModal(false);
    setNewQuiz({ title: '', description: '', course_id: '' });
    fetchQuizzes(Number(selectedCourseId || courses[0]?.course_id));
  };

  const handleCreateQuestion = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingQuestion(true);
    await fetch('/api/admin/education/questions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        ...newQuestion,
        quiz_id: selectedQuizId || quizzes[0]?.quiz_id
      })
    });
    setCreatingQuestion(false);
    setShowQuestionModal(false);
    setNewQuestion({ question_text: '', question_type: 'multiple_choice', quiz_id: '' });
    fetchQuizzes(Number(selectedCourseId || courses[0]?.course_id));
  };

  const handleCreateOption = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingOption(true);
    await fetch('/api/admin/education/options', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        ...newOption,
        question_id: selectedQuestionId
      })
    });
    setCreatingOption(false);
    setShowOptionModal(false);
    setNewOption({ option_text: '', is_correct: false, question_id: '' });
    fetchQuizzes(Number(selectedCourseId || courses[0]?.course_id));
  };

  const handleReviewDocument = async (document_id: number, status: 'approved' | 'rejected') => {
    if (!window.confirm(`Are you sure you want to ${status} this document?`)) return;
    await fetch(`/api/admin/education/documents/${document_id}/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ status })
    });
    fetchDocuments();
  };

  const handleEditCourse = (course: Course) => {
    setEditCourse(course);
    setShowEditCourseModal(true);
  };

  const handleUpdateCourse = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editCourse) return;
    await fetch(`/api/admin/education/courses/${editCourse.course_id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify(editCourse)
    });
    setShowEditCourseModal(false);
    setEditCourse(null);
    setToast({ type: 'success', message: 'Course updated!' });
    fetchCourses();
  };

  const handleDeleteCourse = async (course_id: number) => {
    if (!window.confirm('Are you sure you want to delete this course?')) return;
    setDeletingCourseId(course_id);
    await fetch(`/api/admin/education/courses/${course_id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    setDeletingCourseId(null);
    setToast({ type: 'success', message: 'Course deleted!' });
    fetchCourses();
  };

  const handleEditQuiz = (quiz: Quiz) => {
    setEditQuiz(quiz);
    setShowEditQuizModal(true);
  };

  const handleUpdateQuiz = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editQuiz) return;
    await fetch(`/api/admin/education/quizzes`, {
      method: 'POST', // You may want to use PUT if you have an update endpoint
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify(editQuiz)
    });
    setShowEditQuizModal(false);
    setEditQuiz(null);
    setToast({ type: 'success', message: 'Quiz updated!' });
    fetchQuizzes(Number(selectedCourseId || courses[0]?.course_id));
  };

  const handleDeleteQuiz = async (quiz_id: number) => {
    if (!window.confirm('Are you sure you want to delete this quiz?')) return;
    setDeletingQuizId(quiz_id);
    await fetch(`/api/admin/education/quizzes/${quiz_id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    setDeletingQuizId(null);
    setToast({ type: 'success', message: 'Quiz deleted!' });
    fetchQuizzes(Number(selectedCourseId || courses[0]?.course_id));
  };

  const handleEditQuestion = (question: any) => {
    setEditQuestion(question);
    setShowEditQuestionModal(true);
  };

  const handleUpdateQuestion = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editQuestion) return;
    await fetch(`/api/admin/education/questions`, {
      method: 'POST', // You may want to use PUT if you have an update endpoint
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify(editQuestion)
    });
    setShowEditQuestionModal(false);
    setEditQuestion(null);
    setToast({ type: 'success', message: 'Question updated!' });
    fetchQuestionsForQuiz(editQuestion.quiz_id);
  };

  const handleDeleteQuestion = async (question_id: number, quiz_id: number) => {
    if (!window.confirm('Are you sure you want to delete this question?')) return;
    setDeletingQuestionId(question_id);
    await fetch(`/api/admin/education/questions/${question_id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    setDeletingQuestionId(null);
    setToast({ type: 'success', message: 'Question deleted!' });
    fetchQuestionsForQuiz(quiz_id);
  };

  const handleEditOption = (option: any) => {
    setEditOption(option);
    setShowEditOptionModal(true);
  };

  const handleUpdateOption = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editOption) return;
    await fetch(`/api/admin/education/options`, {
      method: 'POST', // You may want to use PUT if you have an update endpoint
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify(editOption)
    });
    setShowEditOptionModal(false);
    setEditOption(null);
    setToast({ type: 'success', message: 'Option updated!' });
    fetchQuestionsForQuiz(editOption.quiz_id);
  };

  const handleDeleteOption = async (option_id: number, quiz_id: number) => {
    if (!window.confirm('Are you sure you want to delete this option?')) return;
    setDeletingOptionId(option_id);
    await fetch(`/api/admin/education/options/${option_id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    setDeletingOptionId(null);
    setToast({ type: 'success', message: 'Option deleted!' });
    fetchQuestionsForQuiz(quiz_id);
  };

  useEffect(() => {
    if (tab === 'courses') fetchCourses();
    if (tab === 'quizzes' && courses.length > 0) fetchQuizzes(courses[0].course_id);
    if (tab === 'documents') fetchDocuments();
  }, [tab]);

  return (
    <div className="max-w-5xl mx-auto py-8 px-4">
      <h1 className="text-3xl font-bold mb-6 text-center">Admin Education Panel</h1>
      <div className="flex space-x-4 mb-6 justify-center">
        <button onClick={() => setTab('courses')} className={`px-4 py-2 rounded ${tab === 'courses' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>Courses</button>
        <button onClick={() => setTab('quizzes')} className={`px-4 py-2 rounded ${tab === 'quizzes' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>Quizzes</button>
        <button onClick={() => setTab('documents')} className={`px-4 py-2 rounded ${tab === 'documents' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>Documents</button>
        <button onClick={() => setTab('certificates')} className={`px-4 py-2 rounded ${tab === 'certificates' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}>Certificates</button>
      </div>
      {loading ? (
        <div className="flex justify-center items-center h-32"><span className="loading loading-spinner loading-lg"></span></div>
      ) : (
        <>
          {tab === 'courses' && (
            <div>
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Courses</h2>
                <button
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                  onClick={() => setShowCourseModal(true)}
                >
                  Add Course
                </button>
              </div>
              <ul className="space-y-3">
                {courses.map(course => (
                  <li key={course.course_id} className="bg-gray-50 rounded p-4 shadow flex justify-between items-center transition hover:shadow-lg group">
                    <div>
                      <span className="font-medium text-lg">{course.title}</span>
                      <span className="block text-gray-500 text-sm">{course.description}</span>
                    </div>
                    <div className="flex items-center space-x-3 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        className="p-2 rounded hover:bg-blue-100 text-blue-600"
                        title="Edit Course"
                        onClick={() => handleEditCourse(course)}
                      >
                        <FaEdit />
                      </button>
                      <button
                        className="p-2 rounded hover:bg-red-100 text-red-600"
                        title="Delete Course"
                        onClick={() => handleDeleteCourse(course.course_id)}
                        disabled={deletingCourseId === course.course_id}
                      >
                        <FaTrash />
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
              {/* Course Creation Modal */}
              {showCourseModal && (
                <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
                  <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
                    <button
                      className="absolute top-2 right-2 text-gray-400 hover:text-gray-600"
                      onClick={() => setShowCourseModal(false)}
                    >
                      &times;
                    </button>
                    <h3 className="text-lg font-bold mb-4">Add New Course</h3>
                    <form onSubmit={handleCreateCourse} className="space-y-4">
                      <input
                        type="text"
                        className="w-full border rounded px-3 py-2"
                        placeholder="Title"
                        value={newCourse.title}
                        onChange={e => setNewCourse({ ...newCourse, title: e.target.value })}
                        required
                      />
                      <textarea
                        className="w-full border rounded px-3 py-2"
                        placeholder="Description"
                        value={newCourse.description}
                        onChange={e => setNewCourse({ ...newCourse, description: e.target.value })}
                      />
                      <input
                        type="text"
                        className="w-full border rounded px-3 py-2"
                        placeholder="Video URL (optional)"
                        value={newCourse.video_url}
                        onChange={e => setNewCourse({ ...newCourse, video_url: e.target.value })}
                      />
                      <button
                        type="submit"
                        className="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                        disabled={creatingCourse}
                      >
                        {creatingCourse ? 'Creating...' : 'Create Course'}
                      </button>
                    </form>
                  </div>
                </div>
              )}
              {/* Edit Course Modal */}
              {showEditCourseModal && editCourse && (
                <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
                  <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
                    <button
                      className="absolute top-2 right-2 text-gray-400 hover:text-gray-600"
                      onClick={() => setShowEditCourseModal(false)}
                    >
                      &times;
                    </button>
                    <h3 className="text-lg font-bold mb-4">Edit Course</h3>
                    <form onSubmit={handleUpdateCourse} className="space-y-4">
                      <input
                        type="text"
                        className="w-full border rounded px-3 py-2"
                        placeholder="Title"
                        value={editCourse.title}
                        onChange={e => setEditCourse({ ...editCourse, title: e.target.value })}
                        required
                      />
                      <textarea
                        className="w-full border rounded px-3 py-2"
                        placeholder="Description"
                        value={editCourse.description}
                        onChange={e => setEditCourse({ ...editCourse, description: e.target.value })}
                      />
                      <input
                        type="text"
                        className="w-full border rounded px-3 py-2"
                        placeholder="Video URL (optional)"
                        value={editCourse.video_url}
                        onChange={e => setEditCourse({ ...editCourse, video_url: e.target.value })}
                      />
                      <button
                        type="submit"
                        className="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                      >
                        Update Course
                      </button>
                    </form>
                  </div>
                </div>
              )}
              {/* Toast Notification */}
              {toast && (
                <div className={`fixed top-6 right-6 z-50 px-6 py-3 rounded shadow-lg text-white ${toast.type === 'success' ? 'bg-green-600' : 'bg-red-600'}`}
                  onClick={() => setToast(null)}
                  role="alert"
                  style={{ cursor: 'pointer' }}
                >
                  {toast.message}
                </div>
              )}
            </div>
          )}
          {tab === 'quizzes' && (
            <div>
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Quizzes (First Course)</h2>
                <button
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                  onClick={() => setShowQuizModal(true)}
                >
                  Add Quiz
                </button>
              </div>
              <div className="mb-4">
                <label className="block text-sm font-medium mb-1">Select Course:</label>
                <select
                  className="w-full border rounded px-3 py-2"
                  value={selectedCourseId || courses[0]?.course_id || ''}
                  onChange={e => setSelectedCourseId(e.target.value)}
                >
                  {courses.map(course => (
                    <option key={course.course_id} value={course.course_id}>{course.title}</option>
                  ))}
                </select>
              </div>
              <ul className="space-y-3">
                {quizzes.map(quiz => (
                  <li key={quiz.quiz_id} className="bg-gray-50 rounded p-4 shadow flex justify-between items-center transition hover:shadow-lg group">
                    <div>
                      <span className="font-medium text-lg">{quiz.title}</span>
                      <span className="block text-gray-500 text-sm">{quiz.description}</span>
                    </div>
                    <div className="flex items-center space-x-3 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        className="p-2 rounded hover:bg-blue-100 text-blue-600"
                        title="Edit Quiz"
                        onClick={() => handleEditQuiz(quiz)}
                      >
                        <FaEdit />
                      </button>
                      <button
                        className="p-2 rounded hover:bg-red-100 text-red-600"
                        title="Delete Quiz"
                        onClick={() => handleDeleteQuiz(quiz.quiz_id)}
                        disabled={deletingQuizId === quiz.quiz_id}
                      >
                        <FaTrash />
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
              {/* Quiz Creation Modal */}
              {showQuizModal && (
                <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
                  <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
                    <button
                      className="absolute top-2 right-2 text-gray-400 hover:text-gray-600"
                      onClick={() => setShowQuizModal(false)}
                    >
                      &times;
                    </button>
                    <h3 className="text-lg font-bold mb-4">Add New Quiz</h3>
                    <form onSubmit={handleCreateQuiz} className="space-y-4">
                      <input
                        type="text"
                        className="w-full border rounded px-3 py-2"
                        placeholder="Quiz Title"
                        value={newQuiz.title}
                        onChange={e => setNewQuiz({ ...newQuiz, title: e.target.value })}
                        required
                      />
                      <textarea
                        className="w-full border rounded px-3 py-2"
                        placeholder="Description"
                        value={newQuiz.description}
                        onChange={e => setNewQuiz({ ...newQuiz, description: e.target.value })}
                      />
                      <button
                        type="submit"
                        className="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                        disabled={creatingQuiz}
                      >
                        {creatingQuiz ? 'Creating...' : 'Create Quiz'}
                      </button>
                    </form>
                  </div>
                </div>
              )}
              {/* Edit Quiz Modal */}
              {showEditQuizModal && editQuiz && (
                <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
                  <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
                    <button
                      className="absolute top-2 right-2 text-gray-400 hover:text-gray-600"
                      onClick={() => setShowEditQuizModal(false)}
                    >
                      &times;
                    </button>
                    <h3 className="text-lg font-bold mb-4">Edit Quiz</h3>
                    <form onSubmit={handleUpdateQuiz} className="space-y-4">
                      <input
                        type="text"
                        className="w-full border rounded px-3 py-2"
                        placeholder="Quiz Title"
                        value={editQuiz.title}
                        onChange={e => setEditQuiz({ ...editQuiz, title: e.target.value })}
                        required
                      />
                      <textarea
                        className="w-full border rounded px-3 py-2"
                        placeholder="Description"
                        value={editQuiz.description}
                        onChange={e => setEditQuiz({ ...editQuiz, description: e.target.value })}
                      />
                      <button
                        type="submit"
                        className="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                      >
                        Update Quiz
                      </button>
                    </form>
                  </div>
                </div>
              )}
              {/* Question Creation Modal */}
              {showQuestionModal && (
                <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
                  <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
                    <button
                      className="absolute top-2 right-2 text-gray-400 hover:text-gray-600"
                      onClick={() => setShowQuestionModal(false)}
                    >
                      &times;
                    </button>
                    <h3 className="text-lg font-bold mb-4">Add New Question</h3>
                    <form onSubmit={handleCreateQuestion} className="space-y-4">
                      <input
                        type="text"
                        className="w-full border rounded px-3 py-2"
                        placeholder="Question Text"
                        value={newQuestion.question_text}
                        onChange={e => setNewQuestion({ ...newQuestion, question_text: e.target.value })}
                        required
                      />
                      <select
                        className="w-full border rounded px-3 py-2"
                        value={newQuestion.question_type}
                        onChange={e => setNewQuestion({ ...newQuestion, question_type: e.target.value })}
                      >
                        <option value="multiple_choice">Multiple Choice</option>
                        <option value="short_answer">Short Answer</option>
                      </select>
                      <select
                        className="w-full border rounded px-3 py-2"
                        value={selectedQuizId || quizzes[0]?.quiz_id || ''}
                        onChange={e => setSelectedQuizId(e.target.value)}
                      >
                        {quizzes.map(quiz => (
                          <option key={quiz.quiz_id} value={quiz.quiz_id}>{quiz.title}</option>
                        ))}
                      </select>
                      <button
                        type="submit"
                        className="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                        disabled={creatingQuestion}
                      >
                        {creatingQuestion ? 'Creating...' : 'Create Question'}
                      </button>
                    </form>
                  </div>
                </div>
              )}
              {/* Option Creation Modal */}
              {showOptionModal && (
                <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
                  <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
                    <button
                      className="absolute top-2 right-2 text-gray-400 hover:text-gray-600"
                      onClick={() => setShowOptionModal(false)}
                    >
                      &times;
                    </button>
                    <h3 className="text-lg font-bold mb-4">Add New Option</h3>
                    <form onSubmit={handleCreateOption} className="space-y-4">
                      <input
                        type="text"
                        className="w-full border rounded px-3 py-2"
                        placeholder="Option Text"
                        value={newOption.option_text}
                        onChange={e => setNewOption({ ...newOption, option_text: e.target.value })}
                        required
                      />
                      <label className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={newOption.is_correct}
                          onChange={e => setNewOption({ ...newOption, is_correct: e.target.checked })}
                        />
                        <span>Is Correct</span>
                      </label>
                      <button
                        type="submit"
                        className="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                        disabled={creatingOption}
                      >
                        {creatingOption ? 'Creating...' : 'Create Option'}
                      </button>
                    </form>
                  </div>
                </div>
              )}
              {showQuestionsForQuiz[quiz.quiz_id] && questionsByQuiz[quiz.quiz_id] && (
                <ul className="ml-8 mt-2 space-y-2">
                  {questionsByQuiz[quiz.quiz_id].map((question: any) => (
                    <li key={question.question_id} className="bg-white rounded p-3 shadow flex justify-between items-center transition hover:shadow-md group">
                      <div>
                        <span className="font-medium">{question.question_text}</span>
                        <span className="ml-2 text-xs text-gray-400">[{question.question_type}]</span>
                      </div>
                      <div className="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button className="p-1 rounded hover:bg-blue-100 text-blue-600" title="Edit Question" onClick={() => handleEditQuestion(question)}><FaEdit /></button>
                        <button className="p-1 rounded hover:bg-red-100 text-red-600" title="Delete Question" onClick={() => handleDeleteQuestion(question.question_id, quiz.quiz_id)} disabled={deletingQuestionId === question.question_id}><FaTrash /></button>
                        <button className="p-1 rounded hover:bg-green-100 text-green-600" title="Add Option" onClick={() => { setShowOptionModal(true); setSelectedQuestionId(question.question_id.toString()); }} disabled={question.question_type !== 'multiple_choice'}>+</button>
                      </div>
                      {/* Options for multiple choice */}
                      {question.question_type === 'multiple_choice' && question.options && (
                        <ul className="ml-8 mt-2 space-y-1">
                          {question.options.map((option: any) => (
                            <li key={option.option_id} className="flex items-center space-x-2">
                              <span className={option.is_correct ? 'text-green-600 font-semibold' : ''}>{option.option_text}</span>
                              <button className="p-1 rounded hover:bg-blue-100 text-blue-600" title="Edit Option" onClick={() => handleEditOption({ ...option, quiz_id: quiz.quiz_id })}><FaEdit /></button>
                              <button className="p-1 rounded hover:bg-red-100 text-red-600" title="Delete Option" onClick={() => handleDeleteOption(option.option_id, quiz.quiz_id)} disabled={deletingOptionId === option.option_id}><FaTrash /></button>
                            </li>
                          ))}
                        </ul>
                      )}
                    </li>
                  ))}
                </ul>
              )}
              {/* Edit Question Modal */}
              {showEditQuestionModal && editQuestion && (
                <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
                  <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
                    <button className="absolute top-2 right-2 text-gray-400 hover:text-gray-600" onClick={() => setShowEditQuestionModal(false)}>&times;</button>
                    <h3 className="text-lg font-bold mb-4">Edit Question</h3>
                    <form onSubmit={handleUpdateQuestion} className="space-y-4">
                      <input type="text" className="w-full border rounded px-3 py-2" placeholder="Question Text" value={editQuestion.question_text} onChange={e => setEditQuestion({ ...editQuestion, question_text: e.target.value })} required />
                      <select className="w-full border rounded px-3 py-2" value={editQuestion.question_type} onChange={e => setEditQuestion({ ...editQuestion, question_type: e.target.value })}>
                        <option value="multiple_choice">Multiple Choice</option>
                        <option value="short_answer">Short Answer</option>
                      </select>
                      <button type="submit" className="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">Update Question</button>
                    </form>
                  </div>
                </div>
              )}
              {/* Edit Option Modal */}
              {showEditOptionModal && editOption && (
                <div className="fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50">
                  <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
                    <button className="absolute top-2 right-2 text-gray-400 hover:text-gray-600" onClick={() => setShowEditOptionModal(false)}>&times;</button>
                    <h3 className="text-lg font-bold mb-4">Edit Option</h3>
                    <form onSubmit={handleUpdateOption} className="space-y-4">
                      <input type="text" className="w-full border rounded px-3 py-2" placeholder="Option Text" value={editOption.option_text} onChange={e => setEditOption({ ...editOption, option_text: e.target.value })} required />
                      <label className="flex items-center space-x-2">
                        <input type="checkbox" checked={editOption.is_correct} onChange={e => setEditOption({ ...editOption, is_correct: e.target.checked })} />
                        <span>Is Correct</span>
                      </label>
                      <button type="submit" className="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">Update Option</button>
                    </form>
                  </div>
                </div>
              )}
            </div>
          )}

          {tab === 'documents' && (
            <div>
              <h2 className="text-xl font-semibold mb-4">User Documents</h2>
              <ul className="space-y-3">
                {documents.map(doc => (
                  <li key={doc.document_id} className="bg-gray-50 rounded p-4 shadow flex justify-between items-center">
                    <div>
                      <span className="font-medium">User #{doc.user_id} - {doc.document_type}</span>
                      <span className="block text-gray-500 text-xs">Uploaded: {new Date(doc.uploaded_at).toLocaleString()}</span>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold ${doc.status === 'approved' ? 'bg-green-100 text-green-700' : doc.status === 'rejected' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'}`}>{doc.status}</span>
                    <div className="flex space-x-2">
                      <button
                        className="px-3 py-1 bg-green-500 text-white rounded hover:bg-green-600"
                        onClick={() => handleReviewDocument(doc.document_id, 'approved')}
                        disabled={doc.status === 'approved'}
                      >
                        Approve
                      </button>
                      <button
                        className="px-3 py-1 bg-red-500 text-white rounded hover:bg-red-600"
                        onClick={() => handleReviewDocument(doc.document_id, 'rejected')}
                        disabled={doc.status === 'rejected'}
                      >
                        Reject
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {tab === 'certificates' && (
            <div>
              <h2 className="text-xl font-semibold mb-4">Certificate Generation</h2>
              <div className="text-gray-500">Coming soon...</div>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default AdminEducationPanel; 