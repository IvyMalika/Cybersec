import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

interface Option {
  option_id: number;
  option_text: string;
}

interface Question {
  question_id: number;
  question_text: string;
  question_type: string;
  options: Option[];
}

interface Quiz {
  quiz_id: number;
  title: string;
  description: string;
  questions: Question[];
}

const QuizInterface: React.FC = () => {
  const { quiz_id } = useParams<{ quiz_id: string }>();
  const [quiz, setQuiz] = useState<Quiz | null>(null);
  const [current, setCurrent] = useState(0);
  const [answers, setAnswers] = useState<any[]>([]);
  const [submitted, setSubmitted] = useState(false);
  const [score, setScore] = useState<number | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchQuiz = async () => {
      const res = await fetch(`/api/education/quizzes/${quiz_id}`);
      const data = await res.json();
      setQuiz(data.quiz);
    };
    fetchQuiz();
  }, [quiz_id]);

  const handleAnswer = (question_id: number, selected_option_id: number | null, answer_text: string | null) => {
    setAnswers(prev => {
      const filtered = prev.filter(a => a.question_id !== question_id);
      return [...filtered, { question_id, selected_option_id, answer_text }];
    });
  };

  const handleSubmit = async () => {
    const res = await fetch(`/api/education/quizzes/${quiz_id}/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ answers })
    });
    const data = await res.json();
    setScore(data.score);
    setSubmitted(true);
  };

  if (!quiz) {
    return <div className="flex justify-center items-center h-32"><span className="loading loading-spinner loading-lg"></span></div>;
  }

  if (submitted) {
    return (
      <div className="max-w-xl mx-auto py-8 px-4 text-center">
        <h2 className="text-2xl font-bold mb-4">Quiz Complete!</h2>
        <p className="text-lg mb-2">Your Score: <span className="font-semibold">{score}</span> / {quiz.questions.length}</p>
        <button
          className="mt-4 px-6 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition"
          onClick={() => navigate(-1)}
        >
          Back to Course
        </button>
      </div>
    );
  }

  const question = quiz.questions[current];
  const total = quiz.questions.length;

  return (
    <div className="max-w-xl mx-auto py-8 px-4">
      <h2 className="text-xl font-bold mb-4">{quiz.title}</h2>
      <div className="mb-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-gray-500">Question {current + 1} of {total}</span>
          <div className="w-1/2 bg-gray-200 rounded-full h-2">
            <div className="h-2 rounded-full bg-blue-500" style={{ width: `${((current + 1) / total) * 100}%` }}></div>
          </div>
        </div>
        <div className="bg-white rounded shadow p-6">
          <p className="font-medium mb-4">{question.question_text}</p>
          {question.question_type === 'multiple_choice' && (
            <div className="space-y-2">
              {question.options.map(opt => (
                <label key={opt.option_id} className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="radio"
                    name={`q_${question.question_id}`}
                    value={opt.option_id}
                    checked={answers.find(a => a.question_id === question.question_id)?.selected_option_id === opt.option_id}
                    onChange={() => handleAnswer(question.question_id, opt.option_id, null)}
                    className="form-radio text-blue-600"
                  />
                  <span>{opt.option_text}</span>
                </label>
              ))}
            </div>
          )}
          {question.question_type === 'short_answer' && (
            <input
              type="text"
              className="mt-2 w-full border rounded px-3 py-2"
              value={answers.find(a => a.question_id === question.question_id)?.answer_text || ''}
              onChange={e => handleAnswer(question.question_id, null, e.target.value)}
              placeholder="Your answer..."
            />
          )}
        </div>
      </div>
      <div className="flex justify-between mt-4">
        <button
          className="px-4 py-2 bg-gray-200 rounded hover:bg-gray-300"
          onClick={() => setCurrent(c => Math.max(0, c - 1))}
          disabled={current === 0}
        >
          Previous
        </button>
        {current < total - 1 ? (
          <button
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            onClick={() => setCurrent(c => Math.min(total - 1, c + 1))}
          >
            Next
          </button>
        ) : (
          <button
            className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
            onClick={handleSubmit}
          >
            Submit Quiz
          </button>
        )}
      </div>
    </div>
  );
};

export default QuizInterface; 