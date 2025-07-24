import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';

const CertificatePreview: React.FC = () => {
  const { course_id } = useParams<{ course_id: string }>();
  const [certificateUrl, setCertificateUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [showConfetti, setShowConfetti] = useState(false);

  useEffect(() => {
    const fetchCertificate = async () => {
      setLoading(true);
      const res = await fetch(`/api/education/certificate/${course_id}`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        setCertificateUrl(url);
        setShowConfetti(true);
      }
      setLoading(false);
    };
    fetchCertificate();
  }, [course_id]);

  return (
    <div className="max-w-xl mx-auto py-8 px-4 text-center">
      <h2 className="text-2xl font-bold mb-4">Your Certificate</h2>
      {loading ? (
        <span className="loading loading-spinner loading-lg"></span>
      ) : certificateUrl ? (
        <>
          <iframe
            src={certificateUrl}
            title="Certificate Preview"
            className="w-full h-96 border rounded mb-4"
          ></iframe>
          <a
            href={certificateUrl}
            download={`certificate_course_${course_id}.pdf`}
            className="px-6 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition"
          >
            Download Certificate
          </a>
          {showConfetti && (
            <div className="fixed inset-0 pointer-events-none z-50">
              {/* Simple confetti effect using emoji */}
              <div className="absolute inset-0 flex flex-wrap items-center justify-center animate-bounce text-4xl opacity-80">
                {Array.from({ length: 30 }).map((_, i) => (
                  <span key={i} className="mx-2">🎉</span>
                ))}
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="text-red-500">Certificate not available.</div>
      )}
    </div>
  );
};

export default CertificatePreview; 