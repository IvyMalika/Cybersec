import React, { useRef, useState, useEffect } from 'react';

interface DocumentStatus {
  document_id: number;
  document_type: string;
  file_url: string;
  status: string;
  reviewed_by: number | null;
  reviewed_at: string | null;
  uploaded_at: string;
}

const DocumentUpload: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [documentType, setDocumentType] = useState('');
  const [uploading, setUploading] = useState(false);
  const [documents, setDocuments] = useState<DocumentStatus[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchDocuments = async () => {
    const res = await fetch('/api/education/documents/status', {
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    const data = await res.json();
    setDocuments(data.documents || []);
  };

  useEffect(() => {
    fetchDocuments();
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile || !documentType) return;
    setUploading(true);
    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('document_type', documentType);
    await fetch('/api/education/documents/upload', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
      body: formData
    });
    setUploading(false);
    setSelectedFile(null);
    setDocumentType('');
    fetchDocuments();
  };

  return (
    <div className="max-w-xl mx-auto py-8 px-4">
      <h2 className="text-xl font-bold mb-4">Upload Required Documents</h2>
      <div
        className="border-2 border-dashed border-gray-300 rounded-lg p-6 flex flex-col items-center justify-center cursor-pointer hover:border-blue-400 transition mb-4"
        onClick={() => fileInputRef.current?.click()}
        onDrop={handleDrop}
        onDragOver={e => e.preventDefault()}
      >
        <input
          type="file"
          ref={fileInputRef}
          className="hidden"
          onChange={handleFileChange}
        />
        <span className="text-gray-500 mb-2">Drag & drop or click to select a file</span>
        {selectedFile && <span className="text-blue-600 font-medium">{selectedFile.name}</span>}
      </div>
      <input
        type="text"
        className="w-full border rounded px-3 py-2 mb-2"
        placeholder="Document Type (e.g., ID, Certificate, etc.)"
        value={documentType}
        onChange={e => setDocumentType(e.target.value)}
      />
      <button
        className="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition mb-6"
        onClick={handleUpload}
        disabled={!selectedFile || !documentType || uploading}
      >
        {uploading ? 'Uploading...' : 'Upload Document'}
      </button>
      <h3 className="text-lg font-semibold mb-2">Your Documents</h3>
      <ul className="space-y-3">
        {documents.map(doc => (
          <li key={doc.document_id} className="flex items-center justify-between bg-gray-50 rounded p-3 shadow-sm">
            <div>
              <span className="font-medium">{doc.document_type}</span>
              <span className="block text-gray-500 text-xs">Uploaded: {new Date(doc.uploaded_at).toLocaleString()}</span>
            </div>
            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${doc.status === 'approved' ? 'bg-green-100 text-green-700' : doc.status === 'rejected' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'}`}>{doc.status}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default DocumentUpload; 