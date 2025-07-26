-- Education Database INSERT Statements
-- Run these SQL commands in your MySQL database to populate the education tables

-- First, create the tables if they don't exist
CREATE TABLE IF NOT EXISTS courses (
    course_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    video_url VARCHAR(500),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS quizzes (
    quiz_id INT AUTO_INCREMENT PRIMARY KEY,
    course_id INT,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    FOREIGN KEY (course_id) REFERENCES courses(course_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS questions (
    question_id INT AUTO_INCREMENT PRIMARY KEY,
    quiz_id INT,
    question_text TEXT NOT NULL,
    question_type ENUM('multiple_choice', 'text', 'true_false') DEFAULT 'multiple_choice',
    FOREIGN KEY (quiz_id) REFERENCES quizzes(quiz_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS options (
    option_id INT AUTO_INCREMENT PRIMARY KEY,
    question_id INT,
    option_text TEXT NOT NULL,
    is_correct BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (question_id) REFERENCES questions(question_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_course_progress (
    progress_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    course_id INT,
    progress DECIMAL(5,2) DEFAULT 0.0,
    completed BOOLEAN DEFAULT FALSE,
    certificate_url VARCHAR(500),
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(course_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_quiz_submissions (
    submission_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    quiz_id INT,
    score INT DEFAULT 0,
    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (quiz_id) REFERENCES quizzes(quiz_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_answers (
    answer_id INT AUTO_INCREMENT PRIMARY KEY,
    submission_id INT,
    question_id INT,
    selected_option_id INT NULL,
    answer_text TEXT NULL,
    FOREIGN KEY (submission_id) REFERENCES user_quiz_submissions(submission_id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES questions(question_id) ON DELETE CASCADE,
    FOREIGN KEY (selected_option_id) REFERENCES options(option_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_documents (
    document_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    document_type VARCHAR(100) NOT NULL,
    file_url VARCHAR(500),
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    reviewed_by INT NULL,
    reviewed_at DATETIME NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Insert sample courses
INSERT INTO courses (title, description, video_url) VALUES 
('Introduction to Cybersecurity', 'Learn the fundamentals of cybersecurity including threats, vulnerabilities, and basic defense strategies.', 'https://example.com/videos/intro-cybersecurity.mp4'),
('Network Security Fundamentals', 'Understand network protocols, common attacks, and how to secure network infrastructure.', 'https://example.com/videos/network-security.mp4'),
('Web Application Security', 'Learn about OWASP Top 10 vulnerabilities, SQL injection, XSS, and secure coding practices.', 'https://example.com/videos/web-security.mp4'),
('Ethical Hacking Basics', 'Learn penetration testing methodologies, tools, and techniques for security assessment.', 'https://example.com/videos/ethical-hacking.mp4'),
('Incident Response & Forensics', 'Learn how to respond to security incidents and conduct digital forensics investigations.', 'https://example.com/videos/incident-response.mp4');

-- Insert quizzes for Course 1 (Introduction to Cybersecurity)
INSERT INTO quizzes (course_id, title, description) VALUES 
(1, 'Cybersecurity Basics Quiz', 'Test your knowledge of fundamental cybersecurity concepts'),
(1, 'Security Fundamentals Quiz', 'Assess your understanding of basic security principles');

-- Insert quizzes for Course 2 (Network Security)
INSERT INTO quizzes (course_id, title, description) VALUES 
(2, 'Network Security Quiz', 'Test your understanding of network security concepts'),
(2, 'Protocol Security Quiz', 'Assess your knowledge of secure protocols');

-- Insert quizzes for Course 3 (Web Application Security)
INSERT INTO quizzes (course_id, title, description) VALUES 
(3, 'OWASP Top 10 Quiz', 'Test your knowledge of OWASP Top 10 vulnerabilities'),
(3, 'Web Security Quiz', 'Assess your understanding of web application security');

-- Insert questions for Quiz 1 (Cybersecurity Basics)
INSERT INTO questions (quiz_id, question_text, question_type) VALUES 
(1, 'What is the primary goal of cybersecurity?', 'multiple_choice'),
(1, 'Which of the following is NOT a common cyber threat?', 'multiple_choice'),
(1, 'What does CIA stand for in cybersecurity?', 'multiple_choice'),
(1, 'Which of the following is a type of malware?', 'multiple_choice'),
(1, 'What is phishing?', 'multiple_choice');

-- Insert options for Question 1
INSERT INTO options (question_id, option_text, is_correct) VALUES 
(1, 'To protect information systems from theft or damage', TRUE),
(1, 'To make systems faster', FALSE),
(1, 'To reduce costs', FALSE),
(1, 'To improve user experience', FALSE);

-- Insert options for Question 2
INSERT INTO options (question_id, option_text, is_correct) VALUES 
(2, 'Malware', FALSE),
(2, 'Phishing', FALSE),
(2, 'Solar flares', TRUE),
(2, 'DDoS attacks', FALSE);

-- Insert options for Question 3
INSERT INTO options (question_id, option_text, is_correct) VALUES 
(3, 'Confidentiality, Integrity, Availability', TRUE),
(3, 'Computer, Internet, Access', FALSE),
(3, 'Cyber, Information, Attack', FALSE),
(3, 'Control, Identity, Authentication', FALSE);

-- Insert options for Question 4
INSERT INTO options (question_id, option_text, is_correct) VALUES 
(4, 'Virus', TRUE),
(4, 'Firewall', FALSE),
(4, 'Encryption', FALSE),
(4, 'VPN', FALSE);

-- Insert options for Question 5
INSERT INTO options (question_id, option_text, is_correct) VALUES 
(5, 'A social engineering attack that tricks users into revealing sensitive information', TRUE),
(5, 'A type of firewall', FALSE),
(5, 'A network protocol', FALSE),
(5, 'A security software', FALSE);

-- Insert questions for Quiz 2 (Network Security)
INSERT INTO questions (quiz_id, question_text, question_type) VALUES 
(3, 'What protocol is commonly used for secure web browsing?', 'multiple_choice'),
(3, 'What is a VPN used for?', 'multiple_choice'),
(3, 'Which port is typically used for HTTPS?', 'multiple_choice');

-- Insert options for Network Security questions
INSERT INTO options (question_id, option_text, is_correct) VALUES 
(6, 'HTTPS', TRUE),
(6, 'HTTP', FALSE),
(6, 'FTP', FALSE),
(6, 'SMTP', FALSE);

INSERT INTO options (question_id, option_text, is_correct) VALUES 
(7, 'To create a secure, encrypted connection over a public network', TRUE),
(7, 'To increase internet speed', FALSE),
(7, 'To block all traffic', FALSE),
(7, 'To share files', FALSE);

INSERT INTO options (question_id, option_text, is_correct) VALUES 
(8, '443', TRUE),
(8, '80', FALSE),
(8, '21', FALSE),
(8, '25', FALSE);

-- Insert questions for Quiz 3 (Web Security)
INSERT INTO questions (quiz_id, question_text, question_type) VALUES 
(5, 'What is SQL Injection?', 'multiple_choice'),
(5, 'What is XSS?', 'multiple_choice'),
(5, 'Which OWASP Top 10 vulnerability involves broken authentication?', 'multiple_choice');

-- Insert options for Web Security questions
INSERT INTO options (question_id, option_text, is_correct) VALUES 
(9, 'A code injection technique that exploits vulnerabilities in database queries', TRUE),
(9, 'A type of firewall', FALSE),
(9, 'A network protocol', FALSE),
(9, 'A security software', FALSE);

INSERT INTO options (question_id, option_text, is_correct) VALUES 
(10, 'Cross-Site Scripting', TRUE),
(10, 'Cross-Site Security', FALSE),
(10, 'Cross-Site Scanning', FALSE),
(10, 'Cross-Site Service', FALSE);

INSERT INTO options (question_id, option_text, is_correct) VALUES 
(11, 'A02:2021 - Cryptographic Failures', FALSE),
(11, 'A07:2021 - Identification and Authentication Failures', TRUE),
(11, 'A01:2021 - Broken Access Control', FALSE),
(11, 'A03:2021 - Injection', FALSE);

-- Insert sample user progress (assuming user_id 1 exists)
-- You can modify the user_id to match an existing user in your database
INSERT INTO user_course_progress (user_id, course_id, progress, completed) VALUES 
(1, 1, 0.0, FALSE),
(1, 2, 0.3, FALSE),
(1, 3, 0.8, FALSE),
(1, 4, 1.0, TRUE),
(1, 5, 0.0, FALSE);

-- Update the completed course with certificate URL
UPDATE user_course_progress 
SET certificate_url = 'https://example.com/certificates/ethical-hacking.pdf', 
    completed_at = NOW() 
WHERE user_id = 1 AND course_id = 4;

-- Insert sample user documents (assuming user_id 1 exists)
INSERT INTO user_documents (user_id, document_type, file_url, status) VALUES 
(1, 'ID Card', '/uploads/id_card_user1.pdf', 'approved'),
(1, 'Certificate', '/uploads/certificate_user1.pdf', 'pending'),
(1, 'Resume', '/uploads/resume_user1.pdf', 'approved');

-- Show the inserted data
SELECT 'Courses' as table_name, COUNT(*) as count FROM courses
UNION ALL
SELECT 'Quizzes' as table_name, COUNT(*) as count FROM quizzes
UNION ALL
SELECT 'Questions' as table_name, COUNT(*) as count FROM questions
UNION ALL
SELECT 'Options' as table_name, COUNT(*) as count FROM options
UNION ALL
SELECT 'User Progress' as table_name, COUNT(*) as count FROM user_course_progress
UNION ALL
SELECT 'User Documents' as table_name, COUNT(*) as count FROM user_documents; 