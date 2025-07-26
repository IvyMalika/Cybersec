import pymysql
from pymysql.cursors import DictCursor
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

def get_db_connection():
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', 'localhost'),
        user=os.getenv('MYSQL_USER', 'cybersec_app'),
        password=os.getenv('MYSQL_PASSWORD', 'SecurePassword123!'),
        db=os.getenv('MYSQL_DB', 'cybersec_automation'),
        port=int(os.getenv('MYSQL_PORT', 3306)),
        charset='utf8mb4',
        cursorclass=DictCursor,
        autocommit=True
    )

def execute_query(query, args=None, fetch_one=False):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, args or ())
            if query.strip().upper().startswith('SELECT'):
                return cursor.fetchone() if fetch_one else cursor.fetchall()
            return cursor.lastrowid
    except pymysql.Error as e:
        print(f"Database error: {e}")
        raise
    finally:
        conn.commit()
        conn.close()

def setup_education():
    print("Setting up education tables and data...")
    
    # Create courses table
    execute_query("""
        CREATE TABLE IF NOT EXISTS courses (
            course_id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            video_url VARCHAR(500),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create quizzes table
    execute_query("""
        CREATE TABLE IF NOT EXISTS quizzes (
            quiz_id INT AUTO_INCREMENT PRIMARY KEY,
            course_id INT,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            FOREIGN KEY (course_id) REFERENCES courses(course_id) ON DELETE CASCADE
        )
    """)
    
    # Create questions table
    execute_query("""
        CREATE TABLE IF NOT EXISTS questions (
            question_id INT AUTO_INCREMENT PRIMARY KEY,
            quiz_id INT,
            question_text TEXT NOT NULL,
            question_type ENUM('multiple_choice', 'text', 'true_false') DEFAULT 'multiple_choice',
            FOREIGN KEY (quiz_id) REFERENCES quizzes(quiz_id) ON DELETE CASCADE
        )
    """)
    
    # Create options table
    execute_query("""
        CREATE TABLE IF NOT EXISTS options (
            option_id INT AUTO_INCREMENT PRIMARY KEY,
            question_id INT,
            option_text TEXT NOT NULL,
            is_correct BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (question_id) REFERENCES questions(question_id) ON DELETE CASCADE
        )
    """)
    
    # Create user_course_progress table
    execute_query("""
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
        )
    """)
    
    # Create user_quiz_submissions table
    execute_query("""
        CREATE TABLE IF NOT EXISTS user_quiz_submissions (
            submission_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            quiz_id INT,
            score INT DEFAULT 0,
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (quiz_id) REFERENCES quizzes(quiz_id) ON DELETE CASCADE
        )
    """)
    
    # Create user_answers table
    execute_query("""
        CREATE TABLE IF NOT EXISTS user_answers (
            answer_id INT AUTO_INCREMENT PRIMARY KEY,
            submission_id INT,
            question_id INT,
            selected_option_id INT NULL,
            answer_text TEXT NULL,
            FOREIGN KEY (submission_id) REFERENCES user_quiz_submissions(submission_id) ON DELETE CASCADE,
            FOREIGN KEY (question_id) REFERENCES questions(question_id) ON DELETE CASCADE,
            FOREIGN KEY (selected_option_id) REFERENCES options(option_id) ON DELETE CASCADE
        )
    """)
    
    # Create user_documents table
    execute_query("""
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
        )
    """)
    
    print("Education tables created successfully!")
    
    # Check if courses already exist
    existing_courses = execute_query("SELECT COUNT(*) as count FROM courses")
    if existing_courses[0]['count'] == 0:
        print("Adding sample courses...")
        
        # Add sample courses
        course1_id = execute_query("""
            INSERT INTO courses (title, description, video_url) 
            VALUES ('Introduction to Cybersecurity', 'Learn the fundamentals of cybersecurity including threats, vulnerabilities, and basic defense strategies.', 'https://example.com/videos/intro-cybersecurity.mp4')
        """)
        
        course2_id = execute_query("""
            INSERT INTO courses (title, description, video_url) 
            VALUES ('Network Security Fundamentals', 'Understand network protocols, common attacks, and how to secure network infrastructure.', 'https://example.com/videos/network-security.mp4')
        """)
        
        course3_id = execute_query("""
            INSERT INTO courses (title, description, video_url) 
            VALUES ('Web Application Security', 'Learn about OWASP Top 10 vulnerabilities, SQL injection, XSS, and secure coding practices.', 'https://example.com/videos/web-security.mp4')
        """)
        
        course4_id = execute_query("""
            INSERT INTO courses (title, description, video_url) 
            VALUES ('Ethical Hacking Basics', 'Learn penetration testing methodologies, tools, and techniques for security assessment.', 'https://example.com/videos/ethical-hacking.mp4')
        """)
        
        course5_id = execute_query("""
            INSERT INTO courses (title, description, video_url) 
            VALUES ('Incident Response & Forensics', 'Learn how to respond to security incidents and conduct digital forensics investigations.', 'https://example.com/videos/incident-response.mp4')
        """)
        
        print(f"Added {5} sample courses!")
        
        # Add quizzes for course 1
        quiz1_id = execute_query("""
            INSERT INTO quizzes (course_id, title, description) 
            VALUES (%s, 'Cybersecurity Basics Quiz', 'Test your knowledge of fundamental cybersecurity concepts')
        """, (course1_id,))
        
        # Add questions for quiz 1
        q1_id = execute_query("""
            INSERT INTO questions (quiz_id, question_text, question_type) 
            VALUES (%s, 'What is the primary goal of cybersecurity?', 'multiple_choice')
        """, (quiz1_id,))
        
        q2_id = execute_query("""
            INSERT INTO questions (quiz_id, question_text, question_type) 
            VALUES (%s, 'Which of the following is NOT a common cyber threat?', 'multiple_choice')
        """, (quiz1_id,))
        
        # Add options for question 1
        execute_query("""
            INSERT INTO options (question_id, option_text, is_correct) VALUES 
            (%s, 'To protect information systems from theft or damage', TRUE),
            (%s, 'To make systems faster', FALSE),
            (%s, 'To reduce costs', FALSE),
            (%s, 'To improve user experience', FALSE)
        """, (q1_id, q1_id, q1_id, q1_id))
        
        # Add options for question 2
        execute_query("""
            INSERT INTO options (question_id, option_text, is_correct) VALUES 
            (%s, 'Malware', FALSE),
            (%s, 'Phishing', FALSE),
            (%s, 'Solar flares', TRUE),
            (%s, 'DDoS attacks', FALSE)
        """, (q2_id, q2_id, q2_id, q2_id))
        
        print("Added sample quizzes and questions!")
    else:
        print(f"Found {existing_courses[0]['count']} existing courses, skipping sample data creation.")
    
    print("Education setup completed successfully!")
    print("You can now access the education dashboard and see courses, quizzes, and other content.")

if __name__ == "__main__":
    try:
        setup_education()
    except Exception as e:
        print(f"Error setting up education: {e}")
        import traceback
        traceback.print_exc() 