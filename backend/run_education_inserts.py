import pymysql
from pymysql.cursors import DictCursor
import os
from dotenv import load_dotenv

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

def insert_education_data():
    print("Inserting education data...")
    
    # Insert courses
    courses_data = [
        ('Introduction to Cybersecurity', 'Learn the fundamentals of cybersecurity including threats, vulnerabilities, and basic defense strategies.', 'https://example.com/videos/intro-cybersecurity.mp4'),
        ('Network Security Fundamentals', 'Understand network protocols, common attacks, and how to secure network infrastructure.', 'https://example.com/videos/network-security.mp4'),
        ('Web Application Security', 'Learn about OWASP Top 10 vulnerabilities, SQL injection, XSS, and secure coding practices.', 'https://example.com/videos/web-security.mp4'),
        ('Ethical Hacking Basics', 'Learn penetration testing methodologies, tools, and techniques for security assessment.', 'https://example.com/videos/ethical-hacking.mp4'),
        ('Incident Response & Forensics', 'Learn how to respond to security incidents and conduct digital forensics investigations.', 'https://example.com/videos/incident-response.mp4')
    ]
    
    course_ids = []
    for course in courses_data:
        course_id = execute_query(
            "INSERT INTO courses (title, description, video_url) VALUES (%s, %s, %s)",
            course
        )
        course_ids.append(course_id)
        print(f"Inserted course: {course[0]} (ID: {course_id})")
    
    # Insert quizzes
    quizzes_data = [
        (course_ids[0], 'Cybersecurity Basics Quiz', 'Test your knowledge of fundamental cybersecurity concepts'),
        (course_ids[0], 'Security Fundamentals Quiz', 'Assess your understanding of basic security principles'),
        (course_ids[1], 'Network Security Quiz', 'Test your understanding of network security concepts'),
        (course_ids[1], 'Protocol Security Quiz', 'Assess your knowledge of secure protocols'),
        (course_ids[2], 'OWASP Top 10 Quiz', 'Test your knowledge of OWASP Top 10 vulnerabilities'),
        (course_ids[2], 'Web Security Quiz', 'Assess your understanding of web application security')
    ]
    
    quiz_ids = []
    for quiz in quizzes_data:
        quiz_id = execute_query(
            "INSERT INTO quizzes (course_id, title, description) VALUES (%s, %s, %s)",
            quiz
        )
        quiz_ids.append(quiz_id)
        print(f"Inserted quiz: {quiz[1]} (ID: {quiz_id})")
    
    # Insert questions for first quiz
    questions_data = [
        (quiz_ids[0], 'What is the primary goal of cybersecurity?', 'multiple_choice'),
        (quiz_ids[0], 'Which of the following is NOT a common cyber threat?', 'multiple_choice'),
        (quiz_ids[0], 'What does CIA stand for in cybersecurity?', 'multiple_choice'),
        (quiz_ids[0], 'Which of the following is a type of malware?', 'multiple_choice'),
        (quiz_ids[0], 'What is phishing?', 'multiple_choice')
    ]
    
    question_ids = []
    for question in questions_data:
        question_id = execute_query(
            "INSERT INTO questions (quiz_id, question_text, question_type) VALUES (%s, %s, %s)",
            question
        )
        question_ids.append(question_id)
        print(f"Inserted question: {question[1]} (ID: {question_id})")
    
    # Insert options for questions
    options_data = [
        # Question 1 options
        (question_ids[0], 'To protect information systems from theft or damage', True),
        (question_ids[0], 'To make systems faster', False),
        (question_ids[0], 'To reduce costs', False),
        (question_ids[0], 'To improve user experience', False),
        
        # Question 2 options
        (question_ids[1], 'Malware', False),
        (question_ids[1], 'Phishing', False),
        (question_ids[1], 'Solar flares', True),
        (question_ids[1], 'DDoS attacks', False),
        
        # Question 3 options
        (question_ids[2], 'Confidentiality, Integrity, Availability', True),
        (question_ids[2], 'Computer, Internet, Access', False),
        (question_ids[2], 'Cyber, Information, Attack', False),
        (question_ids[2], 'Control, Identity, Authentication', False),
        
        # Question 4 options
        (question_ids[3], 'Virus', True),
        (question_ids[3], 'Firewall', False),
        (question_ids[3], 'Encryption', False),
        (question_ids[3], 'VPN', False),
        
        # Question 5 options
        (question_ids[4], 'A social engineering attack that tricks users into revealing sensitive information', True),
        (question_ids[4], 'A type of firewall', False),
        (question_ids[4], 'A network protocol', False),
        (question_ids[4], 'A security software', False)
    ]
    
    for option in options_data:
        execute_query(
            "INSERT INTO options (question_id, option_text, is_correct) VALUES (%s, %s, %s)",
            option
        )
        print(f"Inserted option: {option[1]} (Correct: {option[2]})")
    
    # Insert sample user progress (assuming user_id 1 exists)
    progress_data = [
        (1, course_ids[0], 0.0, False),
        (1, course_ids[1], 0.3, False),
        (1, course_ids[2], 0.8, False),
        (1, course_ids[3], 1.0, True),
        (1, course_ids[4], 0.0, False)
    ]
    
    for progress in progress_data:
        execute_query(
            "INSERT INTO user_course_progress (user_id, course_id, progress, completed) VALUES (%s, %s, %s, %s)",
            progress
        )
        print(f"Inserted progress for course {progress[1]}: {progress[2]*100}%")
    
    # Update completed course with certificate
    execute_query(
        "UPDATE user_course_progress SET certificate_url = %s, completed_at = NOW() WHERE user_id = %s AND course_id = %s",
        ('https://example.com/certificates/ethical-hacking.pdf', 1, course_ids[3])
    )
    print("Updated completed course with certificate URL")
    
    # Insert sample user documents
    documents_data = [
        (1, 'ID Card', '/uploads/id_card_user1.pdf', 'approved'),
        (1, 'Certificate', '/uploads/certificate_user1.pdf', 'pending'),
        (1, 'Resume', '/uploads/resume_user1.pdf', 'approved')
    ]
    
    for doc in documents_data:
        execute_query(
            "INSERT INTO user_documents (user_id, document_type, file_url, status) VALUES (%s, %s, %s, %s)",
            doc
        )
        print(f"Inserted document: {doc[1]} ({doc[3]})")
    
    print("\nEducation data insertion completed successfully!")
    
    # Show summary
    print("\nData Summary:")
    print(f"Courses: {len(course_ids)}")
    print(f"Quizzes: {len(quiz_ids)}")
    print(f"Questions: {len(question_ids)}")
    print("Options: 20")
    print("User Progress: 5")
    print("User Documents: 3")

if __name__ == "__main__":
    try:
        insert_education_data()
    except Exception as e:
        print(f"Error inserting education data: {e}")
        import traceback
        traceback.print_exc() 