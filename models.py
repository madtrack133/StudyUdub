from flask_sqlalchemy import SQLAlchemy
<<<<<<< HEAD
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
=======
from sqlalchemy import CheckConstraint, UniqueConstraint
from datetime import datetime

# Initialize SQLAlchemy
db = SQLAlchemy()

class Student(db.Model):
    __tablename__ = 'Student'
    StudentID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    FirstName = db.Column(db.Text, nullable=False)
    LastName = db.Column(db.Text, nullable=False)
    Email = db.Column(db.String(100), unique=True)
    Password = db.Column(db.String(255), nullable=False)
    Otp_Code = db.Column(db.String(10))
    Otp_Expiry = db.Column(db.DateTime)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    courses = db.relationship('Course', secondary='StudentCourse', back_populates='students')
    assignments = db.relationship('Assignment', back_populates='student', cascade='all, delete-orphan')
    notes = db.relationship('Notes', back_populates='student', cascade='all, delete-orphan')
    shares_owned = db.relationship('Share', foreign_keys='Share.OwnerStudentID', back_populates='owner', cascade='all, delete-orphan')
    shares_received = db.relationship('Share', foreign_keys='Share.AccesseeStudentID', back_populates='accessee', cascade='all, delete-orphan')

class Course(db.Model):
    __tablename__ = 'Course'
    CourseID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    UnitCode = db.Column(db.String(20), unique=True, nullable=False)
    CourseName = db.Column(db.String(100), nullable=False)
    CreditPoints = db.Column(db.Integer, nullable=False)

    students = db.relationship('Student', secondary='StudentCourse', back_populates='courses')
    assignments = db.relationship('Assignment', back_populates='course', cascade='all, delete-orphan')
    notes = db.relationship('Notes', back_populates='course', cascade='all, delete-orphan')

class StudentCourse(db.Model):
    __tablename__ = 'StudentCourse'
    StudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID', ondelete='CASCADE'), primary_key=True)
    CourseID = db.Column(db.Integer, db.ForeignKey('Course.CourseID', ondelete='CASCADE'), primary_key=True)
    EnrollmentDate = db.Column(db.Date, nullable=True)

class Assignment(db.Model):
    __tablename__ = 'Assignment'
    AssignmentID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CourseID = db.Column(db.Integer, db.ForeignKey('Course.CourseID', ondelete='CASCADE'))
    StudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID', ondelete='CASCADE'))
    AssignmentName = db.Column(db.Text, nullable=False)
    FilePath = db.Column(db.Text, nullable=False)
    HoursSpent = db.Column(db.Float)
    Weight = db.Column(db.Float)
    MarksAchieved = db.Column(db.Float)
    MarksOutOf = db.Column(db.Float)
    DueDate = db.Column(db.Date, nullable=False)

    __table_args__ = (
        CheckConstraint("FilePath LIKE '/secure_uploads/%/_%.%'"
                        " AND length(substr(FilePath, 17, 64)) = 64"
                        " AND substr(FilePath, 17, 64) NOT LIKE '%/%'"
                        " AND (substr(FilePath, -3, 3) = '.md'"
                        " OR substr(FilePath, -4, 4) IN ('.pdf', '.txt')"
                        " OR substr(FilePath, -5, 5) = '.docx')",
                        name='assignment_filepath_check'),
        CheckConstraint('Weight BETWEEN 0 AND 100', name='assignment_weight_check'),
        CheckConstraint('MarksOutOf > 0', name='assignment_marksoutof_check'),
        CheckConstraint('MarksAchieved BETWEEN 0 AND MarksOutOf', name='assignment_marksachieved_check'),
    )

    course = db.relationship('Course', back_populates='assignments')
    student = db.relationship('Student', back_populates='assignments')

class Notes(db.Model):
    __tablename__ = 'Notes'
    NoteID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    StudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID', ondelete='CASCADE'), nullable=False)
    CourseID = db.Column(db.Integer, db.ForeignKey('Course.CourseID', ondelete='SET NULL'), nullable=True)
    Title = db.Column(db.Text)
    Category = db.Column(db.Text)
    Description = db.Column(db.Text)
    FilePath = db.Column(db.Text, nullable=False)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        CheckConstraint("FilePath LIKE '/secure_notes/%/_%.%'"
                        " AND length(substr(FilePath, 15, 64)) = 64"
                        " AND substr(FilePath, 15, 64) NOT LIKE '%/%'"
                        " AND (substr(FilePath, -3, 3) = '.md'"
                        " OR substr(FilePath, -4, 4) IN ('.pdf', '.txt')"
                        " OR substr(FilePath, -5, 5) = '.docx')",
                        name='notes_filepath_check'),
        CheckConstraint("Category IN ('Lecture', 'Tutorial', 'Lab', 'Exam', 'Other')", name='notes_category_check'),
    )

    student = db.relationship('Student', back_populates='notes')
    course = db.relationship('Course', back_populates='notes')
    shares = db.relationship('Share', back_populates='note', cascade='all, delete-orphan')

class Share(db.Model):
    __tablename__ = 'Share'
    ShareID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    NoteID = db.Column(db.Integer, db.ForeignKey('Notes.NoteID', ondelete='CASCADE'), nullable=False)
    OwnerStudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID', ondelete='CASCADE'), nullable=False)
    AccesseeStudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID', ondelete='CASCADE'), nullable=False)
    EditPower = db.Column(db.Integer)

    __table_args__ = (
        UniqueConstraint('NoteID', 'AccesseeStudentID', name='share_unique_note_accessee'),
    )

    note = db.relationship('Notes', back_populates='shares')
    owner = db.relationship('Student', foreign_keys=[OwnerStudentID], back_populates='shares_owned')
    accessee = db.relationship('Student', foreign_keys=[AccesseeStudentID], back_populates='shares_received')
>>>>>>> database
