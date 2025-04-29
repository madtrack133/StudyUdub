from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

from datetime import datetime

class Student(db.Model, UserMixin):
    __tablename__ = 'Student'
    StudentID = db.Column(db.Integer, primary_key=True)
    FirstName = db.Column(db.String(50), nullable=False)
    LastName = db.Column(db.String(50), nullable=False)
    Email = db.Column(db.String(100), unique=True)
    Password = db.Column(db.String(255), nullable=False)
    Otp_Code = db.Column(db.String(10))
    Otp_Expiry = db.Column(db.DateTime)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.Password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.Password, password)

class Class(db.Model):
    __tablename__ = 'Class'
    ClassID = db.Column(db.Integer, primary_key=True)
    UnitCode = db.Column(db.String(20), unique=True, nullable=False)
    ClassName = db.Column(db.String(100), nullable=False)
    CreditPoints = db.Column(db.Integer, nullable=False)

class StudentClass(db.Model):
    __tablename__ = 'StudentClass'
    StudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID'), primary_key=True)
    ClassID = db.Column(db.Integer, db.ForeignKey('Class.ClassID'), primary_key=True)
    EnrollmentDate = db.Column(db.Date, nullable=False)

class Assignment(db.Model):
    __tablename__ = 'Assignment'
    AssignmentID = db.Column(db.Integer, primary_key=True)
    ClassID = db.Column(db.Integer, db.ForeignKey('Class.ClassID'))
    StudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID'))
    AssignmentName = db.Column(db.String(100), nullable=False)
    FilePath = db.Column(db.String(255), nullable=False)
    HoursSpent = db.Column(db.Numeric(5,2))
    Score = db.Column(db.Numeric(5,2))
    Weight = db.Column(db.Numeric(5,2))
    DueDate = db.Column(db.Date, nullable=False)

class Notes(db.Model):
    __tablename__ = 'Notes'
    NoteID = db.Column(db.Integer, primary_key=True)
    StudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID'))
    ClassID = db.Column(db.Integer, db.ForeignKey('Class.ClassID'))
    Title = db.Column(db.String(255))
    FilePath = db.Column(db.String(255), nullable=False)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)

class Share(db.Model):
    __tablename__ = 'Share'
    ShareID = db.Column(db.Integer, primary_key=True)
    OwnerStudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID'))
    AccesseeStudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID'))
    EditPower = db.Column(db.Boolean)
