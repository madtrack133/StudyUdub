# config.py

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'studyudub-fallback-secret'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///StudyUdub_V2.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Optional Mail settings (used for reset emails)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'your-email@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'your-email-password'
