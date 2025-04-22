from dotenv import load_dotenv
import os

load_dotenv()  # Load variables from .env into environment

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    # 🗂️ Database config
    SQLALCHEMY_DATABASE_URI = 'sqlite:///StudyUdub_V1.1.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 📧 Flask-Mail Gmail SMTP settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')   # ✅ your Gmail App Password (not your real password)

    # Optional: Default sender (used if you forget to specify in Message())
    MAIL_DEFAULT_SENDER = MAIL_USERNAME
    
    # Two-Factor Authentication (TOTP) settings
    # Issuer name shown in authenticator apps
    TWOFA_ISSUER_NAME = os.getenv('TWOFA_ISSUER_NAME', 'StudyUdub')