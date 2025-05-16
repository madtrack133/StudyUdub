import unittest
import time
import pyotp
import sys
import os

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import app and db
from app import app as flask_app, db
from models import Student

# TOTP Secret setup
secret = "JBSWY3DPEHPK3PXP"
totp = pyotp.TOTP(secret)


class SeleniumStudyUdubTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Configure Flask app for testing
        flask_app.config.update({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "LOGIN_DISABLED": False,
        })

        # Set up DB and test user
        with flask_app.app_context():
            db.create_all()
            user = Student.query.filter_by(Email="testuser@example.com").first()
            if not user:
                user = Student(
                    Email="testuser@example.com",
                    FirstName="Test",
                    LastName="User",
                    UniStudentID="12345678",
                    totp_secret=secret
                )
                user.set_password("Password@123")
                db.session.add(user)
                db.session.commit()

        # Launch browser
        options = webdriver.ChromeOptions()
        # Comment the next line to show Chrome UI
        # options.add_argument("--headless")
        cls.driver = webdriver.Chrome(options=options)
        cls.driver.implicitly_wait(5)
        cls.base_url = "http://127.0.0.1:5000"

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()
        with flask_app.app_context():
            db.drop_all()

    def login_with_2fa(self):
        self.driver.get(f"{self.base_url}/login")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.NAME, "password").send_keys("Password@123")
        self.driver.find_element(By.XPATH, "//button[@type='submit']").click()

        WebDriverWait(self.driver, 10).until(EC.url_contains("/verify-2fa"))
        code = totp.now()
        for i, digit in enumerate(code):
            self.driver.find_element(By.ID, f"code-{i}").send_keys(digit)
        self.driver.find_element(By.XPATH, "//button[@value='verify']").click()
        WebDriverWait(self.driver, 10).until(EC.url_contains("/dashboard"))

    def test_signup_form_visible(self):
        self.driver.get(f"{self.base_url}/signup")
        heading = self.driver.find_element(By.TAG_NAME, "h4").text
        self.assertIn("Sign Up", heading)

    def test_login_page_loads(self):
        self.driver.get(f"{self.base_url}/login")
        self.assertIn("Log In", self.driver.page_source)

    def test_2fa_verification_works(self):
        self.login_with_2fa()
        self.assertIn("dashboard", self.driver.current_url)

    def test_file_upload_ui_visible(self):
        self.login_with_2fa()
        self.driver.get(f"{self.base_url}/upload")
        self.assertTrue(self.driver.find_element(By.NAME, "title"))

  


if __name__ == "__main__":
    unittest.main()
