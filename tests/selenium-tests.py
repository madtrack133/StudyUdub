import unittest
import time
import pyotp
import sys
import os

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Add project root directory to Python path to allow imports from app
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import Flask app and database
from app import app as flask_app, db
from models import Student

# Static TOTP secret used for 2FA code generation
secret = "JBSWY3DPEHPK3PXP"
totp = pyotp.TOTP(secret)

class SeleniumStudyUdubTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Configure Flask app for testing
        flask_app.config.update({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",  # Use in-memory DB for fast test execution
            "LOGIN_DISABLED": False,
        })

        # Set up database and test user
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
                user.set_password("Passwod@123")  # Assign secure password
                db.session.add(user)
                db.session.commit()

        # Initialize Chrome WebDriver
        options = webdriver.ChromeOptions()
        # Uncomment the following line to run without opening browser window
        # options.add_argument("--headless")
        cls.driver = webdriver.Chrome(options=options)
        cls.driver.implicitly_wait(5)  # Implicit wait for element finding
        cls.base_url = "http://127.0.0.1:5000"  # Base URL of the running Flask app

    @classmethod
    def tearDownClass(cls):
        # Close browser and drop all tables after tests
        cls.driver.quit()
        with flask_app.app_context():
            db.drop_all()

    def login_with_2fa(self):
        # Navigate to login page
        self.driver.get(f"{self.base_url}/login")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.NAME, "password").send_keys("Passwod@123")
        self.driver.find_element(By.XPATH, "//button[@type='submit']").click()

        # Wait until redirected to 2FA page
        WebDriverWait(self.driver, 10).until(EC.url_contains("/verify-2fa"))

        # Fill in 2FA TOTP code
        code = totp.now()
        for i, digit in enumerate(code):
            self.driver.find_element(By.ID, f"code-{i}").send_keys(digit)

        # Submit verification and wait for dashboard
        #self.driver.find_element(By.XPATH, "//button[@value='verify']").click()
        WebDriverWait(self.driver, 10).until(EC.url_contains("/dashboard"))

    def test_signup_form_visible(self):
        # Check if signup page displays the correct heading
        self.driver.get(f"{self.base_url}/signup")
        heading = self.driver.find_element(By.TAG_NAME, "h4").text
        self.assertIn("Sign Up", heading)

    def test_login_page_loads(self):
        # Ensure login page loads with expected content
        self.driver.get(f"{self.base_url}/login")
        self.assertIn("Log In", self.driver.page_source)

    def test_2fa_verification_works(self):
        # Full login flow with 2FA and check for dashboard access
        self.login_with_2fa()
        self.assertIn("dashboard", self.driver.current_url)

    def test_file_upload_ui_visible(self):
        # Access upload page and check if 'title' field is visible
        self.login_with_2fa()
        self.driver.get(f"{self.base_url}/upload")
        self.assertTrue(self.driver.find_element(By.NAME, "title"))

    def test_profile_page_heading_visible(self):
        # Go to profile page and check if expected heading is present
        self.login_with_2fa()
        self.driver.get(f"{self.base_url}/profile")
        heading = self.driver.find_element(By.TAG_NAME, "h4").text
        self.assertIn("StudyUdub", heading)

    def test_upload_form_requires_fields(self):
        # Try submitting empty upload form and ensure it stays on upload page
        self.login_with_2fa()
        self.driver.get(f"{self.base_url}/upload")
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        current_url = self.driver.current_url
        self.assertIn("/upload", current_url)

if __name__ == "__main__":
    unittest.main()
