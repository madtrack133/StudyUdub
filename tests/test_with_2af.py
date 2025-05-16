import unittest
import time
import pyotp
import sys
import os

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Add the root path so we can import from the app package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the Flask app and database
from app import app as flask_app, db
from models import Student

# Predefined TOTP secret used for 2FA
secret = "JBSWY3DPEHPK3PXP"
totp = pyotp.TOTP(secret)

class SeleniumStudyUdubTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Runs once before all test methods.
        Sets up the test database and Selenium WebDriver.
        """
        # Configure Flask app for testing
        flask_app.config.update({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",  # in-memory DB
            "LOGIN_DISABLED": False,
        })

        # Create test user in the test database
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

        # Launch Chrome WebDriver
        options = webdriver.ChromeOptions()
        # options.add_argument("--headless")  # Uncomment to run headless
        cls.driver = webdriver.Chrome(options=options)
        cls.driver.implicitly_wait(5)
        cls.base_url = "http://localhost:5001"  # Adjust to your Flask port

    @classmethod
    def tearDownClass(cls):
        """
        Runs once after all test methods.
        Tears down the browser and database.
        """
        cls.driver.quit()
        with flask_app.app_context():
            db.drop_all()

    def login_with_2fa(self):
        """
        Helper function to perform a full login including 2FA.
        Assumes the user is already registered in the test DB.
        """
        self.driver.get(f"{self.base_url}/login")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.NAME, "password").send_keys("Password@123")
        self.driver.find_element(By.XPATH, "//button[@type='submit']").click()

        # Wait until redirected to 2FA verification page
        WebDriverWait(self.driver, 10).until(EC.url_contains("/verify-2fa"))

        # Input the 6-digit TOTP code
        code = totp.now()
        for i, digit in enumerate(code):
            input_elem = self.driver.find_element(By.ID, f"code-{i}")
            input_elem.clear()
            input_elem.send_keys(digit)

        # Wait until dashboard is loaded (auto submit happens via JS)
        WebDriverWait(self.driver, 10).until(EC.url_contains("/dashboard"))

    def test_2fa_verification_works(self):
        """
        Verifies that TOTP 2FA process redirects correctly to dashboard.
        """
        self.driver.get(f"{self.base_url}/login")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.NAME, "password").send_keys("Password@123")
        self.driver.find_element(By.XPATH, "//button[@type='submit']").click()

        WebDriverWait(self.driver, 10).until(EC.url_contains("/verify-2fa"))

        code = totp.now()
        for i, digit in enumerate(code):
            input_elem = self.driver.find_element(By.ID, f"code-{i}")
            input_elem.clear()
            input_elem.send_keys(digit)

        WebDriverWait(self.driver, 10).until(EC.url_contains("/dashboard"))
        self.assertIn("dashboard", self.driver.current_url)

    def test_signup_form_visible(self):
        """
        Checks that the signup form is rendered and contains the expected heading.
        """
        self.driver.get(f"{self.base_url}/signup")
        heading = self.driver.find_element(By.TAG_NAME, "h4").text
        self.assertIn("Sign Up", heading)

    def test_login_page_loads(self):
        """
        Confirms that the login page loads correctly and contains 'Log In'.
        """
        self.driver.get(f"{self.base_url}/login")
        self.assertIn("Log In", self.driver.page_source)

    def test_dashboard_accessible_after_login(self):
        """
        Ensures the dashboard is accessible after logging in with 2FA.
        """
        self.login_with_2fa()
        self.assertIn("dashboard", self.driver.current_url)
        self.assertIn("Welcome", self.driver.page_source)

    def test_file_upload_ui_visible(self):
        """
        Verifies that the file upload form is visible and functional after login.
        """
        self.login_with_2fa()
        self.driver.get(f"{self.base_url}/upload")
        self.assertTrue(self.driver.find_element(By.NAME, "title"))
        self.assertTrue(self.driver.find_element(By.NAME, "file"))

if __name__ == "__main__":
    unittest.main()
