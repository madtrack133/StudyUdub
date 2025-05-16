import unittest
import time
import pyotp
import sys
import os

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# モジュールのルートパスを追加
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Flask アプリと DB をインポート
from app import app as flask_app, db
from models import Student

# OTP 設定
secret = "JBSWY3DPEHPK3PXP"
totp = pyotp.TOTP(secret)


class SeleniumStudyUdubTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # --- Flask アプリケーション設定 ---
        flask_app.config.update({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "LOGIN_DISABLED": False,
        })

        # --- DBとユーザー作成 ---
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

        # --- Selenium ドライバ起動 ---
        options = webdriver.ChromeOptions()
        # options.add_argument("--headless")  # 必要に応じてコメントアウト
        cls.driver = webdriver.Chrome(options=options)
        cls.driver.implicitly_wait(5)
        cls.base_url = "http://localhost:5001"

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()
        with flask_app.app_context():
            db.drop_all()
            
    def login_without_2fa(self):
        self.driver.get(f"{self.base_url}/login")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.NAME, "password").send_keys("Password@123")
        self.driver.find_element(By.XPATH, "//button[@type='submit']").click()
        WebDriverWait(self.driver, 10).until(EC.url_contains("/verify-2fa"))

        # input code
        code = totp.now()
        for i, digit in enumerate(code):
            input_elem = self.driver.find_element(By.ID, f"code-{i}")
            input_elem.clear()
            input_elem.send_keys(digit)

        WebDriverWait(self.driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//button[@type='submit' and @value='verify']"))
        ).click()
        WebDriverWait(self.driver, 10).until(EC.url_contains("/dashboard"))


    def test_2fa_verification_works(self):
        # 1. ログインフェーズ
        self.driver.get(f"{self.base_url}/login")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.NAME, "password").send_keys("Password@123")
        self.driver.find_element(By.XPATH, "//button[@type='submit']").click()

        # 2. 2FA ページに遷移したことを確認
        WebDriverWait(self.driver, 10).until(EC.url_contains("/verify-2fa"))

        # 3. 現在のTOTPコードを取得し、各桁を分割
        code = totp.now()
        assert len(code) == 6

        # 4. 各 input フィールドに1桁ずつ送信
        for i, digit in enumerate(code):
            input_elem = self.driver.find_element(By.ID, f"code-{i}")
            input_elem.clear()
            input_elem.send_keys(digit)

        # 5. Verifyボタンをクリック
        self.driver.find_element(By.XPATH, "//button[@type='submit' and @value='verify']").click()

        # 6. 認証後に dashboard にリダイレクトされたことを検証
        WebDriverWait(self.driver, 10).until(EC.url_contains("/dashboard"))
        self.assertIn("dashboard", self.driver.current_url)

    def test_signup_form_visible(self):
        self.driver.get(f"{self.base_url}/signup")
        heading = self.driver.find_element(By.TAG_NAME, "h4").text
        self.assertIn("Sign Up", heading)

    def test_login_page_loads(self):
        self.driver.get(f"{self.base_url}/login")
        self.assertIn("Log In", self.driver.page_source)

    def test_dashboard_accessible_after_login(self):
        self.login_without_2fa()
        self.assertIn("dashboard", self.driver.current_url)
        self.assertIn("Welcome", self.driver.page_source)

    def test_file_upload_ui_visible(self):
        self.login_without_2fa()
        self.driver.get(f"{self.base_url}/upload")
        self.assertTrue(self.driver.find_element(By.NAME, "title"))
        self.assertTrue(self.driver.find_element(By.NAME, "file"))

    def test_add_deadline_button_visible(self):
        self.login_without_2fa()
        self.driver.get(f"{self.base_url}/deadlines")
        add_btn = self.driver.find_element(By.XPATH, "//button[contains(text(), 'Add Deadline')]")
        self.assertTrue(add_btn)


if __name__ == "__main__":
    unittest.main()
