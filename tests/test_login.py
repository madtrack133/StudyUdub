import unittest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import os
import time

class StudyUdubUITest(unittest.TestCase):

    def setUp(self):
        options = webdriver.ChromeOptions()
        options.add_argument("--headless=new")
        self.driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        self.driver.get("http://127.0.0.1:5000")
        self.wait = WebDriverWait(self.driver, 10)

    def tearDown(self):
        self.driver.quit()

    def test_01_login_page_loads(self):
        self.driver.get("http://127.0.0.1:5000/login")
        self.assertIn("Log In", self.driver.page_source)

    def test_02_invalid_login(self):
        self.driver.get("http://127.0.0.1:5000/login")
        self.driver.find_element(By.NAME, "email").send_keys("fakeuser@example.com")
        self.driver.find_element(By.NAME, "password").send_keys("wrongpassword")
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        self.assertIn("Invalid", self.driver.page_source)

    def test_03_signup_form(self):
        self.driver.get("http://127.0.0.1:5000/signup")
        self.driver.find_element(By.NAME, "uniStudentID").send_keys("12345678")
        self.driver.find_element(By.NAME, "first_name").send_keys("Test")
        self.driver.find_element(By.NAME, "last_name").send_keys("User")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.NAME, "password").send_keys("Password@123")
        self.driver.find_element(By.NAME, "confirm_password").send_keys("Password@123")
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        self.wait.until(EC.url_contains("login"))
        self.assertIn("Log In", self.driver.page_source)

    def test_04_file_upload(self):
        self.login_user()
        self.driver.get("http://127.0.0.1:5000/upload")
        self.wait.until(EC.presence_of_element_located((By.NAME, "title"))).send_keys("Dummy File")
        file_input = self.driver.find_element(By.NAME, "file")
        file_path = os.path.abspath("tests/dummy.txt")
        file_input.send_keys(file_path)
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        time.sleep(1)
        self.assertIn("successfully", self.driver.page_source.lower())

    def test_05_add_grade(self):
        self.login_user()
        self.driver.get("http://127.0.0.1:5000/grades")
        self.wait.until(EC.presence_of_element_located((By.NAME, "unit"))).send_keys("CITS3002")
        self.driver.find_element(By.NAME, "mark").send_keys("85")
        self.driver.find_element(By.NAME, "weight").send_keys("30")
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        time.sleep(1)
        self.assertIn("CITS3002", self.driver.page_source)

    def login_user(self):
        self.driver.get("http://127.0.0.1:5000/login")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.NAME, "password").send_keys("Password@123")
        self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        self.wait.until(EC.presence_of_element_located((By.CLASS_NAME, "dashboard")))

if __name__ == "__main__":
    unittest.main()
