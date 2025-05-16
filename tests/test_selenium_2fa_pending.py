import unittest
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class SeleniumStudyUdubTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")  # comment this out if you want to see the browser
        cls.driver = webdriver.Chrome(options=options)
        cls.driver.implicitly_wait(5)
        cls.base_url = "http://localhost:5000"

    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()

    def login_without_2fa(self):
        self.driver.get(f"{self.base_url}/test-login")
        self.driver.find_element(By.NAME, "email").send_keys("testuser@example.com")
        self.driver.find_element(By.XPATH, "//button[@type='submit']").click()
        WebDriverWait(self.driver, 10).until(EC.url_contains("dashboard"))

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
