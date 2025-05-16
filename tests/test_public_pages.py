import unittest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

class SeleniumPublicPagesTest(unittest.TestCase):

    def setUp(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")  # Run headless
        self.driver = webdriver.Chrome(options=chrome_options)
        self.driver.get("http://127.0.0.1:5000/")

    def tearDown(self):
        self.driver.quit()

    def test_home_page_loads(self):
        self.assertIn("StudyUdub", self.driver.page_source)

    def test_signup_page_accessible(self):
        self.driver.get("http://127.0.0.1:5000/signup")
        self.assertIn("Sign Up", self.driver.page_source)

    def test_login_page_accessible(self):
        self.driver.get("http://127.0.0.1:5000/login")
        self.assertIn("Log In", self.driver.page_source)

    def test_signup_button_present(self):
        self.driver.get("http://127.0.0.1:5000/signup")
        button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        self.assertTrue(button.is_displayed())

    def test_login_button_present(self):
        self.driver.get("http://127.0.0.1:5000/login")
        button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        self.assertTrue(button.is_displayed())


if __name__ == "__main__":
    unittest.main()
