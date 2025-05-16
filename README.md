# StudyUdub
CITS3403 Group Project.

StudyUdub is a secure web application designed to help university students organise and track their academic progress. It allows students to manage courses, upload and share notes, view grade progression, and secure their accounts with two-factor authentication (2FA).

## Features

- User signup, login, and password reset with 2FA
- Upload, download, and share notes with others
- Track and visualise assignment grades per unit
- Manage enrolled courses and view shared materials
- Secure file handling and access control
- Clean dashboard with summaries and charts

## Tech Stack

- Python, Flask
- SQLite (via SQLAlchemy ORM)
- WTForms + Flask-WTF for form validation
- Flask-Login for authentication
- Flask-Mail for email services
- PyOTP and QRCode for 2FA support
- Bootstrap 5 for responsive UI


## Getting Started

### 1. Clone the repository

Clone the project git clone (https://github.com/madtrack133/StudyUdub.git)<br>
cd StudyUdub

### 2. Create and Activate a Virtual Environment

python3 -m venv venv<br>
source venv/bin/activate  # On Windows: venv\Scripts\activate

### 3. Install Dependencies

pip install -r requirements.txt

### 4. Configure Environment Variables

### 5. Database Setup
flask db upgrade

### 6. Running the App
flask run<br>
Visit: http://localhost:5000

### 7. Run Unit Tests
pytest

### Selenium Integration Tests

Selenium tests were implemented to cover critical user flows, including:

- Signup page rendering
- Login + 2FA verification using PyOTP
- Dashboard and profile access after login
- Upload form functionality and validation

#### How we got Selenium working:

- We configured a headless Chrome browser using `webdriver.ChromeOptions()`
- To handle 2FA, we used a static PyOTP secret and passed the current TOTP during the test
- A helper method was created to simulate login and complete the 2FA prompt using 6-digit autofill
- We inserted a temporary test user in an in-memory SQLite database before each test run
- Selenium was used to assert presence of elements, redirection to correct URLs, and visibility of UI components

To run the tests:
```bash
python3 -m unittest tests/selenium-tests.py
```
If you want to see the browser pop up and interact:
- Comment out the `--headless` line in the `setUpClass` method of `selenium-tests.py`.

### Authors: Takumi Iizuka, Venu Soma, Donna Peari, Krishna Modi
