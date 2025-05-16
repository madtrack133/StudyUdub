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
This project requires **Python 3.9.0** to ensure compatibility with all packages.
### 1. Clone the Repository

```bash
git clone https://github.com/madtrack133/StudyUdub.git
cd StudyUdub
```

---

### 2. Create and Activate a Virtual Environment

<details>
<summary><strong>macOS / Linux</strong></summary>

```bash
python3 -m venv venv
source venv/bin/activate
```

</details>

<details>
<summary><strong>Windows</strong></summary>

```cmd
python -m venv venv
venv\Scripts\activate
```

</details>

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Ensure No Existing Database

To avoid migration or schema issues, delete any old database files or migration folders before setup.

<details>
<summary><strong>macOS / Linux</strong></summary>

```bash
rm -f StudyUdub_V2.db
rm -rf migrations/
```

</details>

<details>
<summary><strong>Windows</strong></summary>

```cmd
del StudyUdub_V2.db
rmdir /s /q migrations
```

</details>

---

### 5. Database Setup

```bash
flask db init         # Only if migrations folder doesn't already exist
flask db migrate -m "Initial migration" # Only if migrations folder doesn't already exist
flask db upgrade
```

---

### 6. Running the App

```bash
flask run
```

Visit: http://localhost:5000

---

### 7. Run Unit Tests
In a new terminal:
```bash
pytest
```

---

### Selenium Integration Tests

Selenium tests cover critical user flows such as:

- Signup page rendering
- Login + 2FA verification using PyOTP
- Dashboard and profile access after login
- Upload form functionality and validation


To run the tests:

<details>
<summary><strong>macOS / Linux</strong></summary>

```bash
python3 -m unittest tests/selenium-tests.py
```

</details>

<details>
<summary><strong>Windows</strong></summary>

```cmd
python -m unittest tests/selenium-tests.py
```

</details>

>  **Want to see the browser pop up?**  
> Open `tests/selenium-tests.py` and **comment out** the following line in `setUpClass`:
>
> ```python
> options.add_argument("--headless")  # ← comment this line to view the browser
> ```

---



### Authors: Takumi Iizuka, Venu Soma, Donna Peari, Krishna Modi
