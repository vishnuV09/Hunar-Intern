# 🔐 Password Strength Analyzer & Generator

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/framework-Flask%20%7C%20Rich-indigo.svg)](#)

A comprehensive Python application designed to analyze password security, calculate Shannon entropy, estimate brute-force crack time, detect structural flaws, and generate cryptographically secure passwords. 

Features both an **Interactive Command-Line Interface (CLI)** and a **Sleek Web Dashboard**.

---

## 🌟 Key Features

- **Rating System**: Classifies passwords into **Weak**, **Okay**, **Strong**, or **Very Strong** with a numerical score ($0 - 100$).
- **Multi-Factor Analysis**:
  - **Length Score**: Evaluates length boundaries ($<8$ severe penalty, $8-11$ okay, $12-15$ strong, $16+$ very strong).
  - **Character Diversity**: Checks for uppercase, lowercase, numbers, and special symbols (`!@#$%^&*()_+-=[]{}|;:,.<>?`).
  - **Pattern & Flaw Detection**: Scans for sequential keys (`qwerty`, `12345`), repeated characters (`aaaa`, `1111`), and numbers/letters-only patterns.
  - **Compromised Password Dictionary**: Instant matching against a built-in dataset of top leaked/weak passwords (`123456`, `password`, `admin`, etc.).
- **Shannon Entropy Calculation**: Computes mathematical entropy $E = L \times \log_2(R)$ in bits.
- **Brute-Force Crack Time Estimator**: Calculates time to crack assuming an offline GPU cluster rate of $10,000,000,000$ ($10^{10}$) guesses/second.
- **Actionable Advice**: Provides real-time recommendations to upgrade weak passwords.
- **Secure Password Generator**: Uses Python's `secrets` module for cryptographically secure random password generation.

---

## 📂 Project Structure

```text
password_strength_checker/
├── app.py                  # Flask Web Application backend & REST API endpoints
├── cli.py                  # Rich-formatted interactive terminal CLI tool
├── common_passwords.py     # Leaked passwords dataset & pattern matching definitions
├── main.py                 # Unified launcher script (CLI & Web modes)
├── password_checker.py     # Core PasswordAnalyzer engine, math, & password generator
├── test_password_checker.py# Unit tests for scoring logic, entropy, & generator
├── README.md               # Complete documentation
├── static/
│   └── style.css           # Glassmorphism dark-theme CSS design system
└── templates/
    └── index.html          # Web dashboard frontend template
```

---

## 🚀 Quick Start & Usage

### Prerequisites
Make sure Python 3.10+ is installed along with required packages:
```bash
pip install flask rich
```

---

### 1. Web Dashboard (Flask GUI)
Launch the web interface:
```bash
python main.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your web browser.

#### Web Dashboard Highlights:
- **Real-Time Evaluation**: As you type, the strength score, crack time, entropy, and checklist update instantly.
- **Password Visibility Toggle**: Show or hide the password input using the eye icon.
- **Password Generator**: Custom length slider ($12 - 32$ chars) with a $1$-click copy-to-clipboard button.

---

### 2. Interactive CLI Mode
Run the terminal app:
```bash
python main.py --cli
```
Or check a specific password directly from command-line arguments:
```bash
python cli.py "P@ssw0rd2026!Secure"
```

---

### 3. Run Automated Unit Tests
Verify the analysis engine using Python's built-in `unittest` runner:
```bash
python test_password_checker.py
```

---

## 📊 Scoring Rubric & Metrics

| Rating | Score Range | Description |
| :--- | :---: | :--- |
| **Weak** | 0 – 39 | Less than 8 characters, common leaked password, or lacks variety. Easily crackable. |
| **Okay** | 40 – 69 | Moderate length ($8-11$ chars) with basic character variety. Vulnerable to targeted attacks. |
| **Strong** | 70 – 89 | $12+$ characters with mixed uppercase, lowercase, numbers, and symbols. High entropy. |
| **Very Strong** | 90 – 100 | $16+$ characters with full character set diversity and no structural patterns. |

---

## 🔌 REST API Reference

The Flask server exposes REST API endpoints for integration:

### `POST /api/analyze`
**Request Body**:
```json
{
  "password": "P@ssw0rd2026!Secure"
}
```
**Response**:
```json
{
  "password": "P@ssw0rd2026!Secure",
  "length": 19,
  "score": 100,
  "rating": "Very Strong",
  "color": "#10b981",
  "entropy": 124.5,
  "crack_time": "48,931,960,422,716 million years",
  "criteria": {
    "has_lowercase": true,
    "has_uppercase": true,
    "has_digits": true,
    "has_symbols": true,
    "min_length_8": true,
    "min_length_12": true,
    "no_common_patterns": true,
    "no_repeats": true
  },
  "flaws": [],
  "suggestions": [
    "Great job! Your password meets all strong security recommendations."
  ]
}
```

### `POST /api/generate`
**Request Body**:
```json
{
  "length": 16,
  "include_symbols": true
}
```

---

## 📜 License
This project is open-source and available under the [MIT License](LICENSE).
