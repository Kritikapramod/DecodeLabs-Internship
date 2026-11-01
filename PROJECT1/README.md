# Password Strength Checker

An educational web application that evaluates how strong a password is and classifies it as **Weak**, **Medium** or **Strong**. It was built for the **DecodeLabs Cyber Security Internship (Project 1)** to practise string handling, character classification, input validation and conditional logic.

> This is a learning project. It gives a rough estimate based on a few simple rules and is **not** a complete password-security audit. Do not type real passwords into a demonstration app you have not reviewed yourself.

## Features

- Classifies a password as Weak, Medium or Strong using a transparent 5-point score.
- Checks four requirements: at least 8 characters, an uppercase letter, a number, and a special character.
- Shows a strength bar, a result label, and a pass/fail checklist for the four requirements.
- Gives suggestions for improving a password (for example "Add a number (0-9)").
- Rejects passwords that appear in a small built-in list of 19 very common passwords (case-insensitive exact match).
- Detects repeated characters (such as `aaa`) and simple sequences (such as `abc` or `123`).
- Show/Hide toggle for the password field, a Clear button, and Enter-key support.
- Handles empty input and an input limit of 256 characters, with error handling for invalid requests.
- Includes a short educational section on why length and variety matter.
- Responsive layout (CSS media queries) with a dark theme.
- Unit tests for the evaluation logic (see [Testing](#testing)).

## Technologies Used

| Part | Technology |
|---|---|
| Password evaluation logic | Python 3 (standard library only) |
| Local web server | Python `http.server` module |
| Interface | HTML5, CSS3, JavaScript (no frameworks or libraries) |
| Tests | Python `unittest` |

**Requirements:** Python 3 only. There are no packages to install, no database, no external APIs, and no internet connection is needed (the page uses system fonts and loads nothing from external sites).

**Where the logic runs:** The password is scored by **Python**, not by browser JavaScript. The browser sends the password to the server running on your own computer (`127.0.0.1`, port 8000) and receives the result. The JavaScript only handles the interface: show/hide, clear, and drawing the results.

## Project Structure

```text
password-strength-checker/
├── app.py                        # Local web server and the /api/check endpoint
├── password_checker.py           # Password evaluation logic (scoring rules)
├── static/
│   ├── index.html                # Page structure
│   ├── style.css                 # Styling and responsive layout
│   └── script.js                 # Interface behaviour; sends the password to the local server
├── tests/
│   └── test_password_checker.py  # Unit tests for the evaluation logic
└── README.md                     # This file
```

## How to Run on Windows

1. Install Python 3 from [python.org](https://www.python.org/downloads/) and tick **Add Python to PATH** during installation.
2. Download or extract the project folder.
3. Open a terminal (Command Prompt or PowerShell) in the project folder, where `app.py` is located.
4. Start the server:

   ```bash
   python app.py
   ```

   If `python` is not recognised, try `py app.py`.
5. Open **http://127.0.0.1:8000** in a modern web browser.
6. Type a password, then click **Check Strength** (or press Enter). Use **Show/Hide** to reveal the text and **Clear** to empty the field and hide the results.
7. Press `Ctrl+C` in the terminal to stop the server.

**Important:** open the app through the address above. If you double-click `static/index.html`, the styling will load but checking will not work, because the page needs the Python server. The page shows a warning in that case.

There is also a command-line mode with hidden input:

```bash
python password_checker.py
```

## How It Works

The function `evaluate_password()` in `password_checker.py` reads the password exactly as entered. It is **never trimmed or modified**, so spaces count as characters.

### Checks

| Check | How it is detected |
|---|---|
| Length | `len(password) >= 8` |
| Uppercase | Any character where `isupper()` is true |
| Number | Any character where `isdigit()` is true |
| Special character | Any character that is **not** a letter or digit (`not isalnum()`), so spaces count as special |

### Scoring (maximum 5 points)

- **+1** for each of the four checks above that passes (length, uppercase, number, special).
- **+1 bonus** if the password is 12 characters or longer.
- **-1 penalty** if it contains a repeated run (3 identical characters in a row) or a sequence of 3 consecutive characters (such as `abc`, `cba`, `123`).
- The score never goes below 0.

### Classification

| Result | Rule |
|---|---|
| **Empty** | Nothing was entered. The page asks the user to type a password. |
| **Weak** | Shorter than 8 characters, **or** in the common-password list, **or** score below 3 |
| **Medium** | At least 8 characters, not a common password, and not Strong |
| **Strong** | At least 12 characters, **all four** checks pass, and no pattern penalty (score 5) |

A password shorter than 8 characters is always Weak, however many character types it contains. Only 12+ character passwords can be Strong.

## Testing

### Automated tests

The project includes unit tests in `tests/test_password_checker.py`. Run them from the project folder:

```bash
python tests\test_password_checker.py
```

The file covers the eight categories below, plus checks that the password is not trimmed, that the result does not contain the password, and that invalid input is rejected.

### Test cases

"Expected result" is what the code's rules produce. The **Automated test** column shows whether the case is in the unit-test file.

| Test case | Example (test data only) | Expected result | Automated test |
|---|---|---|---|
| Empty password | *(nothing)* | Result "Empty", prompt to type a password | Yes |
| Very short password | `aB3$` | Weak (under 8 characters, even with 3 character types) | Yes |
| Lowercase letters only | `sunshinefarm` | Weak (only the length check passes; score 2) | Yes |
| Uppercase letters and numbers | `Mango2024Fruit` | Medium (no special character; score 4) | Yes |
| Uppercase, numbers and symbols | `Gx7!kQ2m` | Medium (all checks pass, but only 8 characters; score 4) | Yes |
| Same types, but 7 characters | `Gx7!kQ2` | Weak (below the 8-character minimum) | Yes |
| Long password, mixed types | `Blue#Tiger47-Rides` | Strong (18 characters, all checks pass; score 5) | Yes |
| Password containing spaces | `Blue Tiger 47 Rides` | Strong (spaces count as special characters and are not trimmed) | Yes |
| Repeated characters | `Aaaa1111!!!!` | Medium (pattern penalty lowers the score from 5 to 4) | Yes |
| Common password | `Password123` | Weak (in the common-password list) | Yes |
| Whitespace only | 8 spaces | Weak (evaluated as entered; score 1) | Yes |

### Verified results

- The unit-test file was executed with Python 3.12.3 on Linux: **4 tests ran and all passed**. These tests check the eleven cases above.
- The local server was started and the `/api/check` endpoint, page loading, and rejection of invalid input were checked in a headless Chromium browser during development.
- These tests have **not** been run on Windows. Run the command above on your own machine to confirm.

## Security Considerations and Limitations

**Privacy design (as implemented in the code):**

- The password is sent only to the server on your own computer (`127.0.0.1`), which refuses connections from other machines on the network.
- The code does not write passwords to files, databases or browser storage, does not print them, and does not send them to external services. Request logging in the server is disabled.
- The result shown on the page never repeats the password.
- The project does not *intentionally* store or log passwords, but this is an educational app and has had no formal security review.

**Limitations:**

- A strength estimate does not guarantee a password is safe. It only reflects a few simple rules.
- The common-password list has just 19 entries. The checker cannot detect passwords from real data breaches.
- It does not measure true entropy or check dictionary words, keyboard patterns (such as `qwerty` beyond the list), or personal information.
- A long password using only lowercase letters (for example a passphrase) scores low, even though length helps security.
- Uppercase and number detection use Python's Unicode-aware methods, so letters and digits from other alphabets also count.
- Python strings cannot be overwritten in memory, so a password may remain in memory until it is garbage collected.
- It is not a substitute for unique passwords, a password manager and multi-factor authentication.

## Learning Outcomes

- **String handling:** iterating over characters and measuring length.
- **Character classification:** `isupper()`, `isdigit()`, `isalnum()` with `any()`.
- **Conditional logic:** `if`/`elif` rules and logical operators (`and`, `or`) to turn a score into a classification.
- **Input validation:** handling empty input, maximum length, wrong data types and malformed requests.
- **Security basics:** why length and variety matter, risks of common passwords and predictable patterns, and not storing or logging sensitive input.
- **Separation of concerns:** evaluation logic (`password_checker.py`) is kept apart from the server (`app.py`) and the interface (`static/`), which makes the logic easy to unit test.
- **Web basics:** a small HTTP server with a JSON endpoint, and a responsive HTML/CSS/JavaScript interface.

## Author and Internship

**DecodeLabs Cyber Security Internship, Project 1.**

This project demonstrates basic password-strength evaluation and fundamental cybersecurity concepts. It was created as an internship exercise and is not an official DecodeLabs product.
