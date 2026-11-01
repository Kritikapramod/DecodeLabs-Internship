"""Password evaluation logic (pure Python, standard library only).

SCORING (max 5 points)
  +1 length >= 8        +1 has uppercase letter
  +1 has digit          +1 has special character (anything not letter/digit, spaces included)
  +1 bonus: length >= 12
  -1 penalty if the password has a repeated run (aaa) or a sequence (abc / 123)

CLASSIFICATION
  Weak   : empty, shorter than 8, a common password, or score < 3
  Medium : length >= 8 and score 3 or 4
  Strong : length >= 12, all four character checks, no penalty (score 5)
The password is never trimmed, modified, logged, or stored.
"""

MIN_LENGTH = 8
STRONG_LENGTH = 12
MAX_LENGTH = 256  # sanity limit on input size

# Tiny educational list of well-known weak passwords (not real user data).
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "abc123", "letmein", "welcome", "admin", "iloveyou",
    "111111", "000000", "passw0rd", "p@ssw0rd", "monkey", "dragon",
}


def has_repeated_run(password, run_length=3):
    """True if the same character appears run_length times in a row."""
    count = 1
    for previous, current in zip(password, password[1:]):
        count = count + 1 if current == previous else 1
        if count >= run_length:
            return True
    return False


def has_sequence(password, seq_length=3):
    """True if characters step up by 1 (abc, 123) or down by 1 (cba, 321)."""
    text = password.lower()
    for i in range(len(text) - seq_length + 1):
        steps = [ord(text[i + j + 1]) - ord(text[i + j]) for j in range(seq_length - 1)]
        if all(s == 1 for s in steps) or all(s == -1 for s in steps):
            if text[i:i + seq_length].isalnum():
                return True
    return False


def evaluate_password(password):
    """Return a dict describing the strength. Never includes the password itself."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if len(password) > MAX_LENGTH:
        raise ValueError(f"password longer than {MAX_LENGTH} characters")

    checks = {
        "length": len(password) >= MIN_LENGTH,
        "uppercase": any(c.isupper() for c in password),
        "number": any(c.isdigit() for c in password),
        "special": any(not c.isalnum() for c in password),
    }
    is_common = password.lower() in COMMON_PASSWORDS
    has_pattern = has_repeated_run(password) or has_sequence(password)

    score = sum(checks.values())
    if len(password) >= STRONG_LENGTH:
        score += 1
    if has_pattern:
        score -= 1
    score = max(score, 0)

    if password == "":
        label = "Empty"
    elif is_common or len(password) < MIN_LENGTH or score < 3:
        label = "Weak"
    elif len(password) >= STRONG_LENGTH and all(checks.values()) and score == 5:
        label = "Strong"
    else:
        label = "Medium"

    tips = []
    if password == "":
        tips.append("Type a password to evaluate it.")
    else:
        if is_common:
            tips.append("This is a very common password. Avoid well-known words and patterns.")
        if not checks["length"]:
            tips.append(f"Use at least {MIN_LENGTH} characters.")
        elif len(password) < STRONG_LENGTH:
            tips.append(f"Use {STRONG_LENGTH}+ characters for a Strong rating.")
        if not checks["uppercase"]:
            tips.append("Add an uppercase letter (A-Z).")
        if not checks["number"]:
            tips.append("Add a number (0-9).")
        if not checks["special"]:
            tips.append("Add a special character such as ! @ # $ %.")
        if has_pattern:
            tips.append("Avoid repeated characters (aaa) and sequences (abc, 123).")

    return {"label": label, "score": score, "max_score": 5, "length": len(password),
            "checks": checks, "is_common": is_common, "has_pattern": has_pattern,
            "tips": tips}


if __name__ == "__main__":  # simple command-line mode
    import getpass
    print(evaluate_password(getpass.getpass("Password (hidden): ")))
