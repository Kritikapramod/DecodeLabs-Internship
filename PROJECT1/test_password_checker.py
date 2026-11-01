import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from password_checker import evaluate_password as ev

CASES = [  # (description, password, expected label)
    ("Empty", "", "Empty"),
    ("Very short", "aB3$", "Weak"),
    ("Lowercase only", "sunshinefarm", "Weak"),
    ("Upper + number, no symbol", "Mango2024Fruit", "Medium"),
    ("Upper + number + symbol, 8 chars", "Gx7!kQ2m", "Medium"),
    ("Short with all types (7 chars)", "Gx7!kQ2", "Weak"),
    ("Long mixed", "Blue#Tiger47-Rides", "Strong"),
    ("Contains spaces (space = special char)", "Blue Tiger 47 Rides", "Strong"),
    ("Repeated characters", "Aaaa1111!!!!", "Medium"),
    ("Common password", "Password123", "Weak"),
    ("Whitespace only", "        ", "Weak"),
]

class T(unittest.TestCase):
    def test_cases(self):
        for desc, pw, expected in CASES:
            with self.subTest(desc):
                self.assertEqual(ev(pw)["label"], expected)
    def test_no_trimming(self):
        self.assertEqual(ev("  ab  ")["length"], 6)
    def test_result_hides_password(self):
        self.assertNotIn("Blue#Tiger47-Rides", str(ev("Blue#Tiger47-Rides")))
    def test_bad_input(self):
        with self.assertRaises(TypeError): ev(None)
        with self.assertRaises(ValueError): ev("a" * 300)

if __name__ == "__main__":
    unittest.main(verbosity=2)
