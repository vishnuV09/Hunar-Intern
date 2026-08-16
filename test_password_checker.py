"""
Unit Tests for Password Strength Analyzer
"""

import unittest
from password_checker import PasswordAnalyzer


class TestPasswordAnalyzer(unittest.TestCase):

    def test_empty_password(self):
        result = PasswordAnalyzer("").analyze()
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["rating"], "Weak")
        self.assertEqual(result["crack_time"], "Instant")

    def test_weak_passwords(self):
        weak_examples = ["123456", "password", "qwerty", "abc", "111111"]
        for pwd in weak_examples:
            res = PasswordAnalyzer(pwd).analyze()
            self.assertEqual(res["rating"], "Weak", f"Failed for '{pwd}': got {res['rating']}")
            self.assertLess(res["score"], 40)

    def test_okay_passwords(self):
        okay_examples = ["Password123", "helloWorld9", "MySecPass1"]
        for pwd in okay_examples:
            res = PasswordAnalyzer(pwd).analyze()
            self.assertIn(res["rating"], ["Okay", "Strong"], f"Failed for '{pwd}': got {res['rating']}")
            self.assertGreaterEqual(res["score"], 40)

    def test_strong_passwords(self):
        strong_examples = [
            "P@ssw0rd2026!Secure",
            "K9#mX2$vL8!qZ4*w",
            "c0mpl3x&S3cur3P@ssw0rd!"
        ]
        for pwd in strong_examples:
            res = PasswordAnalyzer(pwd).analyze()
            self.assertIn(res["rating"], ["Strong", "Very Strong"], f"Failed for '{pwd}': got {res['rating']}")
            self.assertGreaterEqual(res["score"], 70)

    def test_entropy_calculation(self):
        res = PasswordAnalyzer("abcd").analyze()
        # pool size for lowercase = 26. Entropy = 4 * log2(26) = 4 * 4.7004 = ~18.8
        self.assertAlmostEqual(res["entropy"], 18.8, delta=0.5)

    def test_password_generator(self):
        gen_pwd = PasswordAnalyzer.generate_strong_password(length=16)
        self.assertEqual(len(gen_pwd), 16)
        res = PasswordAnalyzer(gen_pwd).analyze()
        self.assertIn(res["rating"], ["Strong", "Very Strong"])


if __name__ == "__main__":
    unittest.main()
