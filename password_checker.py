"""
Password Strength Analyzer Module
Provides comprehensive evaluation of password security, entropy math,
crack time estimation, flaw detection, and secure password generation.
"""

import math
import re
import secrets
import string
from common_passwords import COMMON_PASSWORDS, KEYBOARD_PATTERNS


class PasswordAnalyzer:
    SPECIAL_CHARACTERS = set("!@#$%^&*()_+-=[]{}|;:,.<>?/~`'\"\\")

    def __init__(self, password: str):
        self.password = password or ""
        self.length = len(self.password)

    def analyze(self) -> dict:
        """
        Analyzes the password and returns a comprehensive dictionary of results.
        """
        if not self.password:
            return {
                "password": "",
                "length": 0,
                "score": 0,
                "rating": "Weak",
                "color": "#ef4444",  # Red
                "entropy": 0.0,
                "crack_time": "Instant",
                "criteria": {
                    "has_lowercase": False,
                    "has_uppercase": False,
                    "has_digits": False,
                    "has_symbols": False,
                    "min_length_8": False,
                    "min_length_12": False,
                    "no_common_patterns": True,
                    "no_repeats": True,
                },
                "flaws": ["Password cannot be empty."],
                "suggestions": ["Enter a password to analyze."]
            }

        # 1. Base Criteria Checks
        has_lower = bool(re.search(r"[a-z]", self.password))
        has_upper = bool(re.search(r"[A-Z]", self.password))
        has_digits = bool(re.search(r"\d", self.password))
        has_symbols = any(c in self.SPECIAL_CHARACTERS for c in self.password)

        char_types_count = sum([has_lower, has_upper, has_digits, has_symbols])

        # 2. Check against common passwords
        normalized_pwd = self.password.strip().lower()
        is_common = normalized_pwd in COMMON_PASSWORDS

        # 3. Flaws & Pattern Detection
        flaws = []
        pattern_penalty = 0

        if is_common:
            flaws.append("This is a widely known, compromised password.")
            pattern_penalty += 50

        # Repeated characters (e.g. 'aaaa', '1111')
        if re.search(r"(.)\1{2,}", self.password):
            flaws.append("Contains 3 or more repeated consecutive characters.")
            pattern_penalty += 15

        # Keyboard pattern check
        for pattern in KEYBOARD_PATTERNS:
            if pattern in normalized_pwd or pattern[::-1] in normalized_pwd:
                flaws.append(f"Contains simple sequential pattern ('{pattern[:4]}...').")
                pattern_penalty += 20
                break

        # Only numbers or only letters
        if self.password.isdigit():
            flaws.append("Password contains only numbers.")
            pattern_penalty += 15
        elif self.password.isalpha():
            flaws.append("Password contains only letters.")
            pattern_penalty += 10

        # Short length flaw
        if self.length < 8:
            flaws.append("Password length is less than 8 characters.")

        # 4. Score Calculation (Base 0 - 100)
        score = 0

        # Length score (up to 45 points)
        if self.length >= 16:
            score += 45
        elif self.length >= 12:
            score += 35
        elif self.length >= 8:
            score += 20
        else:
            score += self.length * 2

        # Character variety score (up to 45 points)
        if has_lower:
            score += 10
        if has_upper:
            score += 10
        if has_digits:
            score += 10
        if has_symbols:
            score += 15

        # Variety Bonus (up to 10 points)
        if char_types_count >= 4:
            score += 10
        elif char_types_count == 3:
            score += 5

        # Apply penalties
        score = max(0, score - pattern_penalty)

        # Cap score if password is extremely short or common
        if is_common:
            score = min(score, 15)
        elif self.length < 6:
            score = min(score, 25)

        # Final Score bounded [0, 100]
        score = min(100, max(0, score))

        # 5. Rating & Color Mapping
        if score >= 85:
            rating = "Very Strong"
            color = "#10b981"  # Emerald Green
        elif score >= 70:
            rating = "Strong"
            color = "#22c55e"  # Green
        elif score >= 40:
            rating = "Okay"
            color = "#f59e0b"  # Amber / Yellow
        else:
            rating = "Weak"
            color = "#ef4444"  # Red

        # 6. Shannon Entropy Calculation
        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digits:
            pool_size += 10
        if has_symbols:
            pool_size += 32
        
        # Include any remaining ASCII chars if used
        other_chars = set(self.password) - set(string.ascii_letters + string.digits) - self.SPECIAL_CHARACTERS
        if other_chars:
            pool_size += len(other_chars)

        if pool_size > 0:
            entropy = round(self.length * math.log2(pool_size), 1)
        else:
            entropy = 0.0

        # 7. Estimated Time to Crack (assuming 10^10 hashes/sec brute force)
        crack_time = self._calculate_crack_time(pool_size, self.length)

        # 8. Construct Suggestions
        suggestions = self._generate_suggestions(
            has_lower, has_upper, has_digits, has_symbols, self.length, is_common, flaws
        )

        return {
            "password": self.password,
            "length": self.length,
            "score": score,
            "rating": rating,
            "color": color,
            "entropy": entropy,
            "pool_size": pool_size,
            "crack_time": crack_time,
            "criteria": {
                "has_lowercase": has_lower,
                "has_uppercase": has_upper,
                "has_digits": has_digits,
                "has_symbols": has_symbols,
                "min_length_8": self.length >= 8,
                "min_length_12": self.length >= 12,
                "no_common_patterns": not (is_common or pattern_penalty > 0),
                "no_repeats": not re.search(r"(.)\1{2,}", self.password),
            },
            "flaws": flaws,
            "suggestions": suggestions
        }

    def _calculate_crack_time(self, pool_size: int, length: int) -> str:
        """
        Estimates brute-force time assuming 10,000,000,000 (10 billion) guesses per second.
        """
        if pool_size == 0 or length == 0:
            return "Instant"

        combinations = pool_size ** length
        guesses_per_second = 10_000_000_000
        seconds = combinations / (2 * guesses_per_second)  # Average time is half total combinations

        if seconds < 1:
            return "Instant (< 1 second)"
        elif seconds < 60:
            return f"{math.ceil(seconds)} seconds"
        elif seconds < 3600:
            return f"{math.ceil(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{math.ceil(seconds / 3600)} hours"
        elif seconds < 31_536_000:
            return f"{math.ceil(seconds / 86400)} days"
        elif seconds < 31_536_000 * 100:
            years = math.ceil(seconds / 31_536_000)
            return f"{years} years"
        elif seconds < 31_536_000 * 1_000_000:
            thousand_years = math.ceil(seconds / (31_536_000 * 1000))
            return f"{thousand_years:,} thousand years"
        else:
            million_years = math.ceil(seconds / (31_536_000 * 1_000_000))
            return f"{million_years:,} million years"

    def _generate_suggestions(self, lower: bool, upper: bool, digits: bool, symbols: bool, length: int, common: bool, flaws: list) -> list:
        suggestions = []
        if common:
            suggestions.append("Change your password immediately; this password is included in public leak databases.")
        if length < 8:
            suggestions.append("Increase total length to at least 8 characters (12+ is strongly recommended).")
        elif length < 12:
            suggestions.append("Make your password longer (12-16+ characters significantly boosts security).")

        if not lower:
            suggestions.append("Include lowercase letters (a-z).")
        if not upper:
            suggestions.append("Include uppercase letters (A-Z).")
        if not digits:
            suggestions.append("Include numbers (0-9).")
        if not symbols:
            suggestions.append("Include special symbols (e.g. !@#$%^&*).")

        if "Contains 3 or more repeated consecutive characters." in flaws:
            suggestions.append("Avoid repeating the same character consecutively (e.g. use 'a1b2' instead of 'aaaa').")
        if any("sequential pattern" in f for f in flaws):
            suggestions.append("Avoid sequential keyboard patterns like '1234' or 'qwerty'.")

        if not suggestions:
            suggestions.append("Great job! Your password meets all strong security recommendations.")

        return suggestions

    @staticmethod
    def generate_strong_password(length: int = 16, include_symbols: bool = True) -> str:
        """
        Generates a cryptographically secure strong random password.
        """
        length = max(12, length)
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?" if include_symbols else ""

        # Guarantee at least one from each selected category
        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits)
        ]
        if include_symbols:
            password_chars.append(secrets.choice(symbols))

        all_pool = lowercase + uppercase + digits + symbols
        remaining_length = length - len(password_chars)

        for _ in range(remaining_length):
            password_chars.append(secrets.choice(all_pool))

        # Secure shuffle
        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)
