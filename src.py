#!/usr/bin/env python3
"""
Strong Password Generator with Strength Scoring
Copy this entire file to PyCharm and run it.
"""

import random
import string
import re
from typing import Optional


class PasswordGenerator:
    """A customizable password generator with strength scoring."""

    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate(
        self,
        length: int = 16,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        custom_symbols: Optional[str] = None,
        exclude_ambiguous: bool = False
    ) -> str:
        """
        Generate a customizable password.

        Args:
            length: Password length (default: 16)
            use_lowercase: Include lowercase letters (default: True)
            use_uppercase: Include uppercase letters (default: True)
            use_digits: Include digits (default: True)
            use_symbols: Include symbols (default: True)
            custom_symbols: Custom symbol set to use instead of default
            exclude_ambiguous: Exclude ambiguous characters like 'O', '0', 'l', '1'

        Returns:
            Generated password string
        """
        if length < 4:
            raise ValueError("Password length must be at least 4")

        # Build character pool
        char_pool = ""
        required_chars = []

        ambiguous = "O0l1I"

        lowercase_chars = self.lowercase
        uppercase_chars = self.uppercase
        digit_chars = self.digits
        symbol_chars = custom_symbols if custom_symbols else self.symbols

        if exclude_ambiguous:
            lowercase_chars = ''.join(c for c in lowercase_chars if c not in ambiguous.lower())
            uppercase_chars = ''.join(c for c in uppercase_chars if c not in ambiguous)
            digit_chars = ''.join(c for c in digit_chars if c not in ambiguous)

        if use_lowercase:
            char_pool += lowercase_chars
            required_chars.append(random.choice(lowercase_chars))

        if use_uppercase:
            char_pool += uppercase_chars
            required_chars.append(random.choice(uppercase_chars))

        if use_digits:
            char_pool += digit_chars
            required_chars.append(random.choice(digit_chars))

        if use_symbols:
            char_pool += symbol_chars
            required_chars.append(random.choice(symbol_chars))

        if not char_pool:
            raise ValueError("At least one character type must be selected")

        # Fill remaining length
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [random.choice(char_pool) for _ in range(remaining_length)]

        # Shuffle to avoid predictable patterns
        random.shuffle(password_chars)

        return ''.join(password_chars)

    def calculate_strength(self, password: str) -> dict:
        """
        Calculate password strength and return detailed scoring.

        Returns:
            Dictionary with score (0-100), rating, and feedback
        """
        score = 0
        feedback = []

        # Length scoring (up to 40 points)
        length = len(password)
        if length >= 20:
            score += 40
        elif length >= 16:
            score += 30
        elif length >= 12:
            score += 20
        elif length >= 8:
            score += 10
        else:
            feedback.append("Too short - use at least 12 characters")

        # Character variety scoring (up to 40 points)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

        char_types = sum([has_lower, has_upper, has_digit, has_symbol])
        score += char_types * 10

        if not has_lower:
            feedback.append("Add lowercase letters")
        if not has_upper:
            feedback.append("Add uppercase letters")
        if not has_digit:
            feedback.append("Add numbers")
        if not has_symbol:
            feedback.append("Add symbols for extra security")

        # Pattern penalties
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):
            score -= 10
            feedback.append("Avoid repeating characters")

        # Common sequences
        common_sequences = ['123', 'abc', 'qwe', 'asd', 'zxc', 'password', 'qwerty']
        lower_pass = password.lower()
        for seq in common_sequences:
            if seq in lower_pass:
                score -= 15
                feedback.append(f"Avoid common sequences like '{seq}'")
                break

        # Sequential characters
        if re.search(r'(abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz)', lower_pass):
            score -= 10
            feedback.append("Avoid sequential letters")

        if re.search(r'(0123|1234|2345|3456|4567|5678|6789|7890)', password):
            score -= 10
            feedback.append("Avoid sequential numbers")

        # Ensure score is within 0-100
        score = max(0, min(100, score))

        # Determine rating
        if score >= 80:
            rating = "Excellent"
        elif score >= 60:
            rating = "Strong"
        elif score >= 40:
            rating = "Moderate"
        elif score >= 20:
            rating = "Weak"
        else:
            rating = "Very Weak"

        return {
            "score": score,
            "rating": rating,
            "length": length,
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "feedback": feedback if feedback else ["Good password!"]
        }


def interactive_mode():
    """Interactive CLI for password generation."""
    gen = PasswordGenerator()

    print("=" * 50)
    print("🔐PASSWORD GENERATOR")
    print("=" * 50)
    print()

    # Get settings
    try:
        length = int(input("Password length (default 16): ") or "16")
    except ValueError:
        length = 16

    use_lower = input("Include lowercase letters? (y/n, default y): ").lower() != 'n'
    use_upper = input("Include uppercase letters? (y/n, default y): ").lower() != 'n'
    use_digits = input("Include digits? (y/n, default y): ").lower() != 'n'
    use_symbols = input("Include symbols? (y/n, default y): ").lower() != 'n'
    exclude_ambiguous = input("Exclude ambiguous characters (O,0,l,1)? (y/n, default n): ").lower() == 'y'

    custom_symbols = None
    if use_symbols:
        custom = input("Custom symbols (leave empty for default): ").strip()
        if custom:
            custom_symbols = custom

    # Generate password
    try:
        password = gen.generate(
            length=length,
            use_lowercase=use_lower,
            use_uppercase=use_upper,
            use_digits=use_digits,
            use_symbols=use_symbols,
            custom_symbols=custom_symbols,
            exclude_ambiguous=exclude_ambiguous
        )

        # Calculate strength
        strength = gen.calculate_strength(password)

        # Display results
        print()
        print("=" * 50)
        print("✅ GENERATED PASSWORD")
        print("=" * 50)
        print()
        print(f"📋 {password}")
        print()
        print("-" * 50)
        print("STRENGTH ANALYSIS")
        print("-" * 50)
        print(f"Score: {strength['score']}/100")
        print(f"Rating: {strength['rating']}")
        print(f"Length: {strength['length']} characters")
        print(f"Lowercase: {'✓' if strength['has_lowercase'] else '✗'}")
        print(f"Uppercase: {'✓' if strength['has_uppercase'] else '✗'}")
        print(f"Digits: {'✓' if strength['has_digits'] else '✗'}")
        print(f"Symbols: {'✓' if strength['has_symbols'] else '✗'}")
        print()
        print("Feedback:")
        for msg in strength['feedback']:
            print(f"  • {msg}")
        print()
        print("=" * 50)

        # Option to generate more
        while input("Generate another? (y/n): ").lower() == 'y':
            password = gen.generate(
                length=length,
                use_lowercase=use_lower,
                use_uppercase=use_upper,
                use_digits=use_digits,
                use_symbols=use_symbols,
                custom_symbols=custom_symbols,
                exclude_ambiguous=exclude_ambiguous
            )
            strength = gen.calculate_strength(password)
            print()
            print(f"📋 {password}")
            print(f"   Strength: {strength['rating']} ({strength['score']}/100)")
            print()

    except ValueError as e:
        print(f"Error: {e}")


def quick_generate(length: int = 16) -> str:
    """Quickly generate a strong password with default settings."""
    gen = PasswordGenerator()
    return gen.generate(length=length)


# Example usage and quick presets
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # Command line usage: python password_generator.py 20
        try:
            length = int(sys.argv[1])
            gen = PasswordGenerator()
            password = gen.generate(length=length)
            strength = gen.calculate_strength(password)
            print(password)
            print(f"Strength: {strength['rating']} ({strength['score']}/100)", file=sys.stderr)
        except ValueError:
            print("Usage: python password_generator.py [length]")
    else:
        # Interactive mode
        interactive_mode()
