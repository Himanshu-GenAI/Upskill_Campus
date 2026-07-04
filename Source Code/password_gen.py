"""
password_gen.py — Password Generator Module for Password Manager

Generates cryptographically secure random passwords using Python's
secrets module. Supports configurable length and character-type options.

Security notes:
- Uses secrets.choice() instead of random.choice() for cryptographic safety.
- A "guarantee step" ensures at least one character from each selected
  category is present in the final password.
"""

import string
import secrets


# ── Character Sets ─────────────────────────────────────────────────────────────

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = string.punctuation


# ── Password Generation ───────────────────────────────────────────────────────

def generate_password(
    length: int = 12,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Generate a strong random password.

    Lowercase letters are always included.  Additional character types
    (uppercase, digits, symbols) are added based on the boolean flags.

    A guarantee step replaces random positions in the generated password
    to ensure at least one character from each selected type is present.

    Args:
        length: Desired password length (minimum 4, maximum 128).
        use_upper: Include uppercase letters.
        use_digits: Include numeric digits.
        use_symbols: Include punctuation symbols.

    Returns:
        str: The generated password.

    Raises:
        ValueError: If length is out of the valid range (4–128).
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 characters.")
    if length > 128:
        raise ValueError("Password length must be at most 128 characters.")

    # Build the character pool
    charset = LOWERCASE  # always included

    required_sets = [LOWERCASE]  # track which sets must have ≥ 1 character

    if use_upper:
        charset += UPPERCASE
        required_sets.append(UPPERCASE)
    if use_digits:
        charset += DIGITS
        required_sets.append(DIGITS)
    if use_symbols:
        charset += SYMBOLS
        required_sets.append(SYMBOLS)

    # Generate the initial password
    password = [secrets.choice(charset) for _ in range(length)]

    # Guarantee step: ensure each required set is represented at least once
    positions = list(range(length))
    secrets.SystemRandom().shuffle(positions)

    for i, char_set in enumerate(required_sets):
        if i >= length:
            break  # more sets than password length (shouldn't happen with min=4)
        # Check if the set is already represented
        if not any(c in char_set for c in password):
            password[positions[i]] = secrets.choice(char_set)

    return "".join(password)


# ── Password Strength Evaluation ──────────────────────────────────────────────

def evaluate_strength(password: str) -> str:
    """
    Evaluate the strength of a password.

    Scoring criteria:
    - Length ≥ 8       → +1 point
    - Length ≥ 12      → +1 point
    - Has uppercase    → +1 point
    - Has lowercase    → +1 point
    - Has digits       → +1 point
    - Has symbols      → +1 point

    Returns:
        str: "Weak" (0–2), "Medium" (3–4), or "Strong" (5–6).
    """
    if not password:
        return "Weak"

    score = 0

    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c in UPPERCASE for c in password):
        score += 1
    if any(c in LOWERCASE for c in password):
        score += 1
    if any(c in DIGITS for c in password):
        score += 1
    if any(c in SYMBOLS for c in password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"
