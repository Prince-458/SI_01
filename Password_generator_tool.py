import random
import string
import hashlib
import json

# Constants
COMPROMISED_PASSWORDS_FILE = 'compromised_passwords.json'
STORED_PASSWORDS_FILE = 'stored_passwords.json'

# Load compromised passwords from a file
def load_compromised_passwords():
    try:
        with open(COMPROMISED_PASSWORDS_FILE, 'r') as f:
            return set(json.load(f))
    except FileNotFoundError:
        return set()

# Load stored passwords from a file
def load_stored_passwords():
    try:
        with open(STORED_PASSWORDS_FILE, 'r') as f:
            return set(json.load(f))
    except FileNotFoundError:
        return set()


def save_stored_passwords(passwords):
    with open(STORED_PASSWORDS_FILE, 'w') as f:
        json.dump(list(passwords), f)


def generate_password(length, use_uppercase, use_lowercase, use_numbers, use_symbols, exclude_chars):
    char_set = ''
    if use_uppercase:
        char_set += string.ascii_uppercase
    if use_lowercase:
        char_set += string.ascii_lowercase
    if use_numbers:
        char_set += string.digits
    if use_symbols:
        char_set += string.punctuation

    char_set = ''.join(c for c in char_set if c not in exclude_chars)

    if len(char_set) == 0:
        raise ValueError("No character set available for password generation.")

    password = ''.join(random.choice(char_set) for _ in range(length))
    return password


def assess_password_strength(password):
    length_score = min(len(password) / 20, 1)
    upper_score = sum(1 for c in password if c.isupper()) / len(password)
    lower_score = sum(1 for c in password if c.islower()) / len(password)
    digit_score = sum(1 for c in password if c.isdigit()) / len(password)
    symbol_score = sum(1 for c in password if c in string.punctuation) / len(password)

    strength = (length_score + upper_score + lower_score + digit_score + symbol_score) / 5
    return strength

# Check if the password is compromised
def is_password_compromised(password, compromised_passwords):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password in compromised_passwords

# Main function
def main():
    compromised_passwords = load_compromised_passwords()
    stored_passwords = load_stored_passwords()

    length = int(input("Enter desired password length: "))
    use_uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
    use_lowercase = input("Include lowercase letters? (y/n): ").lower() == 'y'
    use_numbers = input("Include numbers? (y/n): ").lower() == 'y'
    use_symbols = input("Include symbols? (y/n): ").lower() == 'y'
    exclude_chars = input("Enter characters to exclude (leave blank for none): ")

    password = generate_password(length, use_uppercase, use_lowercase, use_numbers, use_symbols, exclude_chars)
    strength = assess_password_strength(password)

    print(f"Generated Password: {password}")
    print(f"Password Strength: {strength:.2f} (0.0 - weak, 1.0 - strong)")

    if is_password_compromised(password, compromised_passwords):
        print("Warning: This password is compromised! Please choose a different one.")
    else:
        print("This password is safe to use.")

        # Option to store the password
        if input("Do you want to store this password? (y/n): ").lower() == 'y':
            stored_passwords.add(password)
            save_stored_passwords(stored_passwords)
            print("Password stored successfully.")

if __name__ == "__main__":
    main()