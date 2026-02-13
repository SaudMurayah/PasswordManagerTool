import secrets
import string


def generate_password(length=16):
    if length < 8:
        raise ValueError("Password length must be at least 8 characters")
    
    char_pool = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    
    password = []
    
    password.append(secrets.choice(string.ascii_lowercase))
    password.append(secrets.choice(string.ascii_uppercase))
    password.append(secrets.choice(string.digits))
    password.append(secrets.choice(string.punctuation))
    
    remaining_length = length - 4
    password.extend(secrets.choice(char_pool) for _ in range(remaining_length))
    
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)


if __name__ == "__main__":
    print("Testing Password Generator:")
    print(f"16-char password: {generate_password(16)}")
    print(f"20-char password: {generate_password(20)}")
    print(f"12-char password: {generate_password(12)}")
