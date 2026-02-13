import re
import string


def check_password_strength(password):
    feedback = []
    length = len(password)
    
    lowercase_count = len(re.findall(r'[a-z]', password))
    uppercase_count = len(re.findall(r'[A-Z]', password))
    numbers_count = len(re.findall(r'\d', password))
    symbols_count = len(re.findall(r'[' + re.escape(string.punctuation) + r']', password))
    
    has_lowercase = lowercase_count > 0
    has_uppercase = uppercase_count > 0
    has_numbers = numbers_count > 0
    has_symbols = symbols_count > 0
    
    has_all_types = has_lowercase and has_uppercase and has_numbers and has_symbols
    
    if has_all_types:
        base_score = 0
        
        if length >= 20:
            base_score = 50
        elif length >= 18:
            base_score = 47
        elif length >= 16:
            base_score = 45
        elif length >= 14:
            base_score = 42
        elif length >= 12:
            base_score = 40
        elif length >= 10:
            base_score = 35
        elif length >= 9:
            base_score = 30
        elif length >= 8:
            base_score = 25
        elif length == 7:
            base_score = 20
        elif length == 6:
            base_score = 15
        else:
            base_score = 10
        
        char_diversity_score = 0
        
        if lowercase_count >= 3:
            char_diversity_score += 10
        elif lowercase_count >= 2:
            char_diversity_score += 7
        elif lowercase_count >= 1:
            char_diversity_score += 4
        
        if uppercase_count >= 3:
            char_diversity_score += 10
        elif uppercase_count >= 2:
            char_diversity_score += 7
        elif uppercase_count >= 1:
            char_diversity_score += 4
        
        if numbers_count >= 3:
            char_diversity_score += 15
        elif numbers_count >= 2:
            char_diversity_score += 10
        elif numbers_count >= 1:
            char_diversity_score += 5
        
        if symbols_count >= 3:
            char_diversity_score += 15
        elif symbols_count >= 2:
            char_diversity_score += 10
        elif symbols_count >= 1:
            char_diversity_score += 5
        
        score = base_score + char_diversity_score
        score = min(100, score)
        
        if score >= 95:
            strength = "Very Strong"
            feedback.append("Excellent! Maximum security password.")
        elif score >= 90:
            strength = "Very Strong"
            feedback.append("Excellent! This is a very strong password.")
        elif score >= 85:
            strength = "Very Strong"
            feedback.append("Excellent! Very strong and secure.")
        elif score >= 80:
            strength = "Strong"
            feedback.append("Great password! Very good security.")
        elif score >= 75:
            strength = "Strong"
            feedback.append("Good password! Strong and secure.")
        elif score >= 70:
            strength = "Strong"
            feedback.append("Good password! Solid security.")
        elif score >= 60:
            strength = "Medium"
            feedback.append("Decent password. Add more character variety.")
        elif score >= 50:
            strength = "Medium"
            feedback.append("Acceptable password. Consider adding more digits and symbols.")
        elif score >= 40:
            strength = "Weak"
            feedback.append("Weak password. Increase length and add more character variety.")
        elif score >= 30:
            strength = "Weak"
            feedback.append("Too short! Use at least 8 characters with more variety.")
        else:
            strength = "Very Weak"
            feedback.append("Very weak! Increase length and character diversity significantly.")
        
        if lowercase_count < 2:
            feedback.append(f"Add more lowercase letters (currently: {lowercase_count}).")
        if uppercase_count < 2:
            feedback.append(f"Add more uppercase letters (currently: {uppercase_count}).")
        if numbers_count < 2:
            feedback.append(f"Add more numbers (currently: {numbers_count}).")
        if symbols_count < 2:
            feedback.append(f"Add more symbols (currently: {symbols_count}).")
        
        if length < 12 and score < 80:
            feedback.append("Recommended: 12+ characters for better security.")
        
    else:
        score = 10
        strength = "Very Weak"
        feedback.append("Password must contain uppercase, lowercase, numbers, and symbols.")
        if not has_lowercase:
            feedback.append("Add lowercase letters (a-z).")
        if not has_uppercase:
            feedback.append("Add uppercase letters (A-Z).")
        if not has_numbers:
            feedback.append("Add numbers (0-9).")
        if not has_symbols:
            feedback.append("Add special symbols (!@#$%^&*).")
    
    return {
        'score': score,
        'strength': strength,
        'feedback': feedback,
        'details': {
            'length': length,
            'has_lowercase': has_lowercase,
            'has_uppercase': has_uppercase,
            'has_numbers': has_numbers,
            'has_symbols': has_symbols,
            'lowercase_count': lowercase_count,
            'uppercase_count': uppercase_count,
            'numbers_count': numbers_count,
            'symbols_count': symbols_count
        }
    }


def print_strength_report(password):
    result = check_password_strength(password)
    
    print("\n" + "="*50)
    print("PASSWORD STRENGTH ANALYSIS")
    print("="*50)
    print(f"Password: {'*' * len(password)}")
    print(f"Length: {result['details']['length']} characters")
    print(f"Score: {result['score']}/100")
    print(f"Strength: {result['strength']}")
    print("\nCharacter Distribution:")
    print(f"  ✓ Lowercase: {result['details']['lowercase_count']} {'✓' if result['details']['has_lowercase'] else '✗'}")
    print(f"  ✓ Uppercase: {result['details']['uppercase_count']} {'✓' if result['details']['has_uppercase'] else '✗'}")
    print(f"  ✓ Numbers: {result['details']['numbers_count']} {'✓' if result['details']['has_numbers'] else '✗'}")
    print(f"  ✓ Symbols: {result['details']['symbols_count']} {'✓' if result['details']['has_symbols'] else '✗'}")
    
    if result['feedback']:
        print("\nSuggestions:")
        for i, suggestion in enumerate(result['feedback'], 1):
            print(f"  {i}. {suggestion}")
    
    print("="*50 + "\n")


if __name__ == "__main__":
    test_passwords = [
        "Pa@1aaaa",
        "Pass@123",
        "MyP@ssw0rd",
        "MyP@ssw0rd!!",
        "MyP@ssW0rd123",
        "MySTR0NG!P@ssW0RD",
        "MyVERY$TR0NG!P@ssW0RD123",
        "A1b!",
        "ABCDabcd1234!@#$",
        "aaaaA1!",
        "Aa1!Aa1!Aa1!Aa1!",
        "password",
    ]
    
    for pwd in test_passwords:
        print_strength_report(pwd)
