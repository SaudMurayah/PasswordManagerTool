import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from password_generator import generate_password
from encryption import encrypt_password, decrypt_password
from strength_checker import check_password_strength, print_strength_report
from file_manager import save_entry, save_plain_password, list_files_in_directory, file_exists


def print_header():
    print("\n" + "="*60)
    print(" " * 15 + "PASSWORD MANAGER TOOL")
    print("="*60)


def print_menu():
    print("\nMain Menu:")
    print("1. Password Generator")
    print("2. Encrypt Existing Password")
    print("3. Decrypt Password")
    print("4. Password Strength Checker")
    print("5. Exit")
    print("-" * 60)


def get_password_criteria():
    print("\n--- Password Generation Criteria ---")
    
    while True:
        try:
            length = int(input("Enter password length (minimum 8, recommended +12): "))
            if length >= 8:
                break
            print("Length must be at least 8 characters.")
        except ValueError:
            print("Please enter a valid number.")
    
    return length


def password_generator_menu():
    print("\n" + "="*60)
    print("PASSWORD GENERATOR")
    print("="*60)
    
    length = get_password_criteria()
    
    try:
        password = generate_password(length)
        print(f"\nGenerated Password: {password}")
        
        print("\nEvaluating password strength...")
        result = check_password_strength(password)
        print(f"Strength: {result['strength']} (Score: {result['score']}/100)")
        
        if result['feedback']:
            print("\nSuggestions:")
            for suggestion in result['feedback']:
                print(f"  • {suggestion}")
        
        if result['score'] < 80:
            regenerate = input("\nPassword strength is below 80%. Generate a longer one? (y/n): ").lower()
            if regenerate == 'y':
                print("\nTip: Use 12+ characters for maximum security.")
                return password_generator_menu()
        
        save_choice = input("\nDo you want to save this password? (y/n): ").lower()
        
        if save_choice == 'y':
            encrypt_choice = input("\nDo you want to encrypt this password? (y/n): ").lower()
            
            if encrypt_choice == 'y':
                service = input("\nEnter service/website name (optional, press Enter to skip): ").strip()
                username = input("Enter username/email (optional, press Enter to skip): ").strip()
                
                passphrase = input("Enter encryption key (passphrase): ").strip()
                if not passphrase:
                    print("Error: Passphrase cannot be empty. Password not saved.")
                    return
                
                print("\n⚠️  IMPORTANT: Remember your passphrase! You'll need it to decrypt.")
                
                try:
                    encrypted = encrypt_password(password, passphrase)
                    print(f"\nPassword encrypted successfully!")
                    
                    save_to_file(service, username, encrypted, is_encrypted=True)
                    
                except Exception as e:
                    print(f"Encryption error: {e}")
            else:
                print("\n" + "="*60)
                print("⚠️  SECURITY WARNING - PLAIN TEXT STORAGE")
                print("="*60)
                print("Saving passwords without encryption is NOT secure!")
                print("Anyone with access to the file can read your password.")
                print("Encryption protects your passwords even if the file is stolen.")
                print("="*60)
                
                confirm = input("\nAre you SURE you want to save as plain text? (yes/no): ").lower()
                
                if confirm == 'yes':
                    service = input("\nEnter service/website name (optional, press Enter to skip): ").strip()
                    username = input("Enter username/email (optional, press Enter to skip): ").strip()
                    save_to_file(service, username, password, is_encrypted=False)
                else:
                    print("\nGood choice! Let's encrypt it instead.")
                    
                    service = input("\nEnter service/website name (optional, press Enter to skip): ").strip()
                    username = input("Enter username/email (optional, press Enter to skip): ").strip()
                    
                    passphrase = input("Enter encryption key (passphrase): ").strip()
                    if not passphrase:
                        print("Error: Passphrase cannot be empty. Password not saved.")
                        return
                    
                    print("\n⚠️  IMPORTANT: Remember your passphrase! You'll need it to decrypt.")
                    
                    try:
                        encrypted = encrypt_password(password, passphrase)
                        print(f"\nPassword encrypted successfully!")
                        save_to_file(service, username, encrypted, is_encrypted=True)
                    except Exception as e:
                        print(f"Encryption error: {e}")
    
    except ValueError as e:
        print(f"Error: {e}")


def save_to_file(service, username, password_data, is_encrypted=True):
    print("\nSave Options:")
    print("1. Create new file")
    print("2. Append to existing file")
    
    choice = input("Choose option (1/2): ").strip()
    
    if choice == '1':
        filename = input("Enter new filename (e.g., passwords.txt): ").strip()
        if not filename.endswith('.txt'):
            filename += '.txt'
        append = False
    elif choice == '2':
        existing_files = list_files_in_directory()
        if existing_files:
            print("\nExisting files:")
            for i, file in enumerate(existing_files, 1):
                print(f"{i}. {file}")
            filename = input("Enter filename to append to: ").strip()
        else:
            print("No existing .txt files found.")
            filename = input("Enter new filename: ").strip()
        
        if not filename.endswith('.txt'):
            filename += '.txt'
        append = True
    else:
        print("Invalid choice.")
        return
    
    if is_encrypted:
        success = save_entry(filename, service, username, password_data, append)
    else:
        success = save_plain_password(filename, service, username, password_data, append)
    
    if success:
        print(f"\n✓ Password saved to '{filename}'")
    else:
        print("\n✗ Failed to save password")


def encrypt_existing_password_menu():
    print("\n" + "="*60)
    print("ENCRYPT EXISTING PASSWORD")
    print("="*60)
    
    password = input("\nEnter the password you want to encrypt: ").strip()
    if not password:
        print("Error: Password cannot be empty.")
        return
    
    service = input("Enter service/website name (optional, press Enter to skip): ").strip()
    username = input("Enter username/email (optional, press Enter to skip): ").strip()
    
    passphrase = input("Enter encryption key (passphrase): ").strip()
    if not passphrase:
        print("Error: Passphrase cannot be empty. Password not saved.")
        return
    
    print("\n⚠️  IMPORTANT: Remember your passphrase! You'll need it to decrypt.")
    
    try:
        encrypted = encrypt_password(password, passphrase)
        print(f"\nPassword encrypted successfully!")
        print(f"Encrypted data: {encrypted[:50]}..." if len(encrypted) > 50 else f"Encrypted data: {encrypted}")
        
        save_to_file(service, username, encrypted, is_encrypted=True)
        
    except Exception as e:
        print(f"Encryption error: {e}")


def decrypt_password_menu():
    print("\n" + "="*60)
    print("DECRYPT PASSWORD")
    print("="*60)
    
    encrypted_data = input("\nEnter the encrypted password (ciphertext): ").strip()
    if not encrypted_data:
        print("Error: Encrypted data cannot be empty.")
        return
    
    passphrase = input("Enter your decryption key (passphrase): ").strip()
    if not passphrase:
        print("Error: Passphrase cannot be empty.")
        return
    
    try:
        decrypted = decrypt_password(encrypted_data, passphrase)
        print(f"\n✓ Decryption successful!")
        print(f"Original password: {decrypted}")
        
    except ValueError as e:
        print(f"\n✗ {e}")
    except Exception as e:
        print(f"\n✗ Decryption failed: {e}")


def strength_checker_menu():
    print("\n" + "="*60)
    print("PASSWORD STRENGTH CHECKER")
    print("="*60)
    
    password = input("\nEnter password to check: ").strip()
    if not password:
        print("Error: Password cannot be empty.")
        return
    
    print_strength_report(password)


def main():
    print_header()
    print("\nWelcome to Password Manager Tool!")
    print("Secure your passwords with encryption and strength analysis.")
    
    while True:
        print_menu()
        choice = input("Select an option (1-5): ").strip()
        
        if choice == '1':
            password_generator_menu()
        elif choice == '2':
            encrypt_existing_password_menu()
        elif choice == '3':
            decrypt_password_menu()
        elif choice == '4':
            strength_checker_menu()
        elif choice == '5':
            print("\n" + "="*60)
            print("Thank you for using Password Manager Tool!")
            print("Stay secure! 🔐")
            print("="*60 + "\n")
            sys.exit(0)
        else:
            print("\n✗ Invalid option. Please choose 1-5.")
        
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting... Goodbye!")
        sys.exit(0)
