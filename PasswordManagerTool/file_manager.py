import os
from datetime import datetime


def format_entry(service_name, username, encrypted_password, timestamp=None):
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    entry = f"""
{'='*60}"""
    
    if service_name:
        entry += f"\nService/Website: {service_name}"
    if username:
        entry += f"\nUsername: {username}"
    
    entry += f"""
Encrypted Password: {encrypted_password}
Timestamp: {timestamp}
{'='*60}
"""
    return entry


def save_entry(filename, service_name, username, encrypted_password, append=True):
    try:
        mode = 'a' if append and os.path.exists(filename) else 'w'
        
        with open(filename, mode, encoding='utf-8') as f:
            entry = format_entry(service_name, username, encrypted_password)
            f.write(entry)
            if mode == 'a':
                f.write('\n')
        
        return True
    except Exception as e:
        print(f"Error saving entry: {e}")
        return False


def save_plain_password(filename, service_name, username, password, append=True):
    try:
        mode = 'a' if append and os.path.exists(filename) else 'w'
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        entry = f"""
{'='*60}"""
        
        if service_name:
            entry += f"\nService/Website: {service_name}"
        if username:
            entry += f"\nUsername: {username}"
        
        entry += f"""
Password: {password}
Timestamp: {timestamp}
[WARNING: This password is stored in PLAIN TEXT]
{'='*60}
"""
        
        with open(filename, mode, encoding='utf-8') as f:
            f.write(entry)
            if mode == 'a':
                f.write('\n')
        
        return True
    except Exception as e:
        print(f"Error saving plain password: {e}")
        return False


def read_file(filename):
    try:
        if not os.path.exists(filename):
            return f"Error: File '{filename}' does not exist."
        
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return content if content else "File is empty."
    
    except Exception as e:
        return f"Error reading file: {e}"


def list_files_in_directory(directory="."):
    try:
        files = [f for f in os.listdir(directory) if f.endswith('.txt')]
        return sorted(files)
    except Exception as e:
        print(f"Error listing files: {e}")
        return []


def file_exists(filename):
    return os.path.exists(filename)


if __name__ == "__main__":
    print("Testing File Manager:")
    
    test_file = "test_passwords.txt"
    
    save_entry(
        test_file,
        "GitHub",
        "user@example.com",
        "encrypted_data_here",
        append=False
    )
    
    save_entry(
        test_file,
        "Gmail",
        "myemail@gmail.com",
        "another_encrypted_data",
        append=True
    )
    
    print("\nFile Contents:")
    print(read_file(test_file))
    
    if os.path.exists(test_file):
        os.remove(test_file)
        print(f"\nTest file '{test_file}' removed.")
