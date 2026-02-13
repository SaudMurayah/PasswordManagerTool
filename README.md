# Password Manager Tool
Password Manager Tool is a Python-based application designed to help you generate, encrypt, and securely manage passwords. The tool features AES encryption, an advanced strength analyzer, and secure file storage. It works on macOS, Windows, and Linux, offering both a user-friendly GUI and an interactive CLI mode for flexible password management.

<p align="center">
<img width="868" height="834" alt="Example-Check" src="https://github.com/user-attachments/assets/72e72fb6-2ca8-47e1-a9d0-d7b498bfeeec" />
</p>

## Features
- Generate strong passwords with customizable length (8-64 characters)
- AES encryption with PBKDF2 key derivation for maximum security
- Advanced strength analyzer that evaluates length and character distribution
- Secure file storage with optional metadata (service name and username)
- Security warnings to protect against plain text storage
- Encrypt and decrypt existing passwords with encryption keys
- Easy-to-use GUI and CLI - user-friendly interfaces for all preferences

## Requirements
- Python 3.x
- Required Python libraries:
  - `cryptography`
  - `tkinter` (macOS and Linux only)
- Virtual environment (recommended)

## Installation

### Clone the repository:
```bash
git clone https://github.com/SaudMurayah/PasswordManagerTool.git
cd PasswordManagerTool
```

### For macOS and Linux

1. Ensure Python 3.x is installed. If not, install it:

```bash 
sudo apt-get install python3 python3-pip   # For Debian-based systems
sudo pacman -S python python-pip           # For Arch-based systems
brew install python                        # For macOS using Homebrew
```

2. Create a Virtual Environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install the required libraries:

```bash
pip install -r requirements.txt
```
If tkinter is not installed, install it via this command:

```bash
sudo apt-get install python3-tk           # For Debian-based systems
sudo pacman -S tk                         # For Arch-based systems
brew install python-tk                    # For macOS using Homebrew
```

### For Windows

1. Ensure Python 3.x is installed. If not, download and install it from the [official website](https://www.python.org/downloads/).
   
Create a Virtual Environment:

```bash
python -m venv venv
venv\Scripts\activate
```
2. Install the required libraries:

```bash
pip install -r requirements.txt
```
`Note: tkinter comes pre-installed with Python on Windows.`

## Usage

1. Run the application:

```bash
python launcher.py
```

2. Using the GUI:

- Run the launcher and select option 2 (GUI Mode)
- Use the tabs to navigate between features:
- Generate Password: Set length, generate, and save passwords
- Encrypt Password: Encrypt existing passwords with metadata
- Decrypt Password: Decrypt passwords using your encryption key
- Strength Checker: Analyze password strength with detailed feedback

3. Using the CLI:

- Run the launcher and select option 1 (CLI Mode)
- Choose from the menu:
  - Option 1: Generate a new password with custom length
  - Option 2: Encrypt an existing password
  - Option 3: Decrypt a password with your encryption key
  - Option 4: Check password strength
  - Option 5: Exit

`Security Tips:
Always use encryption when saving passwords
REMEMBER your encryption keys - there's no recovery option`

## Example
### Password Strength Checker
#### GUI Mode:
<p align="center">
<img width="868" height="834" alt="Example-Check" src="https://github.com/user-attachments/assets/08c9d782-3fc0-4514-8fd5-22c160c849cc" /></p>
The Strength Checker analyzes your password and provides a detailed report showing the strength score, character distribution (lowercase, uppercase, numbers, symbols), and actionable suggestions to improve your password security.


### Generating a Strong Password
#### CLI Mode:
```bash
$ python launcher.py
Choose mode: 1 (CLI)

Menu:
1. Password Generator

Enter choice: 1
Enter password length (minimum 8, recommended +12): 16

Generated Password: A7!xBm9@Pk2Lq#Vw
Strength: Very Strong (90/100)

Do you want to save this password? (y/n): y
Enter service/website name (optional): GitHub
Enter username/email (optional): Saud@Murayah.me

Do you want to encrypt this password? (y/n): y
Enter encryption key (passphrase): Ex@mp1e

✓ Password saved to 'passwords.txt'
```

## Future Enhancements
- **Password Breach Detection:** Check if stored passwords have been compromised in known data breaches.
- **Biometric Authentication:** Add fingerprint or face recognition for additional security layers.
- **Password Expiration Alerts:** Notify users when passwords need to be changed based on age or security policies.
- **Import/Export Support:** Allow importing passwords from other password managers and exporting in standard formats.


## Contributing
Feel free to fork this project and add your own features or improvements.
