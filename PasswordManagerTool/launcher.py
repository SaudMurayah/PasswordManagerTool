#!/usr/bin/env python3

import sys
import subprocess


def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║           🔐 PASSWORD MANAGER TOOL 🔐                ║
    ║                                                       ║
    ║          Secure • Encrypt • Generate                  ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)


def check_dependencies():
    try:
        import cryptography
        return True
    except ImportError:
        print("\n⚠️  Missing required dependency: cryptography")
        install = input("\nWould you like to install it now? (y/n): ").lower()
        if install == 'y':
            try:
                print("\nInstalling cryptography...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
                print("✓ Installation successful!")
                return True
            except Exception as e:
                print(f"\n✗ Installation failed: {e}")
                print("\nPlease install manually: pip install cryptography")
                return False
        return False


def main():
    print_banner()
    
    if not check_dependencies():
        print("\nExiting due to missing dependencies.")
        sys.exit(1)
    
    print("\nSelect Interface Mode:")
    print("1. CLI (Command Line Interface)")
    print("2. GUI (Graphical User Interface)")
    print("3. Exit")
    print("-" * 55)
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == '1':
        print("\nLaunching CLI mode...\n")
        try:
            import cli_main
            cli_main.main()
        except KeyboardInterrupt:
            print("\n\nExiting... Goodbye!")
        except Exception as e:
            print(f"\nError launching CLI: {e}")
    
    elif choice == '2':
        print("\nLaunching GUI mode...\n")
        try:
            import gui_main
            gui_main.main()
        except ImportError as e:
            print(f"\n✗ Error: {e}")
            print("\nTkinter might not be installed.")
            print("On Ubuntu/Debian: sudo apt-get install python3-tk")
            print("On Fedora: sudo dnf install python3-tkinter")
        except Exception as e:
            print(f"\nError launching GUI: {e}")
    
    elif choice == '3':
        print("\nGoodbye! Stay secure! 🔐")
        sys.exit(0)
    
    else:
        print("\n✗ Invalid choice. Please run again and select 1, 2, or 3.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting... Goodbye!")
        sys.exit(0)
