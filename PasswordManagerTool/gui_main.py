import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from password_generator import generate_password
from encryption import encrypt_password, decrypt_password
from strength_checker import check_password_strength
from file_manager import save_entry, save_plain_password


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager Tool 🔐")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.create_widgets()
    
    def create_widgets(self):
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        title_frame.pack(fill='x', side='top')
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame,
            text="🔐 PASSWORD MANAGER TOOL",
            font=('Arial', 20, 'bold'),
            bg='#2c3e50',
            fg='white'
        )
        title_label.pack(expand=True)
        
        subtitle = tk.Label(
            title_frame,
            text="Generate • Encrypt • Secure",
            font=('Arial', 10),
            bg='#2c3e50',
            fg='#ecf0f1'
        )
        subtitle.pack()
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.create_generator_tab()
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_strength_tab()
    
    def create_generator_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Generate Password  ")
        
        canvas = tk.Canvas(tab)
        scrollbar = tk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        main_frame = tk.Frame(scrollable_frame, padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        criteria_frame = tk.LabelFrame(main_frame, text="Password Length", font=('Arial', 11, 'bold'), padx=15, pady=15)
        criteria_frame.pack(fill='x', pady=(0, 15))
        
        length_frame = tk.Frame(criteria_frame)
        length_frame.pack(fill='x', pady=5)
        tk.Label(length_frame, text="Length:", font=('Arial', 11)).pack(side='left')
        self.gen_length = tk.IntVar(value=16)
        tk.Spinbox(length_frame, from_=8, to=64, textvariable=self.gen_length, width=10, font=('Arial', 11)).pack(side='left', padx=10)
        tk.Label(length_frame, text="(minimum 8, recommended +12)", font=('Arial', 9), fg='gray').pack(side='left', padx=10)
        
        info_label = tk.Label(
            criteria_frame,
            text="Generated passwords always include:\n• Uppercase letters (A-Z)\n• Lowercase letters (a-z)\n• Numbers (0-9)\n• Special symbols (!@#$%...)\n\nRecommended: 12+ characters for maximum security",
            font=('Arial', 9),
            fg='#2c3e50',
            justify='left',
            bg='#ecf0f1',
            padx=10,
            pady=10
        )
        info_label.pack(fill='x', pady=(10, 0))
        
        tk.Button(
            main_frame,
            text="🎲 Generate Password",
            command=self.generate_password_action,
            bg='#3498db',
            fg='white',
            font=('Arial', 11, 'bold'),
            padx=20,
            pady=10,
            cursor='hand2'
        ).pack(pady=10)
        
        result_frame = tk.LabelFrame(main_frame, text="Generated Password", font=('Arial', 11, 'bold'), padx=15, pady=15)
        result_frame.pack(fill='both', expand=True, pady=(15, 0))
        
        self.gen_password_var = tk.StringVar()
        password_entry = tk.Entry(result_frame, textvariable=self.gen_password_var, font=('Arial', 12), state='readonly', readonlybackground='white')
        password_entry.pack(fill='x', pady=(0, 10))
        
        tk.Button(result_frame, text="📋 Copy", command=lambda: self.copy_to_clipboard(self.gen_password_var.get()), font=('Arial', 9)).pack(side='left', padx=5)
        
        self.gen_strength_label = tk.Label(result_frame, text="", font=('Arial', 10, 'bold'))
        self.gen_strength_label.pack(pady=10)
        
        save_frame = tk.LabelFrame(main_frame, text="Save Password (Optional)", font=('Arial', 10, 'bold'), padx=15, pady=15)
        save_frame.pack(fill='x', pady=(15, 0))
        
        fields_frame = tk.Frame(save_frame)
        fields_frame.pack(expand=True)
        
        tk.Label(fields_frame, text="Service/Website (optional):", font=('Arial', 9)).grid(row=0, column=0, sticky='e', pady=5, padx=(0, 10))
        self.gen_service = tk.Entry(fields_frame, font=('Arial', 9), width=30)
        self.gen_service.grid(row=0, column=1, pady=5)
        
        tk.Label(fields_frame, text="Username (optional):", font=('Arial', 9)).grid(row=1, column=0, sticky='e', pady=5, padx=(0, 10))
        self.gen_username = tk.Entry(fields_frame, font=('Arial', 9), width=30)
        self.gen_username.grid(row=1, column=1, pady=5)
        
        checkbox_frame = tk.Frame(save_frame)
        checkbox_frame.pack(pady=10)
        
        self.gen_encrypt_var = tk.BooleanVar(value=True)
        encrypt_check = tk.Checkbutton(checkbox_frame, text="Encrypt before saving (RECOMMENDED)", variable=self.gen_encrypt_var, font=('Arial', 9, 'bold'), fg='black')
        encrypt_check.pack()
        
        button_frame = tk.Frame(save_frame)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="💾 Save", command=self.save_generated_password, bg='#27ae60', fg='white', font=('Arial', 9, 'bold'), padx=15, pady=5).pack()
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def create_encrypt_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Encrypt Password  ")
        
        canvas = tk.Canvas(tab)
        scrollbar = tk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        main_frame = tk.Frame(scrollable_frame, padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        input_frame = tk.LabelFrame(main_frame, text="Password Details", font=('Arial', 11, 'bold'), padx=15, pady=15)
        input_frame.pack(fill='x', pady=(0, 15))
        
        fields_frame = tk.Frame(input_frame)
        fields_frame.pack(expand=True)
        
        tk.Label(fields_frame, text="Service/Website (optional):", font=('Arial', 10)).grid(row=0, column=0, sticky='e', pady=8, padx=(0, 10))
        self.enc_service = tk.Entry(fields_frame, font=('Arial', 10), width=40)
        self.enc_service.grid(row=0, column=1, pady=8)
        
        tk.Label(fields_frame, text="Username (optional):", font=('Arial', 10)).grid(row=1, column=0, sticky='e', pady=8, padx=(0, 10))
        self.enc_username = tk.Entry(fields_frame, font=('Arial', 10), width=40)
        self.enc_username.grid(row=1, column=1, pady=8)
        
        tk.Label(fields_frame, text="Password:", font=('Arial', 10)).grid(row=2, column=0, sticky='e', pady=8, padx=(0, 10))
        self.enc_password = tk.Entry(fields_frame, font=('Arial', 10), show='*', width=40)
        self.enc_password.grid(row=2, column=1, pady=8)
        
        tk.Label(fields_frame, text="Encryption Key:", font=('Arial', 10)).grid(row=3, column=0, sticky='e', pady=8, padx=(0, 10))
        self.enc_key = tk.Entry(fields_frame, font=('Arial', 10), show='*', width=40)
        self.enc_key.grid(row=3, column=1, pady=8)
        
        warning = tk.Label(
            main_frame,
            text="⚠️  IMPORTANT: Remember your encryption key! You'll need it to decrypt.",
            font=('Arial', 9, 'bold'),
            fg='#e74c3c',
            wraplength=600
        )
        warning.pack(pady=10)
        
        tk.Button(
            main_frame,
            text="🔒 Encrypt & Save",
            command=self.encrypt_password_action,
            bg='#e67e22',
            fg='white',
            font=('Arial', 11, 'bold'),
            padx=20,
            pady=10
        ).pack(pady=10)
        
        result_frame = tk.LabelFrame(main_frame, text="Encrypted Password", font=('Arial', 10, 'bold'), padx=15, pady=15)
        result_frame.pack(fill='both', expand=True, pady=(15, 0))
        
        self.enc_result = scrolledtext.ScrolledText(result_frame, height=8, font=('Courier', 9), wrap='word')
        self.enc_result.pack(fill='both', expand=True)
        
        tk.Button(result_frame, text="📋 Copy", command=lambda: self.copy_to_clipboard(self.enc_result.get('1.0', 'end-1c')), font=('Arial', 9)).pack(pady=(10, 0))
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def create_decrypt_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Decrypt Password  ")
        
        canvas = tk.Canvas(tab)
        scrollbar = tk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        main_frame = tk.Frame(scrollable_frame, padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        input_frame = tk.LabelFrame(main_frame, text="Decryption Details", font=('Arial', 11, 'bold'), padx=15, pady=15)
        input_frame.pack(fill='both', expand=True, pady=(0, 15))
        
        tk.Label(input_frame, text="Encrypted Password (Ciphertext):", font=('Arial', 10)).pack(anchor='w', pady=(0, 5))
        self.dec_ciphertext = scrolledtext.ScrolledText(input_frame, height=6, font=('Courier', 9), wrap='word')
        self.dec_ciphertext.pack(fill='both', expand=True, pady=(0, 15))
        
        tk.Label(input_frame, text="Decryption Key:", font=('Arial', 10)).pack(anchor='w', pady=(10, 5))
        self.dec_key = tk.Entry(input_frame, font=('Arial', 10), show='*', width=50)
        self.dec_key.pack(fill='x', pady=(0, 10))
        
        tk.Button(
            main_frame,
            text="🔓 Decrypt Password",
            command=self.decrypt_password_action,
            bg='#9b59b6',
            fg='white',
            font=('Arial', 11, 'bold'),
            padx=20,
            pady=10
        ).pack(pady=10)
        
        result_frame = tk.LabelFrame(main_frame, text="Decrypted Password", font=('Arial', 10, 'bold'), padx=15, pady=15)
        result_frame.pack(fill='x', pady=(15, 0))
        
        self.dec_result = tk.Entry(result_frame, font=('Arial', 12, 'bold'), state='readonly', readonlybackground='#d5f4e6')
        self.dec_result.pack(fill='x', pady=10)
        
        tk.Button(result_frame, text="📋 Copy", command=lambda: self.copy_to_clipboard(self.dec_result.get()), font=('Arial', 9)).pack()
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def create_strength_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Strength Checker  ")
        
        canvas = tk.Canvas(tab)
        scrollbar = tk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        main_frame = tk.Frame(scrollable_frame, padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        input_frame = tk.LabelFrame(main_frame, text="Password to Check", font=('Arial', 11, 'bold'), padx=15, pady=15)
        input_frame.pack(fill='x', pady=(0, 15))
        
        self.strength_password = tk.Entry(input_frame, font=('Arial', 12), width=50)
        self.strength_password.pack(fill='x', pady=10)
        
        tk.Button(
            input_frame,
            text="🔍 Check Strength",
            command=self.check_strength_action,
            bg='#16a085',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=8
        ).pack(pady=5)
        
        result_frame = tk.LabelFrame(main_frame, text="Analysis Results", font=('Arial', 11, 'bold'), padx=15, pady=15)
        result_frame.pack(fill='both', expand=True, pady=(15, 0))
        
        self.strength_result = scrolledtext.ScrolledText(result_frame, height=15, font=('Arial', 10), wrap='word', state='disabled')
        self.strength_result.pack(fill='both', expand=True)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def generate_password_action(self):
        try:
            length = self.gen_length.get()
            password = generate_password(length)
            
            self.gen_password_var.set(password)
            
            result = check_password_strength(password)
            strength_text = f"{result['strength']} ({result['score']}/100)"
            
            if result['score'] >= 90:
                color = '#16a085'
            elif result['score'] >= 80:
                color = '#27ae60'
            elif result['score'] >= 60:
                color = '#f39c12'
            elif result['score'] >= 40:
                color = '#e67e22'
            else:
                color = '#e74c3c'
            
            self.gen_strength_label.config(
                text=f"Strength: {strength_text}",
                fg=color
            )
            
            if result['score'] < 80:
                messagebox.showwarning(
                    "Password Strength",
                    f"Password strength is {result['strength']} ({result['score']}/100).\n\n" +
                    "Suggestions:\n" + "\n".join(f"• {s}" for s in result['feedback'])
                )
        
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def save_generated_password(self):
        password = self.gen_password_var.get()
        service = self.gen_service.get().strip()
        username = self.gen_username.get().strip()
        
        if not password:
            messagebox.showerror("Error", "No password to save! Generate one first.")
            return
        
        if self.gen_encrypt_var.get():
            passphrase = tk.simpledialog.askstring("Encryption Key", "Enter encryption key (passphrase):", show='*')
            if not passphrase:
                messagebox.showerror("Error", "Encryption key is required!")
                return
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Password File"
            )
            
            if not filename:
                return
            
            try:
                encrypted = encrypt_password(password, passphrase)
                success = save_entry(filename, service, username, encrypted, append=False)
                
                if success:
                    messagebox.showinfo("Success", f"Encrypted password saved to:\n{filename}\n\n⚠️ Remember your encryption key!")
                else:
                    messagebox.showerror("Error", "Failed to save file.")
            except Exception as e:
                messagebox.showerror("Encryption Error", str(e))
        else:
            warning_result = messagebox.askquestion(
                "⚠️ SECURITY WARNING",
                "⚠️ Saving passwords without encryption is NOT secure!\n\n"
                "• Anyone with access to the file can read your password\n"
                "• Encryption protects your passwords even if the file is stolen\n"
                "• We strongly recommend using encryption\n\n"
                "Do you want to ENCRYPT this password instead?",
                icon='warning'
            )
            
            if warning_result == 'yes':
                passphrase = tk.simpledialog.askstring("Encryption Key", "Enter encryption key (passphrase):", show='*')
                if not passphrase:
                    messagebox.showerror("Error", "Encryption key is required!")
                    return
                
                filename = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                    title="Save Password File"
                )
                
                if not filename:
                    return
                
                try:
                    encrypted = encrypt_password(password, passphrase)
                    success = save_entry(filename, service, username, encrypted, append=False)
                    
                    if success:
                        messagebox.showinfo("Success", f"Encrypted password saved to:\n{filename}\n\n⚠️ Remember your encryption key!")
                    else:
                        messagebox.showerror("Error", "Failed to save file.")
                except Exception as e:
                    messagebox.showerror("Encryption Error", str(e))
            else:
                confirm_result = messagebox.askyesno(
                    "⚠️ FINAL CONFIRMATION",
                    "Are you ABSOLUTELY SURE you want to save as plain text?\n\n"
                    "This is NOT recommended for security reasons.",
                    icon='warning'
                )
                
                if confirm_result:
                    filename = filedialog.asksaveasfilename(
                        defaultextension=".txt",
                        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                        title="Save Password File"
                    )
                    
                    if not filename:
                        return
                    
                    success = save_plain_password(filename, service, username, password, append=False)
                    
                    if success:
                        messagebox.showwarning("Saved", f"Password saved (UNENCRYPTED) to:\n{filename}\n\n⚠️ This file contains your password in plain text!")
                    else:
                        messagebox.showerror("Error", "Failed to save file.")
                else:
                    messagebox.showinfo("Cancelled", "Password not saved. Good choice for your security!")
    
    def encrypt_password_action(self):
        service = self.enc_service.get().strip()
        username = self.enc_username.get().strip()
        password = self.enc_password.get()
        passphrase = self.enc_key.get()
        
        if not password or not passphrase:
            messagebox.showerror("Error", "Password and encryption key are required!")
            return
        
        try:
            encrypted = encrypt_password(password, passphrase)
            self.enc_result.delete('1.0', 'end')
            self.enc_result.insert('1.0', encrypted)
            
            save = messagebox.askyesno("Save", "Encryption successful! Do you want to save to a file?")
            
            if save:
                filename = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                    title="Save Encrypted Password"
                )
                
                if filename:
                    success = save_entry(filename, service, username, encrypted, append=False)
                    if success:
                        messagebox.showinfo("Success", f"Saved to:\n{filename}")
                    else:
                        messagebox.showerror("Error", "Failed to save file.")
        
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
    
    def decrypt_password_action(self):
        ciphertext = self.dec_ciphertext.get('1.0', 'end-1c').strip()
        passphrase = self.dec_key.get()
        
        if not ciphertext or not passphrase:
            messagebox.showerror("Error", "Both encrypted password and key are required!")
            return
        
        try:
            decrypted = decrypt_password(ciphertext, passphrase)
            self.dec_result.config(state='normal')
            self.dec_result.delete(0, 'end')
            self.dec_result.insert(0, decrypted)
            self.dec_result.config(state='readonly')
            
            messagebox.showinfo("Success", "Decryption successful!")
        
        except ValueError as e:
            messagebox.showerror("Decryption Failed", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def check_strength_action(self):
        password = self.strength_password.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password to check!")
            return
        
        result = check_password_strength(password)
        
        output = f"{'='*50}\n"
        output += "PASSWORD STRENGTH ANALYSIS\n"
        output += f"{'='*50}\n\n"
        output += f"Password Length: {result['details']['length']} characters\n"
        output += f"Strength Score: {result['score']}/100\n"
        output += f"Strength Level: {result['strength']}\n\n"
        
        output += "Character Distribution:\n"
        output += f"  {'✓' if result['details']['has_lowercase'] else '✗'} Lowercase letters: {result['details']['lowercase_count']}\n"
        output += f"  {'✓' if result['details']['has_uppercase'] else '✗'} Uppercase letters: {result['details']['uppercase_count']}\n"
        output += f"  {'✓' if result['details']['has_numbers'] else '✗'} Numbers: {result['details']['numbers_count']}\n"
        output += f"  {'✓' if result['details']['has_symbols'] else '✗'} Symbols: {result['details']['symbols_count']}\n\n"
        
        if result['feedback']:
            output += "Suggestions for Improvement:\n"
            for i, suggestion in enumerate(result['feedback'], 1):
                output += f"  {i}. {suggestion}\n"
        
        output += f"\n{'='*50}\n"
        
        self.strength_result.config(state='normal')
        self.strength_result.delete('1.0', 'end')
        self.strength_result.insert('1.0', output)
        self.strength_result.config(state='disabled')
    
    def copy_to_clipboard(self, text):
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", "Copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "Nothing to copy!")


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
