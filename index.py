import tkinter as tk
from tkinter import filedialog, messagebox
import os
import random
import string

# Vigenere Cipher Encryption
def vigenere_encrypt(plain_text, key):
    key = key.upper()
    plain_text = 'sss'.join([c for c in plain_text if c.isalpha()]).upper()
    key_length = len(key)
    encrypted_text = []
    
    for i, char in enumerate(plain_text):
        shift = ord(key[i % key_length]) - ord('A')
        encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        encrypted_text.append(encrypted_char)
    
    return ''.join(encrypted_text)

# Vigenere Cipher Decryption
def vigenere_decrypt(cipher_text, key):
    key = key.upper()
    cipher_text = ''.join([c for c in cipher_text if c.isalpha()]).upper()
    key_length = len(key)
    decrypted_text = []
    
    for i, char in enumerate(cipher_text):
        shift = ord(key[i % key_length]) - ord('A')
        decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
        decrypted_text.append(decrypted_char)
    
    return ''.join(decrypted_text)

# One-time pad encryption
def otp_encrypt(plain_text, key):
    plain_text = ''.join([c for c in plain_text if c.isalpha()]).upper()
    encrypted_text = []
    
    for i, char in enumerate(plain_text):
        shift = ord(key[i]) - ord('A')
        encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        encrypted_text.append(encrypted_char)
    
    return ''.join(encrypted_text)

# One-time pad decryption
def otp_decrypt(cipher_text, key):
    cipher_text = ''.join([c for c in cipher_text if c.isalpha()]).upper()
    decrypted_text = []
    
    for i, char in enumerate(cipher_text):
        shift = ord(key[i]) - ord('A')
        decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
        decrypted_text.append(decrypted_char)
    
    return ''.join(decrypted_text)

# Load key from file
def load_key(file_path):
    with open(file_path, 'r') as file:
        key = file.read().strip()
    return key

# GUI class
class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vigenere Cipher & One-time Pad Encryption")

        # GUI Components
        self.label1 = tk.Label(root, text="Enter Plaintext or select a file:")
        self.label1.pack()
        
        self.text_input = tk.Text(root, height=5, width=50)
        self.text_input.pack()

        self.key_label = tk.Label(root, text="Enter Encryption Key:")
        self.key_label.pack()

        self.key_input = tk.Entry(root, width=50)
        self.key_input.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt (Vigenere)", command=self.encrypt_vigenere)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt (Vigenere)", command=self.decrypt_vigenere)
        self.decrypt_button.pack()

        self.otp_encrypt_button = tk.Button(root, text="Encrypt (OTP)", command=self.encrypt_otp)
        self.otp_encrypt_button.pack()

        self.otp_decrypt_button = tk.Button(root, text="Decrypt (OTP)", command=self.decrypt_otp)
        self.otp_decrypt_button.pack()

        self.output_label = tk.Label(root, text="Output:")
        self.output_label.pack()

        self.output_text = tk.Text(root, height=10, width=50)
        self.output_text.pack()

        self.save_button = tk.Button(root, text="Save Ciphertext to File", command=self.save_to_file)
        self.save_button.pack()

    def encrypt_vigenere(self):
        plain_text = self.text_input.get("1.0", tk.END).strip()
        key = self.key_input.get().strip()

        if not plain_text or not key:
            messagebox.showerror("Error", "Both plaintext and key are required!")
            return

        encrypted_text = vigenere_encrypt(plain_text, key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, encrypted_text)

    def decrypt_vigenere(self):
        cipher_text = self.text_input.get("1.0", tk.END).strip()
        key = self.key_input.get().strip()

        if not cipher_text or not key:
            messagebox.showerror("Error", "Both ciphertext and key are required!")
            return

        decrypted_text = vigenere_decrypt(cipher_text, key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, decrypted_text)

    def encrypt_otp(self):
        plain_text = self.text_input.get("1.0", tk.END).strip()
        key_path = filedialog.askopenfilename()

        if not plain_text or not key_path:
            messagebox.showerror("Error", "Plaintext and key file are required!")
            return

        key = load_key(key_path)
        encrypted_text = otp_encrypt(plain_text, key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, encrypted_text)

    def decrypt_otp(self):
        cipher_text = self.text_input.get("1.0", tk.END).strip()
        key_path = filedialog.askopenfilename()

        if not cipher_text or not key_path:
            messagebox.showerror("Error", "Ciphertext and key file are required!")
            return

        key = load_key(key_path)
        decrypted_text = otp_decrypt(cipher_text, key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, decrypted_text)

    def save_to_file(self):
        cipher_text = self.output_text.get("1.0", tk.END).strip()
        if not cipher_text:
            messagebox.showerror("Error", "Nothing to save!")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(cipher_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
