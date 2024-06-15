import tkinter as tk
from tkinter import messagebox

# Function to encrypt using Caesar Cipher
def encrypt_caesar(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_direction = 1 if char.islower() else -1
            shifted_char = chr(((ord(char) - ord('a' if char.islower() else 'A') + shift) % 26) + ord('a' if char.islower() else 'A'))
            encrypted_text += shifted_char
        else:
            encrypted_text += char
    return encrypted_text

# Function to decrypt using Caesar Cipher
def decrypt_caesar(encrypted_text, shift):
    decrypted_text = ""
    for char in encrypted_text:
        if char.isalpha():
            shift_direction = 1 if char.islower() else -1
            shifted_char = chr(((ord(char) - ord('a' if char.islower() else 'A') - shift + 26) % 26) + ord('a' if char.islower() else 'A'))
            decrypted_text += shifted_char
        else:
            decrypted_text += char
    return decrypted_text

# Function to handle encryption button click
def encrypt_message():
    message = entry_message.get()
    shift = int(entry_shift_encrypt.get())
    encrypted_message = encrypt_caesar(message, shift)
    label_encrypted.config(text=f"Encrypted: {encrypted_message}")

# Function to handle decryption button click
def decrypt_message():
    message = entry_message.get()
    shift = int(entry_shift_decrypt.get())
    decrypted_message = decrypt_caesar(message, shift)
    label_decrypted.config(text=f"Decrypted: {decrypted_message}")

# Clear function to reset inputs and outputs
def clear():
    entry_message.delete(0, tk.END)
    entry_shift_encrypt.delete(0, tk.END)
    entry_shift_decrypt.delete(0, tk.END)
    label_encrypted.config(text="Encrypted: ")
    label_decrypted.config(text="Decrypted: ")

# Create the main window
root = tk.Tk()
root.title("Caesar Cipher Encrypt/Decrypt")

# Labels and entry widget for message input
label_message = tk.Label(root, text="Enter message:")
label_message.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

entry_message = tk.Entry(root, width=40)
entry_message.grid(row=0, column=1, padx=10, pady=5, columnspan=2)

# Labels and entry widgets for encryption
label_shift_encrypt = tk.Label(root, text="Enter shift value for encryption:")
label_shift_encrypt.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

entry_shift_encrypt = tk.Entry(root, width=10)
entry_shift_encrypt.grid(row=1, column=1, padx=10, pady=5)

button_encrypt = tk.Button(root, text="Encrypt", command=encrypt_message)
button_encrypt.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W+tk.E)

label_encrypted = tk.Label(root, text="Encrypted: ")
label_encrypted.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)

# Labels and entry widgets for decryption
label_shift_decrypt = tk.Label(root, text="Enter shift value for decryption:")
label_shift_decrypt.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

entry_shift_decrypt = tk.Entry(root, width=10)
entry_shift_decrypt.grid(row=3, column=1, padx=10, pady=5)

button_decrypt = tk.Button(root, text="Decrypt", command=decrypt_message)
button_decrypt.grid(row=4, column=0, padx=10, pady=10, sticky=tk.W+tk.E)

label_decrypted = tk.Label(root, text="Decrypted: ")
label_decrypted.grid(row=4, column=1, padx=10, pady=5, sticky=tk.W)

# Clear button
button_clear = tk.Button(root, text="Clear", command=clear)
button_clear.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky=tk.W+tk.E)

# Start the main loop
root.mainloop()