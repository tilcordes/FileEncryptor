from Crypto import Random
from Crypto.Cipher import AES
from tkinter import filedialog, messagebox
import tkinter as tk
import os
import time
import hashlib
import sys

class Encryptor:
    def __init__(self, key):
        self.key = hashlib.sha256(key).digest()

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

root = tk.Tk()
root.geometry('400x200')
root.title('FileEncryptor')
root.resizable(False, False)

def get_file():
    filename = filedialog.askopenfilename(initialdir = "/",title = "Select file")
    filename_label.config(text=filename)

def encrypt():
    filename = filename_label['text']
    password = password_entry.get()
    if password == '':
        messagebox.showerror('Password-Error', 'You have to enter a password!')
    else:
        enc = Encryptor(password.encode())
        try:
            enc.encrypt_file(filename)
            filename_label.config(text='')
            password_entry.delete(0, 'end')
        except:
            messagebox.showerror('Encrypting-Error', 'An error occurred while encrypting the file!')

def decrypt():
    filename = filename_label['text']
    password = password_entry.get()
    if password == '':
        messagebox.showerror('Password-Error', 'You have to enter a password!')
    else:
        enc = Encryptor(password.encode())
        try:
            enc.decrypt_file(filename)
            filename_label.config(text='')
            password_entry.delete(0, 'end')
        except:
            messagebox.showerror('Decrypting-Error', 'An error occurred while decrypting the file!')

frame = tk.Frame(root, bg='#8ca7cf')
frame.place(relx=0.05, rely=0.05, relwidth=0.9, relheight=0.9)

filename_label = tk.Label(root, bg='#ced3db')
filename_label.place(relx=0.1, rely=0.1, relwidth=0.8, relheight=0.1)

password_label = tk.Label(root, text='Password:', bg='#ced3db')
password_label.place(relx=0.1, rely=0.25, relwidth=0.15, relheight=0.1)

password_entry = tk.Entry(root, bd=0, bg='#ced3db')
password_entry.place(relx=0.25, rely=0.25, relwidth=0.65, relheight=0.1)

file_button = tk.Button(root, text='Choose File', bd=0, fg='#0a1b38', command=get_file)
file_button.place(relx=0.4, rely=0.45, relwidth=0.2, relheight=0.1)

encrypt_button = tk.Button(root, text='Encrypt', bd=0, fg='#0a1b38', command=encrypt)
encrypt_button.place(relx=0.4, rely=0.6, relwidth=0.2, relheight=0.1)

decrypt_button = tk.Button(root, text='Decrypt', bd=0, fg='#0a1b38', command=decrypt)
decrypt_button.place(relx=0.4, rely=0.75, relwidth=0.2, relheight=0.1)

root.mainloop()
