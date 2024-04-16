# File Encryptor/Decryptor App

## ℹ️ Overview

This Streamlit application allows you to securely encrypt and decrypt files using the AES (Advanced Encryption Standard) algorithm. It's designed to be user-friendly and provides a straightforward interface for processing your files with high security.

## Features

🔒 **File Encryption:** Securely encrypt files with a password of your choice.  
🔓 **File Decryption:** Decrypt previously encrypted files using the original password.  
🛡️ **Secure:** Utilizes the AES encryption algorithm with GCM mode for added security.  
🖥️ **User-Friendly Interface:** Easy-to-navigate interface for encrypting and decrypting files.

## ⚠️ Warning

If you lose the password used for encryption, there is no way to recover the encrypted file. Keep your password safe!

## Installation

To use this app, you need to have Python and Streamlit installed on your machine. Follow these steps to set up the app:

1. **Clone the repository:**
   
   ```bash
   git clone https://github.com/Julienthegoat/File-Encryptor.git
   ```

git clone https://github.com/Julienthegoat/File-Encryptor.git


#Install requirements:

```bash
pip install streamlit pycryptodome
```

Navigate to the correct directory:

```bash
cd path/to/app/directory
```
Run the application:
```bash
streamlit run streamlitencrypt.py
```
