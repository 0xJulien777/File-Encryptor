import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Encrypts the input file content
def encrypt_file(content, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(content)
    return cipher.nonce, salt, tag, ciphertext

# Decrypts the input file content
def decrypt_file(nonce, salt, tag, ciphertext, password):
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# Streamlit UI

st.image('C:/Users/julie/Downloads/encryptorimage.svg')

st.title("File Encryptor/Decryptor 🔐/🔓")


st.write('This tool allows you to encrypt 🔐 and decrypt 🔓 files using the AES encryption algorithm. Keep ypur password safe! 🗝️')
st.warning('Warning : If you lose the password used for encryption, the file will be lost forever. There is no way to recover it. 🚫')
operation = st.radio("Choose an operation:", ['Encrypt 🔐', 'Decrypt 🔓'])
uploaded_file = st.file_uploader("Choose a file 📝")

if uploaded_file is not None:
    password = st.text_input("Password:", type="password", help="Enter a password for the encryption/decryption 🗝️ ")

    if password and st.button('Process'):
        file_bytes = uploaded_file.getvalue()

        if operation == 'Encrypt 🔐':
            try:
                nonce, salt, tag, ciphertext = encrypt_file(file_bytes, password)
                encrypted_file = nonce + salt + tag + ciphertext
                st.download_button(label="Download Encrypted File ⬇️",
                                   data=encrypted_file,
                                   file_name=uploaded_file.name + '.enc')
                st.success("File encrypted successfully! You can now download the encrypted file.")
            except Exception as e:
                st.error(f"⚠️ An error occurred during encryption: {str(e)}")

        elif operation == 'Decrypt 🔓':
            try:
                nonce, salt, tag = file_bytes[:16], file_bytes[16:32], file_bytes[32:48]
                ciphertext = file_bytes[48:]
                plaintext = decrypt_file(nonce, salt, tag, ciphertext, password)
                st.download_button(label="Download Decrypted File ⬇️",
                                   data=plaintext,
                                   file_name='decrypted_' + uploaded_file.name.replace('.enc', ''))
                st.success("File decrypted successfully! You can now download the decrypted file.")
            except Exception as e:
                st.error(f"⚠️ An error occurred during decryption: {str(e)}")



st.write("Made with ❤️ by Julien.G - - - [Check out the code on GitHub 😼](https://github.com/Julienthegoat) - - - [Let's connect on Linkedin ! 🌐](https://www.linkedin.com/in/julien-guinot-33a2b01ba/)")
st.write("If you like this app, consider giving it a ⭐ on GitHub and sharing it with your friends! :smile:")
st.write("Thank you for using this app! 🚀")
st.write("If you have any feedback or questions, feel free to reach out! :notebook:")