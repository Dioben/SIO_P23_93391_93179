import os
from random import randint
from cryptography.hazmat.primitives import hashes,padding
from cryptography.hazmat.primitives.ciphers import algorithms,Cipher,modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import subprocess
from cryptography import x509

CHUNK_SIZE = 1024 * 4 # Same as server so it can decrypt and send to client chunk by chunk

def server_keygen(password, file):
    password = password.encode('latin')
    writer = open(file=file, mode='wb')
    writer.write(PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=os.urandom(16),iterations=100000).derive(password))
    writer.close()

def server_encrypt_file(key_file,decrypted_file,encrypted_file):
    with open(key_file, 'rb') as key_file:
        key = key_file.read()
    iv = os.urandom(16)
    chunk_size = CHUNK_SIZE
    padder = padding.PKCS7(256).padder()
    cipher = Cipher(algorithms.AES(key),  modes.CBC(iv))
    encryptor = cipher.encryptor()
    with open(decrypted_file, 'rb') as decrypted_file, open(encrypted_file, 'wb') as encrypted_file:
        encrypted_file.write(iv)
        chunk = decrypted_file.read(chunk_size)
        while True:
            chunk = padder.update(chunk)
            chunk = encryptor.update(chunk)
            encrypted_file.write(chunk)
            chunk = decrypted_file.read(chunk_size)
            if len(chunk)<chunk_size:
                chunk = padder.update(chunk)+ padder.finalize()
                chunk = encryptor.update(chunk)+encryptor.finalize()
                encrypted_file.write(chunk)
                break
    
def server_decrypt_media_file(key_file,encrypted_file):
    proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)
    with open(key_file, 'rb') as key_file:
        key = key_file.read()
    with open(encrypted_file, 'rb') as encrypted_file:
        iv = encrypted_file.read(16)
        chunk_size = CHUNK_SIZE
        unpadder = padding.PKCS7(256).unpadder()
        cipher = Cipher(algorithms.AES(key),  modes.CBC(iv))
        decryptor = cipher.decryptor()
        chunk = encrypted_file.read(chunk_size)
        while True:
            chunk = decryptor.update(chunk)
            chunk = unpadder.update(chunk)
            proc.stdin.write(chunk)
            chunk = encrypted_file.read(chunk_size)
            if len(chunk)<chunk_size:
                chunk = decryptor.update(chunk) + decryptor.finalize()
                chunk = unpadder.update(chunk) + unpadder.finalize()
                proc.stdin.write(chunk)
                break


def server_decrypt_certificate_file(key_file,encrypted_file):
    ret = b''
    with open(key_file, 'rb') as key_file:
        key = key_file.read()
    with open(encrypted_file, 'rb') as encrypted_file:
        iv = encrypted_file.read(16)
        chunk_size = CHUNK_SIZE
        unpadder = padding.PKCS7(256).unpadder()
        cipher = Cipher(algorithms.AES(key),  modes.CBC(iv))
        decryptor = cipher.decryptor()
        chunk = encrypted_file.read(chunk_size)
        while True:
            chunk = decryptor.update(chunk)
            chunk = unpadder.update(chunk)
            ret += chunk
            chunk = encrypted_file.read(chunk_size)
            if len(chunk)<chunk_size:
                chunk = decryptor.update(chunk) + decryptor.finalize()
                chunk = unpadder.update(chunk) + unpadder.finalize()
                ret += chunk
                break
    return ret



if  __name__ == "__main__":
    key_file = 'server_rest_key'
    server_keygen('sunny afternoon', key_file)
    decrypted_file = 'catalog/'+'898a08080d1840793122b7e118b27a95d117ebce.mp3'
    encrypted_file = 'catalog/'+'898a08080d1840793122b7e118b27a95d117ebce'
    server_encrypt_file(key_file, decrypted_file, encrypted_file)
    # server_decrypt_media_file(key_file, encrypted_file)
    decrypted_file = '../client/'+'cert.der'
    encrypted_file = 'client_certificates/'+'cert'
    server_encrypt_file(key_file, decrypted_file, encrypted_file) # Reusing the function used for the media files for ease of use
    decrypted_file_contents = server_decrypt_certificate_file(key_file, encrypted_file)
    client_certificate = x509.load_der_x509_certificate(decrypted_file_contents)
    print(client_certificate)

