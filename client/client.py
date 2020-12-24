import requests
import logging
import binascii
import json
import os
import subprocess
import time
import datetime
import sys
import PyKCS11
import getpass
from cryptography.hazmat.primitives import ciphers,hashes,serialization,padding,hmac
from random import choice
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asympad
import cipher_suites

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

# Load the client's hardware identification (citizen card)
lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
with open("cert.der","rb") as cert:
    CLIENT_CERTIFICATE = x509.load_der_x509_certificate(cert.read())
date = datetime.datetime.now()
if CLIENT_CERTIFICATE.not_valid_before>date or date>CLIENT_CERTIFICATE.not_valid_after:
    print("expired cert ",CLIENT_CERTIFICATE.public_key)
    sys.exit(1)
slots = pkcs11.getSlotList()
citizen_card_session = pkcs11.openSession(slots[0])

def ratchet_next(ratchet_key, HASH, salt):
    output = HKDF(algorithm=HASH(),length=80,salt=salt,info=None).derive(ratchet_key)
    ratchet_key, cipher_key, iv = output[:32], output[32:64], output[64:]
    return ratchet_key, cipher_key, iv

def main():
    
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
   
    # TODO: Secure the session
    s = requests.Session()

    # Finds 3 random possible protocol/cipher suite possibilities and a client random (random 32 bytes)
    protocol_list = list(cipher_suites.getCipherSuiteList(3))
    client_random = os.urandom(32)
    
    # Sends the protocol_list and client random to the server at /protocols
    req = s.post(f'{SERVER_URL}/api/protocols', data = client_random+json.dumps(protocol_list).encode('latin'))
    if req.status_code==200:
        print("Got Protocol List")

    # Server returns the protocol/cipher suite it chose
    cipher_suite = req.text.split('\n',1)[0].split('_')
    print("cipher suite:", cipher_suite)
    CIPHER = cipher_suites.CIPHERS[cipher_suites.cs_indexes[cipher_suite[3]]]
    MODE = cipher_suites.MODES[cipher_suites.cs_indexes[cipher_suite[4]]]
    HASH = cipher_suites.HASHES[cipher_suites.cs_indexes[cipher_suite[5]]]

    # Server returns the server's certificate and the client random signed by the server
    print("chose ",CIPHER, MODE, HASH)
    SERVER_CERTIFICATE = req.content.split(b"\n",1)[1].split(b"\n-----END CERTIFICATE-----\n")[0] +b"\n-----END CERTIFICATE-----\n"
    signed_client_random = req.content.split(b"\n-----END CERTIFICATE-----\n")[1]
    SERVER_CERTIFICATE = x509.load_pem_x509_certificate(SERVER_CERTIFICATE)

    # Checks that the server's certificate is valid
    date = datetime.datetime.now()
    if SERVER_CERTIFICATE.not_valid_before>date or date>SERVER_CERTIFICATE.not_valid_after:
        print("Expired server cert ",SERVER_CERTIFICATE.not_valid_before," - ",SERVER_CERTIFICATE.not_valid_after)
        return

    # TODO: check certificate chain

    # Checks that the server signed the client random successfully
    server_public_key = SERVER_CERTIFICATE.public_key()
    server_public_key.verify(signed_client_random,client_random,asympad.PSS(mgf=asympad.MGF1(HASH()),salt_length=asympad.PSS.MAX_LENGTH),HASH())

    # putting these in so that people cant confuse server by setting a new suite while impersonating
    s.headers.update({
        'suite_hash':(cipher_suites.cs_indexes[cipher_suite[5]]).to_bytes(1,"big"),
        'suite_cipher':(cipher_suites.cs_indexes[cipher_suite[3]]).to_bytes(1,"big"),
        'suite_mode':(cipher_suites.cs_indexes[cipher_suite[4]]).to_bytes(1,"big")})
    
    # AT THIS POINT SERVER HAS BEEN VERIFIED, WE'VE STILL GOTTA DO IT
    
    # Diffie-Hellman setup - using ephemeral elliptic for max performance/safety
    # Send salt and client's DH parameter to the server at /key
    salt = os.urandom(32)
    client_dh_private = ec.generate_private_key(ec.SECP384R1())
    client_dh = client_dh_private.public_key()
    payload = salt + client_dh.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    req = s.post(f'{SERVER_URL}/api/key',data=payload)

    # Server returns the client's ID and the server's DH parameter
    clientID = req.content.split(b"\n",1)[0].decode('latin')
    s.headers.update({'id':clientID})
    server_dh = req.content.split(b"\n",1)[1]

    # Calculates shared keys for further messaging
    server_dh = serialization.load_pem_public_key(server_dh)
    shared_key = client_dh_private.exchange(ec.ECDH(), server_dh)
    client_ratchet_key = HKDF(algorithm=HASH(),length=32,salt=salt,info=None).derive(shared_key)
    client_ratchet_send_key = client_ratchet_key
    client_ratchet_key = HKDF(algorithm=HASH(),length=32,salt=salt,info=None).derive(client_ratchet_key)
    client_ratchet_receive_key = client_ratchet_key

    # client_ratchet_send_key, client_send_key, client_send_iv = ratchet_next(client_ratchet_send_key, HASH, salt)
    # client_ratchet_receive_key, client_receive_key, client_receive_iv = ratchet_next(client_ratchet_receive_key, HASH, salt)

    # TODO: make the signature check work
    # Encrypts the client's certificate with the shared key
    client_ratchet_send_key, client_send_key, client_send_iv = ratchet_next(client_ratchet_send_key, HASH, salt)
    encryptor = ciphers.Cipher(CIPHER(client_send_key),MODE(client_send_iv)).encryptor()
    padder = padding.PKCS7(256).padder()
    encrypted_client_certificate = padder.update(CLIENT_CERTIFICATE.public_bytes(encoding=serialization.Encoding.PEM))+padder.finalize()
    encrypted_client_certificate = encryptor.update(encrypted_client_certificate)+encryptor.finalize()

    # Signs the clientID
    citizen_card_private_key = citizen_card_session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS,None) #BASICALLY MANDATORY, IT'S EITHER SHA 2 OR SHA 1/MD5 WHICH ARENT TRUSTWORTHY
    client_signature = bytes(citizen_card_session.sign(citizen_card_private_key, clientID, mechanism))
    
    # Sends the encrypted client's certificate and the signed clientID to the server at /auth
    req = s.post(f'{SERVER_URL}/api/auth',data=encrypted_client_certificate+client_signature)
    
    # Gets list of musics from the server
    req = s.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")
    content = req.content
    encrypted_data, server_data_hmac = content.split(b'\n\n\n\n\n')

    client_ratchet_receive_key, client_receive_key, client_receive_iv = ratchet_next(client_ratchet_receive_key, HASH, salt)
    client_data_hmac = hmac.HMAC(client_receive_key, HASH())
    client_data_hmac.update(encrypted_data)
    client_data_hmac = client_data_hmac.finalize()

    if server_data_hmac != client_data_hmac:
        print("Server list is corrupted")
        sys.exit(1)

    decryptor = ciphers.Cipher(CIPHER(client_receive_key), MODE(client_receive_iv)).decryptor()
    unpadder = padding.PKCS7(256).unpadder()
    encrypted_data = decryptor.update(encrypted_data)+decryptor.finalize()
    data = unpadder.update(encrypted_data)+unpadder.finalize()
    media_list = json.loads(data)

    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    # Example: Download first file
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = s.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        content = req.content
       
        # TODO: Check when server return an error instead of a chunk

        encrypted_data, server_data_hmac = content.split(b'\n\n\n\n\n')

        client_ratchet_receive_key, client_receive_key, client_receive_iv = ratchet_next(client_ratchet_receive_key, HASH, salt)
        client_data_hmac = hmac.HMAC(client_receive_key, HASH())
        client_data_hmac.update(encrypted_data)
        client_data_hmac = client_data_hmac.finalize()

        if server_data_hmac != client_data_hmac:
            print("Media chunk is corrupted")
            proc.kill()
            sys.exit(1)

        decryptor = ciphers.Cipher(CIPHER(client_receive_key), MODE(client_receive_iv)).decryptor()
        unpadder = padding.PKCS7(256).unpadder()
        encrypted_data = decryptor.update(encrypted_data)+decryptor.finalize()
        data = unpadder.update(encrypted_data)+unpadder.finalize()
        chunk = json.loads(data)

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)