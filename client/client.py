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
import base64

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
    logger.error("expired cert "+str(CLIENT_CERTIFICATE))
    sys.exit(1)
slots = pkcs11.getSlotList()
citizen_card_session = pkcs11.openSession(slots[0])

def ratchet_next(ratchet_key, HASH, salt):
    """ Gets current key and the hash and salt for the derivation
        Returns next derivation of key, a key for a cipher and an iv for a cipher"""
    output = HKDF(algorithm=HASH(),length=80,salt=salt,info=None).derive(ratchet_key)
    ratchet_key, cipher_key, iv = output[:32], output[32:64], output[64:]
    return ratchet_key, cipher_key, iv

def encrypt_message_hmac(data, CIPHER, MODE, HASH, key, iv):
    """ Gets data to encrypt and the cipher, mode, hash, key and iv necessary to do so
        Returns the encrypted data and an hmac for authentication and integrity verification """
    encryptor = ciphers.Cipher(CIPHER(key),MODE(iv)).encryptor()
    padder = padding.PKCS7(256).padder()
    encrypted_data = padder.update(data)+padder.finalize()
    encrypted_data = encryptor.update(encrypted_data)+encryptor.finalize()
    data_hmac = hmac.HMAC(key, HASH())
    data_hmac.update(encrypted_data)
    data_hmac = data_hmac.finalize() # Has to send finalize because only bytes can be sent (is then compared with the other side's finalize)
    return encrypted_data, data_hmac

def decrypt_message_hmac(data, CIPHER, MODE, HASH, key, iv):
    """ Gets data+hmac to decrypt and the cipher, mode, hash, key and iv necessary to do so
        Returns the decrypted data and a boolean with the validity of the hmac """
    encrypted_data, data_hmac = data[:-32], data[-32:]
    data_hmac_2 = hmac.HMAC(key, HASH())
    data_hmac_2.update(encrypted_data)
    data_hmac_2 = data_hmac_2.finalize()
    if data_hmac != data_hmac_2:
        return None, False
    decryptor = ciphers.Cipher(CIPHER(key), MODE(iv)).decryptor()
    unpadder = padding.PKCS7(256).unpadder()
    encrypted_data = decryptor.update(encrypted_data)+decryptor.finalize()
    data = unpadder.update(encrypted_data)+unpadder.finalize()
    return data, True

def is_error_message(req):
    """ Gets request 
        Returns if the request was successful and prints the error if not """
    try:
        logger.error(str(req.status_code)+': '+str(req.json()['error'])) # Error messages are not encrypted
        return True
    except:
        return 200>=req.status_code>=300

def _get_all_certificates():
    """ Returns all certificates in the client's machine (/etc/ssl/certs/) """
    ret = {}
    files = os.scandir("/etc/ssl/certs")
    for file in files:
        if not file.is_dir():
            with open(file,"rb") as file:
                data = file.read()
                certificate = x509.load_pem_x509_certificate(data)
                date = datetime.datetime.now()
                if certificate != None and certificate.not_valid_before<date<certificate.not_valid_after:
                    ret[certificate.subject]=certificate
    return ret

def is_certificate_trusted(certificate : x509.Certificate):
    """ Gets a certificate 
        Returns if the certificate's issuer is root and in the client's machine """
    cert_dict = _get_all_certificates()
    if certificate.issuer in cert_dict.keys():
        while certificate.issuer != certificate.subject:
            if certificate.issuer not in cert_dict.keys():
                return False
            cert_dict[certificate.issuer].public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                asympad.PKCS1v15(),
                certificate.signature_hash_algorithm
            )
            certificate = cert_dict[certificate.issuer]
        return True
    return False

def main():
    
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    logger.info("Contacting Server")
   
    s = requests.Session()

    # Finds 3 random possible protocol/cipher suite possibilities and a client random (random 32 bytes)
    protocol_list = list(cipher_suites.getCipherSuiteList(3))
    client_random = os.urandom(32)
    
    # Sends the protocol_list and client random to the server at /protocols
    req = s.post(f'{SERVER_URL}/api/protocols', data = client_random+json.dumps(protocol_list).encode('latin'))
    if is_error_message(req):
        return
    logger.info("Protocols successful")

    # Server returns the protocol/cipher suite it chose
    cipher_suite = req.text.split('\n',1)[0].split('_')
    logger.info("cipher suite: "+req.text.split('\n',1)[0])
    CIPHER = cipher_suites.CIPHERS[cipher_suites.cs_indexes[cipher_suite[3]]]
    MODE = cipher_suites.MODES[cipher_suites.cs_indexes[cipher_suite[4]]]
    HASH = cipher_suites.HASHES[cipher_suites.cs_indexes[cipher_suite[5]]]

    # Server returns the server's certificate and the client random signed by the server
    SERVER_CERTIFICATE = req.content.split(b"\n",1)[1].split(b"\n-----END CERTIFICATE-----\n")[0] +b"\n-----END CERTIFICATE-----\n"
    signed_client_random = req.content.split(b"\n-----END CERTIFICATE-----\n")[1]
    SERVER_CERTIFICATE = x509.load_pem_x509_certificate(SERVER_CERTIFICATE)

    # Checks that the server's certificate is valid
    date = datetime.datetime.now()
    if SERVER_CERTIFICATE.not_valid_before>date or date>SERVER_CERTIFICATE.not_valid_after:
        logger.error("Expired server cert: "+str(SERVER_CERTIFICATE.not_valid_before)+" - "+str(SERVER_CERTIFICATE.not_valid_after))
        return
    if SERVER_CERTIFICATE.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value != SERVER_URL.split('//',1)[1].split(':',1)[0]:
        logger.error("Incorrect server common name: "+SERVER_CERTIFICATE.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)
        return

    # Checks that the client trusts the server's certificate (looks at the certificates in /etc/ssl/certs/)
    if not is_certificate_trusted(SERVER_CERTIFICATE):
        logger.error("Server's certificate is not trusted")
        return

    # Checks that the server signed the client random successfully
    server_public_key = SERVER_CERTIFICATE.public_key()
    server_public_key.verify(signed_client_random,client_random,asympad.PSS(mgf=asympad.MGF1(HASH()),salt_length=asympad.PSS.MAX_LENGTH),HASH())

    # putting these in so that people cant confuse server by setting a new suite while impersonating
    s.headers.update({
        'suite_hash':(cipher_suites.cs_indexes[cipher_suite[5]]).to_bytes(1,"big"),
        'suite_cipher':(cipher_suites.cs_indexes[cipher_suite[3]]).to_bytes(1,"big"),
        'suite_mode':(cipher_suites.cs_indexes[cipher_suite[4]]).to_bytes(1,"big")}) # TODO: maybe make the server save them so they cant be changed
    
    # Diffie-Hellman setup - using ephemeral elliptic for max performance/safety

    # Send a client salt and client's DH parameter to the server at /key
    client_salt = os.urandom(32)
    client_dh_private = ec.generate_private_key(ec.SECP384R1())
    client_dh = client_dh_private.public_key()
    payload = client_salt + client_dh.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    req = s.post(f'{SERVER_URL}/api/key',data=payload)
    if is_error_message(req):
        return
    logger.info("Key successful")

    # Server returns the client's ID, a server salt and the server's DH parameter
    content = req.content
    clientID = content[:32].decode('latin')
    s.headers.update({'id':clientID})
    server_salt = content[32:64]
    server_dh = content[64:]

    # Calculates shared keys for further messaging from both salts
    server_dh = serialization.load_pem_public_key(server_dh)
    shared_key = client_dh_private.exchange(ec.ECDH(), server_dh)
    client_ratchet_key = HKDF(algorithm=HASH(),length=32,salt=server_salt,info=None).derive(shared_key)
    client_ratchet_send_key = client_ratchet_key
    client_ratchet_key = HKDF(algorithm=HASH(),length=32,salt=server_salt,info=None).derive(client_ratchet_key)
    client_ratchet_receive_key = client_ratchet_key

    salt = client_salt

    # Signs the clientID
    citizen_card_private_key = citizen_card_session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS,None) #BASICALLY MANDATORY, IT'S EITHER SHA 2 OR SHA 1/MD5 WHICH ARENT TRUSTWORTHY
    client_signature = bytes(citizen_card_session.sign(citizen_card_private_key, clientID.encode('latin'), mechanism))

    # Sends the encrypted client's certificate and the signed clientID to the server at /auth
    client_ratchet_send_key, client_send_key, client_send_iv = ratchet_next(client_ratchet_send_key, HASH, salt)
    encrypted_data, client_data_hmac = encrypt_message_hmac(len(client_signature).to_bytes(2, 'big')+CLIENT_CERTIFICATE.public_bytes(encoding=serialization.Encoding.PEM)+client_signature, CIPHER, MODE, HASH, client_send_key, client_send_iv)
    req = s.post(f'{SERVER_URL}/api/auth',data=encrypted_data+client_data_hmac)
    if is_error_message(req):
        return
    logger.info("Auth successful")

    # Server returns an encrypted license token to send with every message
    content = req.content
    client_ratchet_receive_key, client_receive_key, client_receive_iv = ratchet_next(client_ratchet_receive_key, HASH, salt)
    token, valid_hmac = decrypt_message_hmac(content, CIPHER, MODE, HASH, client_receive_key, client_receive_iv)
    if not valid_hmac:
        logger.error("Server license token is corrupted")
        return

    # Sends the encrypted token to the server at /list
    client_ratchet_send_key, client_send_key, client_send_iv = ratchet_next(client_ratchet_send_key, HASH, salt)
    encrypted_token, client_token_hmac = encrypt_message_hmac(token, CIPHER, MODE, HASH, client_send_key, client_send_iv)
    req = s.get(f'{SERVER_URL}/api/list?token={base64.urlsafe_b64encode(encrypted_token+client_token_hmac)}')
    if is_error_message(req):
        return
    logger.info("List successful")

    # Server returns an encrypted list of all the music
    content = req.content
    client_ratchet_receive_key, client_receive_key, client_receive_iv = ratchet_next(client_ratchet_receive_key, HASH, salt)
    data, valid_hmac = decrypt_message_hmac(content, CIPHER, MODE, HASH, client_receive_key, client_receive_iv)
    if not valid_hmac:
        logger.error("Server list is corrupted")
        return
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

        # Sends an encrypted media id, media chunk and token to the server at /download
        client_ratchet_send_key, client_send_key, client_send_iv = ratchet_next(client_ratchet_send_key, HASH, salt)
        encrypted_media_id, client_media_id_hmac = encrypt_message_hmac(media_item["id"].encode('latin'), CIPHER, MODE, HASH, client_send_key, client_send_iv)
        encrypted_media_chunk, client_media_chunk_hmac = encrypt_message_hmac(str(chunk).encode('latin'), CIPHER, MODE, HASH, client_send_key, client_send_iv)
        encrypted_token, client_token_hmac = encrypt_message_hmac(token, CIPHER, MODE, HASH, client_send_key, client_send_iv)
        req = s.get(f'{SERVER_URL}/api/download?id={base64.urlsafe_b64encode(encrypted_media_id+client_media_id_hmac)}&chunk={base64.urlsafe_b64encode(encrypted_media_chunk+client_media_chunk_hmac)}&token={base64.urlsafe_b64encode(encrypted_token+client_token_hmac)}')
        if is_error_message(req):
            return

        # Server returns the encrypted chunk to play on ffplay
        content = req.content
        client_ratchet_receive_key, client_receive_key, client_receive_iv = ratchet_next(client_ratchet_receive_key, HASH, salt)
        data, valid_hmac = decrypt_message_hmac(content, CIPHER, MODE, HASH, client_receive_key, client_receive_iv)
        if not valid_hmac:
            logger.error("Media chunk is corrupted")
            break
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