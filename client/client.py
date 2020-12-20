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
from cryptography.hazmat.primitives import ciphers,hashes,serialization
from random import choice
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509

#consider moving these into a shared file
cipherposs = {'AES-256':ciphers.algorithms.AES,'Camellia-256':ciphers.algorithms.Camellia}
modeposs = {'CBC':ciphers.modes.CBC,'CFB':ciphers.modes.CFB,'OFB':ciphers.modes.OFB}
digests = {'SHA-256':hashes.SHA256,'SHA3-256':hashes.SHA3_256}
encodings = {'AES-256':(0).to_bytes(1,"big"),
             'Camellia-256':(1).to_bytes(1,"big"),
             'CBC':(0).to_bytes(1,"big"),
             'CFB':(1).to_bytes(1,"big"),
             'OFB':(2).to_bytes(1,"big"),
             'SHA-256':(0).to_bytes(1,"big"),
             'SHA3-256':(1).to_bytes(1,"big")}


lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
with open("cert.der","rb") as cert:
    certificate = x509.load_der_x509_certificate(cert.read())
date =datetime.datetime.now()
if certificate.not_valid_before>date or date>certificate.not_valid_after:
    print("expired cert ",certificate.public_key)
    sys.exit(0)
logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

def main():

    
    slots = pkcs11.getSlotList()
    citizencardsession = pkcs11.openSession(slots[0])
    
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
   
    # TODO: Secure the session , load our keys all the way up here
    s = requests.Session()
    
    protocolmap = {
            'ciphers':['AES-256','Camellia-256'],
            'digests':['SHA-256','SHA3-256'],
            'modes':['CBC','CFB','OFB'],
        }

    req = s.get(f'{SERVER_URL}/api/protocols',params = protocolmap)
    if req.status_code==200:
        print("Got Protocol List")
    
    suite = req.text
    info = suite.split("_")
    cipherstring =info[4]
    cipher = cipherposs[cipherstring]
    
    modestring=info[5]
    mode = modeposs[modestring]
    
    digeststring =info[6]
    hashfunc = digests[digeststring]

    print("chose ",cipherstring,modestring,digeststring)
    citizen_private_key = citizencardsession.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS,None) #BASICALLY MANDATORY, IT'S EITHER SHA 2 OR SHA 1/MD5 WHICH ARENT TRUSTWORTHY
    
    
    s.headers.update({'hashmode':encodings[digeststring],'ciphermode':encodings[cipherstring],'modemode':encodings[modestring]})#putting these in
                                                                                                                                #so that people cant confuse server
                                                                                                                                #by setting a new suite while impersonating
    #Diffie-Hellman setup- using ephemeral elliptic for max performance/safety
    salt = os.urandom(32)
    
    private_key = ec.generate_private_key(ec.SECP384R1())
    sendable_public_key = private_key.public_key()
    payload = sendable_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    req = s.post(f'{SERVER_URL}/api/key',data=salt+payload)
    serverID = req.content.split(b"\n",1)[0].decode('latin')
    peer_public_key = req.content.split(b"\n",1)[1]
    peer_public_key = serialization.load_pem_public_key(peer_public_key)
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(algorithm=hashfunc(),length=32,salt=salt,info=None).derive(shared_key)
    s.headers.update({'ID':serverID})
    req = s.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")
    media_list = req.json()


    
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
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()
       
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)