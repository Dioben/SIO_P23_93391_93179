#!/usr/bin/env python
from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
from cryptography.hazmat.primitives import ciphers,hashes,serialization,padding,hmac
from random import choice
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding as asympad
import uuid
from time import time
from cryptography import x509
import cipher_suites
import base64

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                # 'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce',
                'iv': None,
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

HOUR = 3600
DAY = 24*3600

with open("server_cert.crt","rb") as cert:
    SERVER_PEM_CERTIFICATE = cert.read()
    SERVER_CERTIFICATE = x509.load_pem_x509_certificate(SERVER_PEM_CERTIFICATE)
with open('server_cert_priv_key.pem','rb') as keyfile:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(keyfile.read(),password=None)

# Key for decrypting server files
with open('server_rest_key', 'rb') as rest_key:
    rest_key = rest_key.read()

# Contains entries: clientID<server_ratchet_receive_key, server_ratchet_send_key, salt, time_valid>
ids_info = {}

# Contains entries: client_public_key<tokens_left, time_valid>
licenses = {}

# Adding the encrypted clients' certificates in a file to licenses
trusted_client_certificates = os.scandir('client_certificates/')
for file in trusted_client_certificates:
    decrypted_file = b''
    with open(file, 'rb') as encrypted_file:
        iv = encrypted_file.read(16)
        chunk_size = CHUNK_SIZE
        unpadder = padding.PKCS7(256).unpadder()
        cipher = ciphers.Cipher(ciphers.algorithms.AES(rest_key),  ciphers.modes.CBC(iv))
        decryptor = cipher.decryptor()
        chunk = encrypted_file.read(chunk_size)
        while True:
            chunk = decryptor.update(chunk)
            chunk = unpadder.update(chunk)
            decrypted_file += chunk
            chunk = encrypted_file.read(chunk_size)
            if len(chunk)<chunk_size:
                chunk = decryptor.update(chunk) + decryptor.finalize()
                chunk = unpadder.update(chunk) + unpadder.finalize()
                decrypted_file += chunk
                break
    license_client_certificate = x509.load_der_x509_certificate(decrypted_file)
    licenses[license_client_certificate.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)] = [5, time()+HOUR/6] # TODO: increase values for delivery

# Contains entries: token<time_valid>
license_tokens = {}

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

def error_message(request, code, message):
    """ Gets the request, error code and error message 
        Prepares request to send an error 
        Returns the error content to send """
    request.setResponseCode(code)
    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
    return json.dumps({'error': message}).encode('latin')

media_file_unpadder = padding.PKCS7(256).unpadder()
media_file_algorithm = ciphers.algorithms.AES(rest_key)
def decrypt_chunk(chunk, iv):
    """ Gets media chunk to decrypt and the iv to do so 
        Returns the decrypted media chunk"""
    unpadder = media_file_unpadder
    cipher = ciphers.Cipher(media_file_algorithm, ciphers.modes.CBC(iv))
    decryptor = cipher.decryptor()
    if len(chunk)<CHUNK_SIZE:
        chunk = decryptor.update(chunk) + decryptor.finalize()
        chunk = unpadder.update(chunk) + unpadder.finalize()
    else:
        chunk = decryptor.update(chunk)
        chunk = unpadder.update(chunk)
    return chunk

class MediaServer(resource.Resource):
    isLeaf = True

    def do_protocols(self,request):
        """ Gets a request with a client random and a list of possible protocols/cipher suite
            Chooses from one of the protocols
            Returns the server certificate, the chosen protocol and the signed random"""
        data = request.content.read()
        client_random = data[0:32]
        protocol_list = json.loads(data[32::])
        # Checks if all protocol possibilities are valid
        protocol_list = [p for p in protocol_list if p.split('_')[3] in cipher_suites.cipher_possibilities and p.split('_')[4] in cipher_suites.mode_posibilities and p.split('_')[5] in cipher_suites.hash_possibilities]
        if protocol_list == []:
            protocol = 'No available protocol'
        else:
            protocol = choice(protocol_list)
        HASH = cipher_suites.HASHES[cipher_suites.cs_indexes[protocol.split('_')[5]]]
        signed_client_random = SERVER_PRIVATE_KEY.sign(
            client_random,
            asympad.PSS(
                mgf= asympad.MGF1(HASH()),
                salt_length=asympad.PSS.MAX_LENGTH
                ),
                HASH())
        return (protocol+'\n').encode('latin') + SERVER_PEM_CERTIFICATE + signed_client_random


    def do_key(self,request):
        """ Gets a request with a client salt (random bytes) and the client DH parameter (key used to find the shared key)
            Calculates the server salt, receiving key and sending key and saves in the clientID the keys, the client salt and a time limit
            Returns the clientID, server salt and the server DH parameter"""
        HASH = cipher_suites.HASHES[request.getHeader(b'suite_hash')[0]]
        data = request.content.read()
        client_salt = data[0:32]
        client_dh = data[32::]
        server_salt = os.urandom(32)

        client_dh = serialization.load_pem_public_key(client_dh)
        server_dh_private = ec.generate_private_key(ec.SECP384R1())
        server_dh = server_dh_private.public_key()
        shared_key = server_dh_private.exchange(ec.ECDH(), client_dh)
        server_ratchet_key = HKDF(algorithm=HASH(),length=32,salt=server_salt,info=None).derive(shared_key)
        server_ratchet_receive_key = server_ratchet_key
        server_ratchet_key = HKDF(algorithm=HASH(),length=32,salt=server_salt,info=None).derive(server_ratchet_key)
        server_ratchet_send_key = server_ratchet_key
        
        clientID = uuid.uuid4().hex
        ids_info[(clientID).encode('latin')] = [server_ratchet_receive_key,server_ratchet_send_key,client_salt,time()+DAY]
        
        return clientID.encode('latin')+server_salt+server_dh.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)


    def do_auth(self,request):
        """ gets a request with the client's certificate and a client signature
            Checks if the client's certificate and signature are valid
            Returns an encrypted token from the client's license """
        if request.getHeader(b'id') not in ids_info.keys():
            return error_message(request, 401, 'id not found')
        if ids_info[request.getHeader(b'id')][3]<time():
            try:
                del ids_info[request.getHeader(b'id')]
            except:
                pass
            return error_message(request, 401, 'id has expired')

        content = request.content.read()
        CIPHER = cipher_suites.CIPHERS[request.getHeader(b'suite_cipher')[0]]
        MODE = cipher_suites.MODES[request.getHeader(b'suite_mode')[0]]
        HASH = cipher_suites.HASHES[request.getHeader(b'suite_hash')[0]]

        server_ratchet_receive_key, salt = ids_info[request.getHeader(b'id')][0], ids_info[request.getHeader(b'id')][2]
        server_ratchet_receive_key, server_receive_key, server_receive_iv = ratchet_next(server_ratchet_receive_key, HASH, salt)
        ids_info[request.getHeader(b'id')][0] = server_ratchet_receive_key

        data, valid_hmac = decrypt_message_hmac(content, CIPHER, MODE, HASH, server_receive_key, server_receive_iv)
        if not valid_hmac:
            return error_message(request, 400, 'invalid auth hmac')

        client_signature_len = int.from_bytes(data[:2], 'big')

        client_certificate, client_signature = x509.load_pem_x509_certificate(data[2:-client_signature_len]), data[-client_signature_len:]

        client_certificate_public_key_bytes = client_certificate.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        if client_certificate_public_key_bytes not in licenses: # This is equivalent to checking the certificate chain licenses contains all certificates trusted by the server
            return error_message(request, 401, 'license has expired') # Message is slightly incorrect to not give information of which certificates have licenses
        license = licenses[client_certificate_public_key_bytes]
        if license[0]<=0 or license[1]<time():
            return error_message(request, 401, 'license has expired')
        license[0] -= 1

        # TODO: uncomment signature validation (only commented because it doesnt work on one of the members)
        # try:
        #     client_certificate.public_key().verify(client_signature,request.getHeader(b'id'),asympad.PKCS1v15(),hashes.SHA256())
        # except:
        #     return error_message(request, 400, 'invalid signature')

        token = base64.urlsafe_b64encode(os.urandom(256))
        license_tokens[token] = time()+HOUR/60 # TODO: increase value for delivery

        server_ratchet_send_key, salt = ids_info[request.getHeader(b'id')][1], ids_info[request.getHeader(b'id')][2]
        server_ratchet_send_key, server_send_key, server_send_iv = ratchet_next(server_ratchet_send_key, HASH, salt)
        ids_info[request.getHeader(b'id')][1] = server_ratchet_send_key

        encrypted_data, server_data_hmac = encrypt_message_hmac(token, CIPHER, MODE, HASH, server_send_key, server_send_iv)

        return encrypted_data + server_data_hmac


    def do_list(self, request):
        """ Gets a request with the token for validation
            Returns an encrypted list of all the media files """
        if request.getHeader(b'id') not in ids_info.keys():
            return error_message(request, 401, 'id not found')
        if ids_info[request.getHeader(b'id')][3]<time():
            try:
                del ids_info[request.getHeader(b'id')]
            except:
                pass
            return error_message(request, 401, 'id has expired')

        CIPHER = cipher_suites.CIPHERS[request.getHeader(b'suite_cipher')[0]]
        MODE = cipher_suites.MODES[request.getHeader(b'suite_mode')[0]]
        HASH = cipher_suites.HASHES[request.getHeader(b'suite_hash')[0]]

        server_ratchet_receive_key, salt = ids_info[request.getHeader(b'id')][0], ids_info[request.getHeader(b'id')][2]
        server_ratchet_receive_key, server_receive_key, server_receive_iv = ratchet_next(server_ratchet_receive_key, HASH, salt)
        ids_info[request.getHeader(b'id')][0] = server_ratchet_receive_key
            
        token_content = base64.urlsafe_b64decode(request.args.get(b'token', [None])[0].decode('utf-8')[2:-1])

        license_token, valid_hmac = decrypt_message_hmac(token_content, CIPHER, MODE, HASH, server_receive_key, server_receive_iv)
        if not valid_hmac:
            return error_message(request, 400, 'invalid token hmac')
        if license_token not in license_tokens.keys():
            return error_message(request, 401, 'token not found')
        if license_tokens[license_token]<time():
            return error_message(request, 401, 'token has expired')

        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        data = json.dumps(media_list, indent=4).encode('latin')

        CIPHER = cipher_suites.CIPHERS[request.getHeader(b'suite_cipher')[0]]
        MODE = cipher_suites.MODES[request.getHeader(b'suite_mode')[0]]
        HASH = cipher_suites.HASHES[request.getHeader(b'suite_hash')[0]]
        server_ratchet_send_key, salt = ids_info[request.getHeader(b'id')][1], ids_info[request.getHeader(b'id')][2]
        server_ratchet_send_key, server_send_key, server_send_iv = ratchet_next(server_ratchet_send_key, HASH, salt)
        ids_info[request.getHeader(b'id')][1] = server_ratchet_send_key

        encrypted_data, server_data_hmac = encrypt_message_hmac(data, CIPHER, MODE, HASH, server_send_key, server_send_iv)

        return encrypted_data+server_data_hmac # May be better to find another way to separate encrypted_data and server_data_hmac


    def do_download(self, request):
        """ Gets a request with the media id, the chunk wanted and the token for validation 
            Returns the encrypted media's chunk to play on ffplay"""
        if request.getHeader(b'id') not in ids_info.keys():
            return error_message(request, 401, 'id not found')
        if ids_info[request.getHeader(b'id')][3]<time():
            try:
                del ids_info[request.getHeader(b'id')]
            except:
                pass
            return error_message(request, 401, 'id has expired')

        # logger.debug(f'Download: args: {request.args}')

        CIPHER = cipher_suites.CIPHERS[request.getHeader(b'suite_cipher')[0]]
        MODE = cipher_suites.MODES[request.getHeader(b'suite_mode')[0]]
        HASH = cipher_suites.HASHES[request.getHeader(b'suite_hash')[0]]

        server_ratchet_receive_key, salt = ids_info[request.getHeader(b'id')][0], ids_info[request.getHeader(b'id')][2]
        server_ratchet_receive_key, server_receive_key, server_receive_iv = ratchet_next(server_ratchet_receive_key, HASH, salt)
        ids_info[request.getHeader(b'id')][0] = server_ratchet_receive_key

        token_content = base64.urlsafe_b64decode(request.args.get(b'token', [None])[0].decode('utf-8')[2:-1])
        license_token, valid_hmac = decrypt_message_hmac(token_content, CIPHER, MODE, HASH, server_receive_key, server_receive_iv)
        if not valid_hmac:
            return error_message(request, 400, 'invalid token hmac')
        if license_token not in license_tokens.keys():
            return error_message(request, 401, 'token not found')
        if license_tokens[license_token]<time():
            return error_message(request, 401, 'token has expired')

        id_content = base64.urlsafe_b64decode(request.args.get(b'id', [None])[0].decode('utf-8')[2:-1])

        media_id, valid_hmac = decrypt_message_hmac(id_content, CIPHER, MODE, HASH, server_receive_key, server_receive_iv)
        if not valid_hmac:
            return error_message(request, 400, 'invalid media id hmac')

        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            return error_message(request, 400, 'invalid media id')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            return error_message(request, 404, 'media file not found')
        
        # Get the media item
        media_item = CATALOG[media_id]

        chunk_content = base64.urlsafe_b64decode(request.args.get(b'chunk', [b'0'])[0].decode('utf-8')[2:-1])

        chunk_id, valid_hmac = decrypt_message_hmac(chunk_content, CIPHER, MODE, HASH, server_receive_key, server_receive_iv)
        if not valid_hmac:
            return error_message(request, 400, 'invalid media chunk id hmac')

        # Check if a chunk is valid
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            return error_message(request, 400, 'invalid media chunk id')

        logger.debug(f'Download: chunk: {chunk_id}')

        if media_item['iv'] == None:
            with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
                media_item['iv'] = f.read(16)
        media_iv = media_item['iv']

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        try:
            with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
                f.seek(offset+16)
                data = f.read(CHUNK_SIZE)

                data = decrypt_chunk(data, media_iv)

                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                data = json.dumps(
                        {
                            'media_id': media_id, 
                            'chunk': chunk_id, 
                            'data': binascii.b2a_base64(data).decode('latin').strip()
                        },indent=4
                    ).encode('latin')

                server_ratchet_send_key, salt = ids_info[request.getHeader(b'id')][1], ids_info[request.getHeader(b'id')][2]
                server_ratchet_send_key, server_send_key, server_send_iv = ratchet_next(server_ratchet_send_key, HASH, salt)
                ids_info[request.getHeader(b'id')][1] = server_ratchet_send_key

                encrypted_data, server_data_hmac = encrypt_message_hmac(data, CIPHER, MODE, HASH, server_send_key, server_send_iv)

                return encrypted_data+server_data_hmac
        except:
            # File was not open?
            return error_message(request, 500, 'unknown')

  # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received GET request for {request.uri.split(b"?",1)[0]}')
        try:
            if request.path == b'/api/list':
                return self.do_list(request)
            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
    
    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST request for {request.uri}')
        if request.path==b'/api/key':
            return self.do_key(request)
        elif request.path == b'/api/auth':
            return self.do_auth(request)
        elif request.path == b'/api/protocols':
            return self.do_protocols(request)
        request.setResponseCode(501)
        return b''


print("Server started")
print("URL is: http://IP:8080")
s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
