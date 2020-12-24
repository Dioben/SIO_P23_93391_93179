#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
from cryptography.hazmat.primitives import ciphers,hashes,serialization,padding
from random import choice
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding as asympad
import uuid
from time import time
from cryptography import x509
import cipher_suites

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
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

HOUR = 3600
DAY = 24*3600

with open("127.0.0.1.crt","rb") as cert:
    SERVER_PEM_CERTIFICATE = cert.read()
    SERVER_CERTIFICATE = x509.load_pem_x509_certificate(SERVER_PEM_CERTIFICATE)
with open('privkey.pem','rb') as keyfile:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(keyfile.read(),password=None)

# Contains entries: clientID<server_ratchet_receive_key,server_ratchet_send_key,salt,time_valid>
ids_info={}

licenses = {}

def ratchet_next(ratchet_key, HASH, salt):
    output = HKDF(algorithm=HASH(),length=80,salt=salt,info=None).derive(ratchet_key)
    ratchet_key, cipher_key, iv = output[:32], output[32:64], output[64:]
    return ratchet_key, cipher_key, iv

class MediaServer(resource.Resource):
    isLeaf = True

    def do_protocols(self,request):
        """ Gets client random and a list of possible protocols/cipher suite
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
        """ Gets salt (random bytes) and the client DH parameter (key used to find the shared key)
            Calculates shared key and saves the clientID and its time
            Returns the clientID and the server DH parameter"""
        HASH = cipher_suites.HASHES[request.getHeader(b'suite_hash')[0]]
        data = request.content.read()
        salt = data[0:32]
        client_dh = data[32::]

        client_dh = serialization.load_pem_public_key(client_dh)
        server_dh_private = ec.generate_private_key(ec.SECP384R1())
        server_dh = server_dh_private.public_key()
        shared_key = server_dh_private.exchange(ec.ECDH(), client_dh)
        server_ratchet_key = HKDF(algorithm=HASH(),length=32,salt=salt,info=None).derive(shared_key)
        server_ratchet_receive_key = server_ratchet_key
        server_ratchet_key = HKDF(algorithm=HASH(),length=32,salt=salt,info=None).derive(server_ratchet_key)
        server_ratchet_send_key = server_ratchet_key

        # server_ratchet_receive_key, server_receive_key, server_receive_iv = ratchet_next(server_ratchet_receive_key, HASH, salt)
        # server_ratchet_send_key, server_send_key, server_send_iv = ratchet_next(server_ratchet_send_key, HASH, salt)
        
        clientID = uuid.uuid4().hex
        ids_info[(clientID).encode('latin')] = [server_ratchet_receive_key,server_ratchet_send_key,salt,time()+DAY]
        
        return (clientID+"\n").encode('latin')+server_dh.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)


    def do_auth(self,request):
        """ Recieves the client's certificate and a client signature 
            TODO: Finish this javadoc after i'm sure of what this function does """
        if request.getHeader(b'id') not in ids_info.keys():
            return "register a key first".encode('latin')
        if ids_info[request.getHeader(b'id')][3]<time():
            try:
                del ids_info[request.getHeader(b'id')]
            except:
                pass
            request.setResponseCode(401)
            return "your key has expired".encode('latin')
        data = request.content.read()
        CIPHER = cipher_suites.CIPHERS[request.getHeader(b'suite_cipher')[0]]
        MODE = cipher_suites.MODES[request.getHeader(b'suite_mode')[0]]
        HASH = cipher_suites.HASHES[request.getHeader(b'suite_hash')[0]]

        server_ratchet_receive_key, salt = ids_info[request.getHeader(b'id')][0], ids_info[request.getHeader(b'id')][2]
        server_ratchet_receive_key, server_receive_key, server_receive_iv = ratchet_next(server_ratchet_receive_key, HASH, salt)
        ids_info[request.getHeader(b'id')][0] = server_ratchet_receive_key

        unpadder = padding.PKCS7(256).unpadder()
        decryptor = ciphers.Cipher(CIPHER(server_receive_key), MODE(server_receive_iv)).decryptor()
        client_certificate = decryptor.update(data[:-384])+decryptor.finalize()
        client_certificate = unpadder.update(client_certificate)+unpadder.finalize()
        client_certificate = x509.load_pem_x509_certificate(client_certificate)
        client_signature = data[-384:]
        client_certificate.public_key().verify(client_signature,request.getHeader(b'id'),asympad.PKCS1v15(),hashes.SHA256())

        # TODO: look properly at the rest of the comment
        # license_key = os.urandom(256) # TODO: unused
        # licenses[request.getHeader(b'id')]=(client_certificate.public_key(),derived_key,time()+HOUR) #this should  be PUBLIC KEY - LICENSE - EXPIRE TIME
        # return derived_key # TODO: this shouldnt be sending the derived key, right?
        return None


    # Send the list of media files to clients
    def do_list(self, request):
        if request.getHeader(b'id') not in ids_info.keys():
            request.setResponseCode(401)
            return "register a key first".encode('latin')
        if ids_info[request.getHeader(b'id')][3]<time():
            try:
                del ids_info[request.getHeader(b'id')]
            except:
                pass
            request.setResponseCode(401)
            return "your key has expired".encode('latin')
        #TODO: ENCRYPT WITH SHARED KEY,sign


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
        return data


    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

  # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')
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
        logger.debug(f'Received POST for {request.uri}')
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
#TODO: WE PROBABLY WANNA LOAD CERTS AROUND HERE
s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()