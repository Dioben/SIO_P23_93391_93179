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

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

HOUR = 3600
DAY = 24*3600

with open("127.0.0.1.crt","rb") as cert:
    certpem = cert.read()
    SELF_CERTIFICATE = x509.load_pem_x509_certificate(certpem)
with open('privkey.pem','rb') as keyfile:
    SELF_PRIVATE_KEY = serialization.load_pem_private_key(keyfile.read(),password=None)

cipherposs = {'AES-256':ciphers.algorithms.AES,'Camellia-256':ciphers.algorithms.Camellia}
modeposs = {'CBC':ciphers.modes.CBC,'CFB':ciphers.modes.CFB,'OFB':ciphers.modes.OFB}
digests = {'SHA-256':hashes.SHA256,'SHA3-256':hashes.SHA3_256}


HASHES={0:hashes.SHA256,1:hashes.SHA3_256}
CIPHERS={0:'AES-256',1:'Camellia-256'}         
MODES = {0:'CBC',1:'CFB',2:'OFB'}

keys={}
licenses = {}
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

class MediaServer(resource.Resource):
    isLeaf = True


    def do_key_set(self,request):
        encoding = request.getHeader(b'hashmode')[0]
        peer_public_key= request.content.read()
        salt = peer_public_key[0:32]
        peer_public_key = peer_public_key[32::]

        peer_public_key = serialization.load_pem_public_key(peer_public_key)
        private_key = ec.generate_private_key(ec.SECP384R1())
        sendable_public_key = private_key.public_key()
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(algorithm= HASHES[encoding](),length=32,salt=salt,info=None).derive(shared_key)
        
        user = uuid.uuid4().hex
        keys[(user).encode('latin')]= (derived_key,time()+DAY)
        
        
        return (user+"\n").encode('latin')+sendable_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)


    def do_get_protocols(self,request):
        data = request.content.read()
        secret = data[0:32]
        protocolmap = json.loads(data[32::])
        protocol = 'TLS_ECHDE_RSA_'
        ciphers = [x for x in protocolmap['ciphers'] if x in cipherposs.keys()]
        if ciphers ==[]:
            protocol='No available ciphers'
        digestposs = [x for x in protocolmap['digests'] if x in digests.keys()]
        if digestposs==[]:
            protocol='No available digests'
        modes = [x for x in protocolmap['modes'] if x in modeposs.keys()]
        if modes==[]:
            protocol='No available modes'
        cipherchoice = choice(ciphers)
        protocol+="WITH_"+cipherchoice+"_"
        modechoice = choice(modes)
        protocol+=modechoice+"_"
        digestchoice = choice(digestposs)
        
        if digestchoice =='SHA-256':
            hashf = hashes.SHA256
        elif digestchoice=='SHA3-256':
            hashf = hashes.SHA3_256
        
        protocol+=digestchoice+"\n"

        encrypted_secret = SELF_PRIVATE_KEY.sign(
            secret,
            asympad.PSS(
                mgf= asympad.MGF1(hashf()),
                salt_length=asympad.PSS.MAX_LENGTH
                ),
                hashf())
        msg = protocol.encode('latin')+certpem+encrypted_secret
        return msg

    # Send the list of media files to clients
    def do_list(self, request):
        if request.getHeader(b'ID') not in keys.keys():
            request.setResponseCode(401)
            return "register a key first".encode('latin')
        if keys[request.getHeader(b'ID')][1]<time():
            try:
                del keys[request.getHeader(b'ID')]
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

    
    
    
    
  

    def try_auth(self,request):
        if request.getHeader(b'ID') not in keys.keys():
            return "register a key first".encode('latin')
        if keys[request.getHeader(b'ID')][1]<time():
            try:
                del keys[request.getHeader(b'ID')]
            except:
                pass
            request.setResponseCode(401)
            return "your key has expired".encode('latin')
        data = request.content.read()
        iv = data[0:16]
        algo= CIPHERS[request.getHeader(b'ciphermode')[0]]
        digest = HASHES[request.getHeader(b'hashmode')[0]]
        mode = MODES[request.getHeader(b'modemode')[0]]
        key = keys[request.getHeader(b'id')][0]
        unpadder = padder = padding.PKCS7(256).unpadder()
        decryptor = ciphers.Cipher(cipherposs[algo](key),modeposs[mode](iv)).decryptor()
        cert = decryptor.update(data[16:-384])+decryptor.finalize()
        cert = unpadder.update(cert)+unpadder.finalize()
        cert = x509.load_pem_x509_certificate(cert)
        sig = data[-384:]
        cert.public_key().verify(sig,request.getHeader(b'ID'),asympad.PKCS1v15(),hashes.SHA256())
        licensekey = os.urandom(256) 
        licenses[request.getHeader(b'ID')]=(cert.public_key(),key,time()+HOUR) #this should  be PUBLIC KEY - LICENSE - EXPIRE TIME
        return key



















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
            return self.do_key_set(request)
        elif request.path == b'/api/auth':
            return self.try_auth(request)
        elif request.path == b'/api/protocols':
                return self.do_get_protocols(request)
        request.setResponseCode(501)
        return b''






print("Server started")
print("URL is: http://IP:8080")
#TODO: WE PROBABLY WANNA LOAD CERTS AROUND HERE
s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()