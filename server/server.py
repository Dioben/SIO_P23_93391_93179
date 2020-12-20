#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
from cryptography.hazmat.primitives import ciphers,hashes,serialization
from random import choice
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import uuid
from time import time
userkeys= {}
licenses = {'mike':5}
logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

HOUR = 3600
DAY = 24*3600

cipherposs = {'AES-256':ciphers.algorithms.AES,'Camellia-256':ciphers.algorithms.Camellia}
modeposs = {'CBC':ciphers.modes.CBC,'CFB':ciphers.modes.CFB,'OFB':ciphers.modes.OFB}
digests = {'SHA-256':hashes.SHA256,'SHA3-256':hashes.SHA3_256}


HASHES={0:hashes.SHA256,1:hashes.SHA3_256}
CIPHERS={(0).to_bytes(1,"big"):'AES-256',(1).to_bytes(1,"big"):'Camellia-256'}         
MODES = {(0).to_bytes(1,"big"):'CBC',(1).to_bytes(1,"big"):'CFB',(2).to_bytes(1,"big"):'OFB'}

keys= {}

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

    def do_get_protocols(self,request):#gotta restrict this to good ones only
        protocol = 'TLS_ECHDE_RSA_'
        ciphers = [x for x in request.args[b'ciphers'] if x.decode('latin') in cipherposs.keys()]
        if ciphers ==[]:
            return
        digestposs = [x for x in request.args[b'digests'] if x.decode('latin') in digests.keys()]
        if digestposs==[]:
            return
        modes = [x for x in request.args[b'modes'] if x.decode('latin') in modeposs.keys()]
        if modes==[]:
            return
        cipherchoice = choice(ciphers).decode('latin')
        protocol+="WITH_"+cipherchoice+"_"
        modechoice = choice(modes).decode('latin')
        protocol+=modechoice+"_"
        digestchoice = choice(digestposs).decode('latin')
        protocol+=digestchoice
        return protocol.encode('latin')
    # Send the list of media files to clients
    def do_list(self, request):
        if request.getHeader(b'ID') not in keys.keys():
            return "register a key first".encode('latin')
        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'


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

        return json.dumps(media_list, indent=4).encode('latin')


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
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            #elif request.uri == 'api/auth':

            elif request.path == b'/api/list':
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
        request.setResponseCode(501)
        return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()