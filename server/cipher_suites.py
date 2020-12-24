from cryptography.hazmat.primitives import ciphers, hashes
from random import choice

cipher_possibilities = ['AES-256', 'Camellia-256']
mode_posibilities = ['CBC', 'CFB', 'OFB']
hash_possibilities = ['SHA-256', 'SHA3-256']
cs_indexes = {
    'AES-256':0,
    'Camellia-256':1,
    'CBC':0,
    'CFB':1,
    'OFB':2,
    'SHA-256':0,
    'SHA3-256':1
}

CIPHERS = {
    0:ciphers.algorithms.AES,
    1:ciphers.algorithms.Camellia
}         
MODES = {
    0:ciphers.modes.CBC,
    1:ciphers.modes.CFB,
    2:ciphers.modes.OFB
}
HASHES = {
    0:hashes.SHA256,
    1:hashes.SHA3_256
}

def getCipherSuiteList(size):
    if size > len(cipher_possibilities) * len(mode_posibilities) * len(hash_possibilities):
        return None
    prefix = 'TLS_ECHDE_RSA_'
    cipher_suites = set()
    while len(cipher_suites) < size:
        cipher_suites.add(prefix + choice(cipher_possibilities) + '_' + choice(mode_posibilities) + '_' + choice(hash_possibilities))
    return cipher_suites
