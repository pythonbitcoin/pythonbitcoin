# tools.py
#
# I, the copyright holder of this work, hereby release it into the public
# domain. This applies worldwide.
#
# If this is not legally possible:
# I grant any entity the right to use this work for any purpose, without any
# conditions, unless such conditions are required by law.

from hashlib import sha256, new as hashnew
from time import time, gmtime, strftime
from binascii import b2a_hex as tohex, a2b_hex as unhex
from base64 import b64encode, b64decode
from os import urandom

err = RuntimeError

def itime():
    """Return current timestamp as int"""
    return int(time())

def stime(t):
    """Convert timestamp to string UTC"""
    return strftime('%d.%m.%Y %H:%M:%S', gmtime(t))

def intle(i, l = None):
    """Convert int to little endian bytecode"""
    b = ''
    while i != 0:
        b += chr(i % 256)
        i //= 256
    if l:
        b += '\0' * (l - len(b))
        if len(b) != l: raise err('integer overflow', i, l)
    return b

def leint(b):
    """Convert little endian bytecode to int"""
    i = 0
    p = 1
    for c in b:
        i += ord(c) * p
        p *= 256
    return i

def intbe(i, l = None):
    """Convert int to big endian bytecode"""
    b = ''
    while i != 0:
        b = chr(i % 256) + b
        i //= 256
    if l:
        b = '\0' * (l - len(b)) + b
        if len(b) != l: raise err('integer overflow', i, l)
    return b

def beint(b):
    """Convert big endian bytecode to int"""
    i = 0
    for c in b:
        i = ord(c) + i * 256
    return i

def tohexl(b):
    """Convert little endian bytecode to hex"""
    return tohex(b[::-1])

def unhexl(h):
    """Convert hex to little endian bytecode"""
    return unhex(h)[::-1]

def dhash(s):
    """Double sha256"""
    return sha256(sha256(s).digest()).digest()

def rhash(s):
    """Ripemd160 of sha256"""
    r = hashnew('ripemd160')
    r.update(sha256(s).digest())
    return r.digest()

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encodeaddr(b, v = 0):
    """Encode Base64Check"""
    b = chr(v) + b
    b += dhash(b)[:4]
    
    i = beint(b)
    a = ''
    while i != 0:
        a = b58[i % 58] + a
        i //= 58
    z = 0
    for c in b:
        if c == '\0': z += 1
        else: break
    
    return b58[0] * z + a

def decodeaddr(a, v = 0):
    """Decode Base64Check"""
    i = 0
    for c in a:
        i = b58.find(c) + i * 58
    b = intbe(i)
    z = 0
    for c in a:
        if c == b58[0]: z += 1
        else: break
    b = '\0' * z + b
    
    if b[0] != chr(v): raise err('version', a, v)
    if dhash(b[:-4])[:4] != b[-4:]: raise err('checksum', a, v)
    return b[1:-4]

def putint(i, l):
    """Convert int to bytecode integer size l"""
    return intle(i, l)

def putvarint(i):
    """Convert int to bytecode variable length interger"""
    if i < 0xfd:
        l = 1
        f = ''
    elif i < 0xffff:
        l = 2
        f = '\xfd'
    elif i < 0xffffffff:
        l = 4
        f = '\xfe'
    else:
        l = 8
        f = '\xff'
    return f + intle(i, l)

def putvarstr(s):
    """Convert str to bytecode variable length string"""
    return putvarint(len(s)) + s

def putbin(s, l):
    """Convert str to bytecode fixed length string"""
    while len(s) < l: s += chr(0)
    if len(s) != l: raise err('string overflow', s, l)
    return s

def putip(ip, port):
    """Convert ip and port to bytecode"""
    b = '\0' * 10 + '\xFF\xFF'
    for n in ip.split('.'): b += chr(int(n))
    return b + chr(port // 256) + chr(port % 256)

def getint(s, o, l):
    """Read integer from bytecode offset o size l. Return (int, new_offset)"""
    return leint(s[o:o + l]), o + l

def getvarint(s, o):
    """Read variable length integer from bytecode. Return (int, new_offset)"""
    if s[o] == '\xfd': l = 2
    elif s[o] == '\xfe': l = 4
    elif s[o] == '\xff': l = 8
    else: l = 1
    if l > 1: o += 1
    return leint(s[o:o + l]), o + l

def getvarstr(s, o):
    """Read variable length string from bytecode. Return (int, new_offset)"""
    l, o = getvarint(s, o)
    return s[o:o + l], o + l

def getbin(s, o, l):
    """Read fixed length string from bytecode. Return (str, new_offset)"""
    return s[o:o + l], o + l

def getip(s, o):
    """Read ip and port from bytecode. Return (ip, port, new_offset)"""
    if s[o:o + 12] == '\0' * 10 + '\xFF\xFF':
        return (str(ord(s[o + 12])) + '.' + str(ord(s[o + 13])) + '.'
            + str(ord(s[o + 14])) + '.' + str(ord(s[o + 15])),
            ord(s[o + 16]) * 256 + ord(s[o + 17]), o + 18)

