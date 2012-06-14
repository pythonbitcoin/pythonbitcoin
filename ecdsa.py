# ecdsa.py
#
# I, the copyright holder of this work, hereby release it into the public
# domain. This applies worldwide.
#
# If this is not legally possible:
# I grant any entity the right to use this work for any purpose, without any
# conditions, unless such conditions are required by law.


from tools import *

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

def randkey():
    while True:
        r = beint(urandom(32)) + 1
        if 1 <= r < _n: return r

def inversemod(a, m):
    if a < 0 or m <= a: a = a % m
    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc
    if d != 1: raise err('d is not 1', a, m)
    if ud > 0: return ud
    else: return ud + m

def doublepoint(x, y):
    if x is None: return None, None
    l = ((3 * x * x + _a) * inversemod(2 * y, _p)) % _p
    x3 = (l * l - 2 * x) % _p
    y3 = (l * (x - x3) - y) % _p
    return x3, y3

def addpoint(x1, y1, x2, y2):
    if x2 is None: return x1, y1
    if x1 is None: return x2, y2
    if x1 == x2:
        if (y1 + y2) % _p == 0:
            return None, None
        else:
            return doublepoint(x1, y1)
    l = ((y2 - y1) * inversemod(x2 - x1, _p)) % _p
    x3 = (l * l - x1 - x2) % _p
    y3 = (l * (x1 - x3) - y1) % _p
    return x3, y3

def mulpoint(x, y, e):
    e = e % _n
    if e <= 0 or x is None: return None, None
    e3 = 3 * e
    i = 1
    while i <= e3: i *= 2
    i //= 2
    x3, y3 = x, y
    i //= 2
    while i > 1:
        x3, y3 = doublepoint(x3, y3)
        if (e3 & i) != 0 and (e & i) == 0: x3, y3 = addpoint(x3, y3, x, y)
        if (e3 & i) == 0 and (e & i) != 0: x3, y3 = addpoint(x3, y3, x, -y)
        i //= 2
    return x3, y3

def checkpubkey(x, y):
    if (y * y - (x * x * x + _a * x + _b)) % _p != 0:
        raise err('not on curve', x, y)
    if mulpoint(x, y, _n) != (None, None):
        raise err('mul to _n is not None', x, y)
    return True

def sign(key, digest, nonce):
    k = nonce % _n
    r, y = mulpoint(_gx, _gy, k)
    if r == 0: raise err('r is 0', key, digest, nonce)
    s = (inversemod(k, _n) * (digest + (key * r) % _n)) % _n
    if s == 0: return err('s is 0', key, digest, nonce)
    return r, s

def verify(x, y, digest, r, s):
    checkpubkey(x, y)
    if r < 1 or r > _n - 1: raise err('incorrect r', r)
    if s < 1 or s > _n - 1: raise err('incorrect s', s)
    c = inversemod(s, _n)
    u1 = (digest * c ) % _n
    u2 = (r * c) % _n
    x1, y1 = mulpoint(_gx, _gy, u1)
    x2, y2 = mulpoint(x, y, u2)
    x, y = addpoint(x1, y1, x2, y2)
    v = x % _n
    if v == r: return True
    else: raise err('signature failed', x, y, digest, r, s)

def genkey():
    """Generate random private key"""
    return intbe(randkey(), 32)

def getpubkey(privkey):
    """Return public key for given private key"""
    if len(privkey) != 32: raise err('len privkey')
    x, y = mulpoint(_gx, _gy, beint(privkey))
    return '\x04' + intbe(x, 32) + intbe(y, 32)

def signdigest(privkey, digest):
    """Sign digest (32 bytes). Return signature in DER format"""
    if len(privkey) != 32 or len(digest) != 32: raise err('len privkey')
    r, s = sign(beint(privkey), beint(digest), randkey())
    r = intbe(r)
    if ord(r[0]) > 0x7f: r = '\0' + r
    sig = '\x02' + chr(len(r)) + r
    s = intbe(s)
    if ord(s[0]) > 0x7f: s = '\0' + s
    sig += '\x02' + chr(len(s)) + s
    sig = '\x30' + chr(len(sig)) + sig
    return sig

def verifydigest(pubkey, digest, sig):
    """Check signature (DER)"""
    if len(pubkey) != 65 or pubkey[0] != '\x04': raise err('len pubkey')
    x = beint(pubkey[1:33])
    y = beint(pubkey[33:])
    if len(digest) != 32: raise err('len digest')
    if sig[0] != '\x30' or len(sig) != ord(sig[1]) + 2: raise err('len sig')
    r = beint(sig[4:4 + ord(sig[3])])
    s = beint(sig[6 + ord(sig[3]):])
    return verify(x, y, beint(digest), r, s)

def nprivkey(mprivkey, n, mpubkey = None):
    """Get private key from main private key with n sequence (n is str)"""
    if len(mprivkey) != 32: raise err('len privkey')
    if not mpubkey:
        mpubkey = getpubkey(mprivkey)
    h = beint(dhash(n + ':' + mpubkey[1:]))
    return intbe((beint(mprivkey) + h) % _n, 32)

def npubkey(mpubkey, n):
    """Get public key from main public key with n sequence (n is str)"""
    if len(mpubkey) != 65 or mpubkey[0] != '\x04': raise err('len pubkey')
    x1 = beint(mpubkey[1:33])
    y1 = beint(mpubkey[33:])
    h = beint(dhash(n + ':' + mpubkey[1:]))
    x2, y2 = mulpoint(_gx, _gy, h)
    x, y = addpoint(x1, y1, x2, y2)
    return '\x04' + intbe(x, 32) + intbe(y, 32)

def rspubkey(digest, r, s, k):
    x = r + (k / 2) * _n
    a1 = (x * x * x + _a * x + _b) % _p
    b1 = pow(a1, (_p + 1) / 4, _p)
    if (b1 - k) % 2 == 0:
        y = b1
    else:
        y = _p - b1
    checkpubkey(x, y)
    x1, y1 = mulpoint(x, y, s)
    x2, y2 = mulpoint(_gx, _gy, -digest % _n)
    x, y = addpoint(x1, y1, x2, y2)
    x, y = mulpoint(x, y, inversemod(r, _n))
    return x, y

def msgmagic(msg):
    return "\x18Bitcoin Signed Message:\n" + intle(len(msg)) + msg

def verifymsg(hashr, msg, sig):
    """Verify message using riperm160 of sha256 hash of public key"""
    if len(hashr) != 20: raise err('len hashr')
    if len(sig) > 65: sig = b64decode(sig)
    if len(sig) == 65:
        ka = [ord(sig[0]) - 27]
        r = beint(sig[1:33])
        s = beint(sig[33:])
    elif len(sig) == 64:
        ka = xrange(2)
        r = beint(sig[:32])
        s = beint(sig[32:])
    else:
        raise err('len sig')
    digest = beint(dhash(msgmagic(msg)))
    for k in ka:
        x, y = rspubkey(digest, r, s, k)
        if hashr == rhash('\x04' + intbe(x, 32) + intbe(y, 32)):
            verify(x, y, digest, r, s)
            return chr(k + 27)
    raise err('verify hashr failed', hashr, msg, sig)

def signmsg(privkey, msg):
    """Sign message. Return sig in Base64"""
    if len(privkey) != 32: raise err('len privkey')
    r, s = sign(beint(privkey), beint(dhash(msgmagic(msg))), randkey())
    sig = intbe(r, 32) + intbe(s, 32)
    c = verifymsg(rhash(getpubkey(privkey)), msg, sig)
    return b64encode(c + sig)

