# bitcoin.py
#
# I, the copyright holder of this work, hereby release it into the public
# domain. This applies worldwide.
#
# If this is not legally possible:
# I grant any entity the right to use this work for any purpose, without any
# conditions, unless such conditions are required by law.

from tools import *
from ecdsa import *

# Client version
_cversion = 62000
# Main network magic value. Included in all message headers.
_magicvalue = '\xF9\xBE\xB4\xD9'
# 32 zero bytes
_zerohash = '\0' * 32
# Input index for coinbase tx
_noindex = 0xffffffff
# 1 BTC
_bc = float(100000000)
# Total 21 million BTC
_totalcoins = 2100000000000000 
# 50 BTC per block
_startcoinbase = 5000000000 
# Coinbase value is halved each 210000 blocks (4 years)
_coinbasechange = 210000
# Highest possible target (bits 1d00ffff)
_maxtarget = 0x00000000ffff0000000000000000000000000000000000000000000000000000
# Target is changed every 2016 blocks
_targetchange = 2016
# 2 weeks timespan
_targettimespan = _targetchange * 600
# Min and max timespan for target change
_mintimespan = _targettimespan / 4
_maxtimespan = _targettimespan * 4
# Last block key in Db
_lastblock = '\0'

class _input:
    """Tx.inputs"""
    prevtx = _zerohash  # Hash of the referenced transaction
    index = _noindex    # Index of the specific output in the transaction
    sig = ''           # Signature script
    sequence = _noindex # Transaction version as defined by sender

class _output:
    """Tx.outputs"""
    value =  0  # Transaction value
    pubkey = '' # Public key script

class _tx:
    """Bitcoin transaction"""
    version = 1    # Transaction data format version
    inputs = None  # List of sources for coins
    outputs = None # List of destination for coins
    locktime = 0   # Block number or timestamp at whith this tx locked
    o = 0          # New offset (o + length of tx message)

def decodetx(p, o = 0):
    """Decode tx message from bytecode. Return tx object"""
    tx = _tx()
    tx.version, o = getint(p, o, 4)
    if tx.version != 1: raise err('tx.version', tx.version)
    incount, o = getvarint(p, o)
    tx.inputs = []
    for i in xrange(incount):
        txinput = _input()
        txinput.prevtx, o = getbin(p, o, 32)
        txinput.index, o = getint(p, o, 4)
        txinput.sig, o = getvarstr(p, o)
        txinput.sequence, o = getint(p, o, 4)
        if txinput.sequence != _noindex:
            raise err('txinput.sequence', i, txinput.sequence)
        tx.inputs.append(txinput)
    outcount, o = getvarint(p, o)
    tx.outputs = []
    for i in xrange(outcount):
        txoutput = _output()
        txoutput.value, o = getint(p, o, 8)
        if txoutput.value < 1 or txoutput.value > _totalcoins:
            raise err('txoutput.value', i, txoutput.value)
        txoutput.pubkey, o = getvarstr(p, o)
        tx.outputs.append(txoutput)
    if not tx.inputs or not tx.outputs: raise err('empty tx')
    tx.locktime, o = getint(p, o, 4)
    if tx.locktime != 0 : raise err('tx.locktime', tx.locktime)
    tx.o = o
    return tx
    
def encodetx(tx):
    """Encode tx object. Return bytecode"""
    b = putint(tx.version, 4) + putvarint(len(tx.inputs))
    for txinput in tx.inputs:
        b += (putbin(txinput.prevtx, 32) + putint(txinput.index, 4)
            + putvarstr(txinput.sig) + putint(txinput.sequence, 4))
    b += putvarint(len(tx.outputs))
    for txoutput in tx.outputs:
        b += putint(txoutput.value, 8) + putvarstr(txoutput.pubkey)
    b += putint(tx.locktime, 4)
    return b

class _block:
    """Bitcoin block"""
    version = 1               # Block format version
    prevblock = _zerohash     # Hash of the previous block
    merkleroot = _zerohash    # Hash of transactions in block
    timestamp = 0             # Unix timestamp
    bits = '\xff\xff\x00\x1d' # Difficulty target
    nonce = 0                 # Random nonce
    tx = None                 # List of tx objects
    txb = None                # List of tx in bytecode
    o = 0                     # New offset (o + length of block message)

def decodeblock(p, o = 0):
    """Decode block message from bytecode. Return block object"""
    if len(p) < 80: raise err('len block header')
    block = _block()
    block.version, o = getint(p, o, 4)
    if block.version != 1: raise ('block.version', block.version)
    block.prevblock, o = getbin(p, o, 32)
    block.merkleroot, o = getbin(p, o, 32)
    block.timestamp, o = getint(p, o, 4)
    block.bits, o = getbin(p, o, 4)
    block.nonce, o = getint(p, o, 4)
    if len(p) > 81:
        block.tx = []
        block.txb = []
        count, o = getvarint(p, o)
        for i in xrange(count):
            tx = decodetx(p, o)
            block.tx.append(tx)
            block.txb.append(p[o:tx.o])
            o = tx.o
    block.o = o
    return block

def encodeblock(block):
    """Encode block object. Return bytecode"""
    b = (putint(block.version, 4) + putbin(block.prevblock, 32)
        + putbin(block.merkleroot, 32) + putint(block.timestamp, 4)
        + putbin(block.bits, 4) + putint(block.nonce, 4))
    if block.tx:
        b += putvarint(len(block.tx))
        for tx in block.tx:
            b += encodetx(tx)
    else:
        b += putvarint(len(block.txb))
        for txb in block.txb:
            b += txb
    return b

class _netaddr:
    """Msg.addr"""
    timestamp = 0
    services, ip, port = 1, '10.2.2.2', 8333

class _netmsg:
    """Network message"""
    cmd = '' # Message type
    p = ''   # Message bytecode without header
    o = 0    # New offset (o + length of message)
    # Cmd 'version' - exchanged when first connecting
    version = _cversion
    services = 1
    timestamp = 0
    recvservices, recvip, recvport = 1, '10.2.2.2', 8333
    fromservices, fromip, fromport = 1, '10.3.3.3', 8333
    nonce = '\0' * 8
    useragent = ''
    startheight = 0
    # Cmd 'verask' - reply to version
    # Cmd 'getaddr' - request for addr
    # Cmd 'addr' - list of nodes
    addr = None # List of netaddr objects
    # Cmd 'inv' - list of new block or transactions
    blocks = None # List of block hashes
    txs = None    # List of tx hashes
    # Cmd 'getdata' - request for block or tx, same as inv
    # Cmd 'getheaders' - request for headers
    hashes = None        # List of known block hashes
    hashstop = _zerohash # Last block hash
    # Cmd 'getblocks' - request for inv, same as getheaders
    # Cmd 'tx' - see decodetx(), p contain tx bytecode
    # Cmd 'block' - see decodeblock(), p contain block bytecode
    # Cmd 'headers' - list of block headers
    headers = None # List of block headers bytecode, see decodeblock()
    
def decodemsg(m, o = 0):
    """Decode message from bytecode. Return msg object"""
    # For incompleted messages, return None
    # For incorrent checksum, msg.cmd contain '!', msg.o - new offset
    msg = _netmsg()
    while True:
        if o >= len(m): return
        magic, o = getbin(m, o, 4)
        if magic == _magicvalue: break
        o -= 3
    msg.cmd, o = getbin(m, o, 12)
    msg.cmd = msg.cmd.replace('\0', '')
    length, o = getint(m, o, 4)
    checksum, o = getbin(m, o, 4)
    p, o = getbin(m, o, length)
    msg.p = p
    msg.o = o
    if (len(p) != length): return
    if dhash(p)[0:4] != checksum:
        msg.cmd += '!'
        return msg
        
    if msg.cmd == 'version':
        msg.version, o = getint(p, 0, 4)
        msg.services, o = getint(p, o, 8)
        msg.timestamp, o = getint(p, o, 8)
        msg.recvservices, o = getint(p, o, 8)
        msg.recvip, msg.recvport, o = getip(p, o)
        msg.fromservices, o = getint(p, o, 8)
        msg.fromip, msg.fromport, o = getip(p, o)
        msg.nonce, o = getbin(p, o, 8)
        msg.useragent, o = getvarstr(p, o)
        msg.startheight, o = getint(p, o, 4)
    elif msg.cmd == 'addr':
        count, o = getvarint(p, 0)
        msg.addr = []
        for i in xrange(count):
            addr = _netaddr()
            addr.timestamp, o = getint(p, o, 4)
            addr.services, o = getint(p, o, 8)
            addr.ip, addr.port, o = getip(p, o)
            msg.addr.append(addr)
    elif msg.cmd in ('inv', 'getdata'):
        count, o = getvarint(p, 0)
        msg.txs = []
        msg.blocks = []
        for i in xrange(count):
            t, o = getint(p, o, 4)
            h, o = getbin(p, o, 32)
            if t == 1:
                msg.txs.append(h)
            elif t == 2:
                msg.blocks.append(h)
    elif msg.cmd in ('getblocks', 'getheaders'):
        msg.version, o = getint(p, 0, 4)
        count, o = getvarint(p, o)
        msg.hashes = []
        for i in xrange(count):
            h, o = getbin(p, o, 32)
            msg.hashes.append(h)
        msg.hashstop, o = getbin(p, o, 32)
    elif msg.cmd == 'headers':
        count, o = getvarint(p, 0)
        msg.headers = []
        for i in xrange(count):
            h, o = getbin(p, o, 81)
            msg.headers.append(h[:80])
    return msg

def encodemsg(cmd, msg = ''):
    """Encode msg object or add header to bytecode"""
    if type(msg) == str:
        p = msg
    elif msg.cmd == 'version':
        if not msg.timestamp: msg.timestamp = itime()
        p = (putint(msg.version, 4) + putint(msg.services, 8)
            + putint(msg.timestamp, 8) + putint(msg.recvservices, 8)
            + putip(msg.recvip, msg.recvport) + putint(msg.fromservices, 8)
            + putip(msg.fromip, msg.fromport) + putbin(msg.nonce, 8)
            + putvarstr(msg.useragent) + putint(msg.startheight, 4))
    elif msg.cmd == 'addr':
        p = putvarint(len(msg.addr))
        for addr in msg.addr:
            p += (putint(addr.timestamp, 4) + putint(addr.services, 8)
                + putip(addr.ip, addr.port))
    elif msg.cmd in ('inv', 'getdata'):
        p = putvarint(len(msg.txs) + len(msg.blocks))
        for h in msg.txs:
             p += putint(1, 4) + putbin(h, 32)
        for h in msg.blocks:
             p += putint(2, 4) + putbin(h, 32)
    elif msg.cmd in ('getblocks', 'getheaders'):
        p = putint(msg.version, 4) + putvarint(len(msg.hashes))
        for h in msg.hashes:
            p += putbin(h, 32)
        p += putbin(msg.hashstop, 32)
    elif msg.cmd == 'headers':
        p = putvarint(len(msg.headers))
        for header in msg.headers:
            p += putbin(header, 81)
    return _magicvalue + putbin(cmd, 12) + putint(len(p), 4) + dhash(p)[0:4] + p



Db = anydbm.open(...)
Db[_lastblock] = _zerohash



def getcoinbase(blocknum):
    """Return coinbase value for given blocknum"""
    w = blocknum // _coinbasechange
    a = _startcoinbase
    for i in xrange(w): a //= 2
    return a

def decodebits(b):
    """Convert bits to target"""
    i = leint(b[:3])
    p = ord(b[3])
    return i * 256 ** (p - 3)

def getdi(target):
    """Return difficulty for given target"""
    return float(_maxtarget) / target

def updatetarget(oldtarget, timespan):
    """Calculate target for given timespan"""
    if timespan < _mintimespan: timespan = _mintimespan
    if timespan > _maxtimespan: timespan = _maxtimespan
    target = oldtarget * timespan / _targettimespan
    # Round value
    p = 0
    while target > 0x7fffff:
        target //= 256
        p += 1
    target *= 256 ** p
    if target > _maxtarget: target = _maxtarget
    return target

def verifysig(stpub, txb, i):
    """Verify sig pubkey script pair"""
    txcopy = decodetx(txb)
    stsig = txcopy.inputs[i].sig
    if ord(stsig[0]) == len(stsig) - 1 and stsig[-1] == '\x01':
        sig = stsig[1:-1]
    elif stsig[ord(stsig[0]):ord(stsig[0]) + 2] == '\x01\x41':
        sig = stsig[1:ord(stsig[0])]
        pub = stsig[ord(stsig[0]) + 2:]
    else: raise err('unknown sig format')
    if ord(stpub[0]) == len(stpub) - 2 and stpub[-1] == '\xac':
        pub = stpub[1:-1]
    elif stpub[0:3] == '\x76\xa9\x14' and stpub[23:25] == '\x88\xac':
        hashr = stpub[3:23]
        if hashr != rhash(pub): return 'err rhash'
    else: raise err('unknown pub format')
    for k, cinput in enumerate(txcopy.inputs):
        if i == k: cinput.sig = stpub
        else: cinput.sig = ''
    txcopyhash = dhash(encodetx(txcopy) + putint(1, 4))
    verifydigest(pub, txcopyhash, sig)

def decodepub(stpub):
    """Get rhash of pubkey from pubkey script"""
    if ord(stpub[0]) == len(stpub) - 2 and stpub[-1] == '\xac':
        pub = stpub[1:-1]
        hashr = rhash(pub)
    elif stpub[0:3] == '\x76\xa9\x14' and stpub[23:25] == '\x88\xac':
        hashr = stpub[3:23]
    else: raise err('unknown pub format')
    return [hashr]

def readblocknum(h):
    """Get block number by block hash"""
    if h not in Db: return
    return leint(Db[h][80:])

def readblockhash(n):
    """Get block hash by block number"""
    n = intle(n, 4)
    if n not in Db: return
    return Db[n][:32]

def readheader(h):
    """Get block header bytecode by block hash or number"""
    if type(h) == int: h = readblockhash(h)
    if h is None or h not in Db: return
    return Db[h][:80]

def readblocktx(n):
    """Get list of tx hashes by block hash or number"""
    if type(n) == str: n = readblocknum(n)
    if n is None: return
    n = intle(n, 4)
    if n not in Db: return
    l = Db[n]
    txs = []
    for i in xrange(32, len(l), 32): txs.append(l[i:i + 32])
    return txs

def readtx(h):
    """Get tx bytecode by tx hash"""
    if h not in Db: return
    return Db[h][6:]

def readtxblock(h):
    """Get (blocknum, txnum) by tx hash"""
    if h not in Db: return
    return leint(Db[h][:4]), leint(Db[h][4:6])

def readblock(h):
    """Get block bytecode by block hash or number"""
    bb = readheader(h)
    if bb is None: return
    txs = readblocktx(h)
    bb += putvarint(len(txs))
    for txhash in txs: bb += readtx(txhash)
    return bb

def readspend(prevtx, index):
    """Get new tx hash by prev tx hash and output index"""
    k = prevtx + intle(index, 2)
    if k not in Db: return
    return Db[k]

def readaddrtx(baddr):
    """Get list of (blocknum, txnum) by rhash of pubkey"""
    if baddr not in Db: return
    l = Db[baddr]
    txn = []
    for i in xrange(0, len(l), 6):
        txn.append((leint(l[i:i + 4]), leint(l[i + 4:i + 6])))
    return txn

def readlasthash():
    """Get hash of last block in blockchain"""
    return Db[_lastblock]

def writedat(dat, lastblock):
    """Write dat records to Db"""
    Db[_lastblock] = lastblock
    for k in dat:
        if len(k) == 20 and k in Db: Db[k] += dat[k]
        elif dat[k] is None: del Db[k]
        else: Db[k] = dat[k]

def verifyblocktx(b, bb, blockhash, num, dat = None):
    """Verify txs in block. Return dat records"""
    if len(b.tx) < 1: raise err('empty block')
    # Verify Merkle tree
    if len(b.tx) == 1:
        mroot = dhash(b.txb[0])
        txh = [mroot]
    else:
        mtree = []
        for tx in b.txb:
            mtree.append(dhash(tx))
        txh = mtree
        while len(mtree) != 1:
            if len(mtree) % 2: mtree.append(mtree[-1])
            ntree = []
            for i in xrange(1, len(mtree), 2):
                ntree.append(dhash(mtree[i - 1] + mtree[i]))
            mtree = ntree
        mroot = mtree[0]
    if mroot != b.merkleroot: raise err('merkleroot')
    # Records in dat will be added to Db
    if dat is None: dat = {}
    # Header record. block hash (32) : block header (80) block number (4)
    dat[blockhash] = bb[:80] + intle(num, 4)
    numrec = blockhash
    for n, txb in enumerate(b.txb):
        # Tx record. tx hash (32) : block number (4) tx number (2) tx bytecode
        dat[txh[n]] = intle(num, 4) + intle(n, 2) + txb
        numrec += txh[n]
    # Num record. blocknumber (4) : block hash (32) list of tx hashes (32)
    dat[intle(num, 4)] = numrec
    
    fee = 0
    for n, tx in enumerate(b.tx):
        txvalue = 0
        addrlist = []
        for i, txinput in enumerate(tx.inputs):
            if not n: break
            if txinput.prevtx == _zerohash: raise err('coinbase')
            btx = readtx(txinput.prevtx)
            if not btx and txinput.prevtx in dat: btx = dat[txinput.prevtx][6:]
            if not btx: raise err('no prevtx')
            ptx = decodetx(btx)
            if txinput.index >= len(ptx.outputs): raise err('no index')
            if readspend(txinput.prevtx, txinput.index):
                raise err('double spend')
            verifysig(ptx.outputs[txinput.index].pubkey, b.txb[n], i)
            # Spend record. prev tx hash (32) prev tx index (2) : new tx hash
            dat[txinput.prevtx + intle(txinput.index, 2)] = txh[n]
            addrlist += decodepub(ptx.outputs[txinput.index].pubkey)
            txvalue += ptx.outputs[txinput.index].value
        for txoutput in tx.outputs:
            addrlist += decodepub(txoutput.pubkey)
            if n: txvalue -= txoutput.value
        if txvalue < 0: raise err('txvalue')
        fee += txvalue
        for baddr in addrlist:
            if baddr not in dat: dat[baddr] = ''
            # Addr record. hashr (20) : list of block number (4) tx number (2)
            dat[baddr] += intle(num, 4) + intle(n, 2)
        
    coinbase = b.tx[0]
    if (len(coinbase.inputs) != 1 or coinbase.inputs[0].prevtx != _zerohash
        or coinbase.inputs[0].index != _noindex): raise err('no coinbase')
    coinbasevalue = 0
    for txoutput in coinbase.outputs: coinbasevalue += txoutput.value
    if coinbasevalue != getcoinbase(num) + fee: raise err('bad coinbase')
    
    return dat

def acceptblock(bb):
    """Verify block and add to blockchain"""
    blockhash = dhash(bb[:80])
    if readheader(blockhash): raise err('duplicate')
    b = decodeblock(bb)
    blocktarget = decodebits(b.bits)
    # Hash of the block header must be lower than or equal to the target
    if leint(blockhash) > blocktarget: raise err('blockhash')
    lastblock = readlasthash()
    
    if b.prevblock == lastblock:
        # Add to main branch
        pass
    else: raise err('prevblock')
    if lastblock != _zerohash:
        num = readblocknum(lastblock) + 1
        # Last target change block
        tbnum = (num - 1) // _targetchange * _targetchange
        tb = decodeblock(readheader(tbnum))
        # Current target
        target = decodebits(tb.bits)
        # Update target every 2016 block
        if not num % _targetchange:
            pb = decodeblock(readheader(num - 1))
            target = updatetarget(target, pb.timestamp - tb.timestamp)
    else:
        num = 0
        target = _maxtarget
    # Bits must be equal to the current target
    if blocktarget != target: raise err('bits')
    dat = verifyblocktx(b, bb, blockhash, num)
    """if branch not in Branches: Branches.append(branch)
    if branch is not Mainbranch:
        if branch.di > Mainbranch.di:
            # A side branch becoming the main branch
            del Branches[branchid]
            p = b
            # For blocks in new main branch
            while _sidebranch + p.prevblock in Db:
                del Db[_sidebranch + p.prevblock]
                p = decodeblock(p.prevblock)
            forkblock = p.prevblock
            branchid = len(Branches)
            phash = Mainbranch.lastblock
            # For blocks in old main branch
            while phash != forkblock:
                Db[_sidebranch + phash] = branchid
                p = decodeblock(phash)
                phash = p.prevblock
            Branches.append(Branches[0])
            Branches[0] = branch
        else:
            Db[_sidebranch + blockhash] = branchid"""
    writedat(dat, blockhash)

def docommand(c):
    r = ''
    c = c.split(' ')
    if c[0] == 'blocks':
        if len(c) < 3: count = 20
        else: count = int(c[2])
        if len(c) < 2: start = readblocknum(readlasthash()) - 19
        else: start = int(c[1])
        for num in xrange(start, start + count):
            bh = readblockhash(num)
            if not bh: break
            b = decodeblock(readheader(bh))
            r += str(num) + ' ' + stime(b.timestamp) + '\n' + tohexl(bh) + '\n'
    
    if c[0] == 'tx':
        if len(c[1]) == 64:
            txhash = unhexl(c[1])
            blocknum, txnum = readtxblock(txhash)
        else:
            l = c[1].split('.')
            blocknum = int(l[0])
            txnum = int(l[1])
            txs = readblocktx(blocknum)
            txhash = txs[txnum]
        tx = decodetx(readtx(txhash))
        r += str(blocknum) + '.' + str(txnum) + ' ' + tohexl(txhash) + '\n'
        txvalue = 0
        if txnum:
            r += 'From:\n'
            for txinput in tx.inputs:
                ptx = decodetx(readtx(txinput.prevtx))
                pb, pt = readtxblock(txinput.prevtx)
                poutput = ptx.outputs[txinput.index]
                r += str(poutput.value / _bc) + ' '
                r += encodeaddr(decodepub(poutput.pubkey)[0]) + ' '
                r += str(pb) + '.' + str(pt) + '.' + str(txinput.index) + '\n'
                txvalue += poutput.value
        r += 'To:\n'
        for txoutput in tx.outputs:
            r += str(txoutput.value / _bc) + ' '
            r += encodeaddr(decodepub(txoutput.pubkey)[0]) + '\n'
            txvalue -= txoutput.value
        txvalue /= _bc
        if not txnum: r += 'Generation: ' + str(- txvalue) + '\n'
        elif txvalue: r += 'Fee: ' + str(txvalue) + '\n'
    
    if c[0] == 'block':
        if len(c[1]) == 64:
            bh = unhexl(c[1])
            num = readblocknum(bh)
        else:
            num = int(c[1])
            bh = readblockhash(num)
        r += str(num) + ' ' + tohexl(bh) + '\n'
        b = decodeblock(readheader(bh))
        r += 'Prev block: ' + tohexl(b.prevblock) + '\n'
        nextblock = readblockhash(num + 1)
        if nextblock: r += 'Next block: ' + tohexl(nextblock) + '\n'
        else: r += 'Last block\n'
        r += 'Merkle root: ' + tohexl(b.merkleroot) + '\n'
        r += 'Time: ' + stime(b.timestamp) + ' (' + str(b.timestamp) + ')\n'
        r += 'Difficulty: ' + str(getdi(decodebits(b.bits)))
        r += ' (Bits: ' + tohexl(b.bits) + ')\n'
        r += 'Nonce: ' + str(b.nonce) + '\n'
        txs = readblocktx(bh)
        for txhash in txs: r += '\n' + docommand('tx ' + tohexl(txhash))
    
    if c[0] == 'addr':
        hashr = decodeaddr(c[1])
        txn = readaddrtx(hashr)
        for blocknum, txnum in txn: 
            r += '\n' + docommand('tx ' + str(blocknum) + '.' + str(txnum))
    return r




def verifydigest(*a): pass

def ver():
    count = 2000
    count = -1
    timestart = time()
    try:
        fb =  open('blockchain', 'r')
        o = 0
        bc = 1024 * 1024 * 10
        bs = 1024 * 1024 * 12
        buf = fb.read(bs)

        while True:
            if o > bc:
                buf = buf[o:]
                o = 0
                buf += fb.read(bs)
            if o >= len(buf): break
            block = decodeblock(buf, o)
            acceptblock(buf[o:block.o])
            print readblocknum(readlasthash()), \
                stime(decodeblock(readheader(readlasthash())).timestamp), \
                len(readblocktx(readlasthash()))
            o = block.o
            count -= 1
            if count == 0: break
    finally:
        timespan = time() - timestart
        fb.close()
        print '-' * 78
        print 'Last block:'
        print readblocknum(readlasthash()), \
            stime(decodeblock(readheader(readlasthash())).timestamp)
        print tohexl(readlasthash())
        print timespan, 'sec'
        print (readblocknum(readlasthash()) + 1) / timespan, 'block/sec'
        print '-' * 80
    from traceback import format_exc
    while True:
        c = raw_input()
        try:
            print docommand(c)
        except:
            print format_exc()
    

def testsignmsg():
    timestart = time()
    for i in xrange(100):
        print 'i', i
        priv = genkey()
        print 'priv', tohex(priv)
        msg = repr(urandom(i * 8 + 15))
        print 'msg', msg
        sig = signmsg(priv, msg)
        print 'sig', sig
        pub = getpubkey(priv)
        print 'pub', tohex(pub)
        v = rhash(pub)
        print 'v', tohex(v)
        a = encodeaddr(v)
        print 'a', a
        r = decodeaddr(a)
        print 'r', tohex(r)
        if r != v: raise err('r != v')
        verifymsg(r, msg, sig)
        digest = dhash(msg)
        print 'digest', tohex(digest)
        s = signdigest(priv, digest)
        print 's', tohex(s)
        verifydigest(pub, digest, s)
        for n in xrange(2):
            for m in xrange(3):
                print 'n:m', str(n) + ':' + str(m)
                npriv = nprivkey(priv, str(n) + ':' + str(m), pub)
                print 'npriv', tohex(npriv)
                d = urandom(32)
                print 'd', tohex(d)
                g = signdigest(npriv, d)
                print 'g', tohex(g)
                npub = npubkey(pub, str(n) + ':' + str(m))
                print 'npub', tohex(npub)
                verifydigest(npub, d, g)
                vpub = getpubkey(npriv)
                print 'vpub', tohex(vpub)
                if vpub != npub: raise err('vpub != npub')
    print time() - timestart, 'sec'

