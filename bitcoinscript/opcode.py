"""
Definition and basic operations related to script opcodes.

:note: Many of the definitions here are imported from python-bitcoinlib's `bitcoin.core.script`,
    or are simple wrappers around definitions from there.
"""

import struct

import hashlib
from hashlib import sha256 as _sha256, sha1 as _sha1

from bitcoin.core.script import *
from bitcoin.core.script import CScriptOp, OPCODES_BY_NAME, _bchr


################################################################################

# add the "OP_TRUE" and "OP_FALSE" aliases to OPCODES_BY_NAME:
OPCODES_BY_NAME = dict(OPCODES_BY_NAME, OP_FALSE = OPCODES_BY_NAME['OP_0'], OP_TRUE = OPCODES_BY_NAME['OP_1'])

def is_opcode(x):
    """
    >>> is_opcode(OP_PUSHDATA2)
    True
    >>> is_opcode(0x4d)
    False
    """
    return isinstance(x, CScriptOp)

def get_opcode_by_name(opname):
    """
    >>> get_opcode_by_name('OP_PUSHDATA2')
    OP_PUSHDATA2
    >>> get_opcode_by_name('OP_TRUE')
    OP_1
    """
    return OPCODES_BY_NAME[opname]

def get_opcode_const(n):
    """
    >>> get_opcode_const(4)
    OP_4
    """
    return CScriptOp.encode_op_n(n)

def encode_op_pushdata(d, force_pushdata = None):
    """
    Encode a PUSHDATA op, returning bytes

    :param force_pushdata: set to 1/2/4, to force using OP_PUSHDATA1/2/4, instead the shortest
        appropriate OP_PUSHDATAX.
    :note: This function is a modified copy of python-bitcoinlib's encode_op_pushdata, adding
        the force_pushdata args.

    >>> encode_op_pushdata(b'X').hex()
    '0158'
    >>> encode_op_pushdata(b'X', force_pushdata=2).hex()
    '4d010058'

    """
    if force_pushdata is None:
        force_pushdata = 0
    if len(d) < 0x4c and force_pushdata <= 0:
        return b'' + _bchr(len(d)) + d # OP_PUSHDATA
    elif len(d) <= 0xff and force_pushdata <= 1:
        return b'\x4c' + _bchr(len(d)) + d # OP_PUSHDATA1
    elif len(d) <= 0xffff and force_pushdata <= 2:
        return b'\x4d' + struct.pack(b'<H', len(d)) + d # OP_PUSHDATA2
    elif len(d) <= 0xffffffff:
        return b'\x4e' + struct.pack(b'<I', len(d)) + d # OP_PUSHDATA4
    else:
        raise ValueError("Data too long to encode in a PUSHDATA op")

################################################################################
# Hash functions

def _opify(hash_func):
    # add a "OP" attribute to the function
    hash_func.OP = get_opcode_by_name('OP_%s' % hash_func.__name__)
    return hash_func

@_opify
def RIPEMD160(x):
    """ hashed using RIPEMD-160. """
    h = hashlib.new('RIPEMD160')
    h.update(x)
    return h.digest()

@_opify
def SHA1(x):
    """ hashed using SHA-1. """
    return _sha1(x).digest()

@_opify
def SHA256(x):
    """ hashed using SHA-256. """
    return _sha256(x).digest()

@_opify
def HASH160(x):
    """ hashed twice: first with SHA-256 and then with RIPEMD-160. """
    return RIPEMD160(SHA256(x))

@_opify
def HASH256(x):
    """ hashed two times with SHA-256. """
    return SHA256(SHA256(x))


HASH_FUNCTIONS = dict(
    RIPEMD160 = RIPEMD160,
    SHA1 = SHA1,
    SHA256 = SHA256,
    HASH160 = HASH160,
    HASH256 = HASH256,
)

def to_hash_function(x):
    """
    A convenience function for convert anything to a hash function.
    
    >>> to_hash_function(SHA1)
    <function bitcoinscript.opcode.SHA1>
    >>> to_hash_function(OP_SHA1)
    <function bitcoinscript.opcode.SHA1>
    >>> to_hash_function('SHA1')
    <function bitcoinscript.opcode.SHA1>
    >>> to_hash_function('OP_SHA1')
    <function bitcoinscript.opcode.SHA1>
    """
    orig_x = x
    x = getattr(x, '__name__', x)  # function -> name
    if isinstance(x, CScriptOp):  # CScriptOp -> name
        x = str(x)
    if isinstance(x, str):
        # remove 'OP_' prefix
        if x.startswith('OP_'):
            x = x[len('OP_') : ]
        try:
            return HASH_FUNCTIONS[x]
        except KeyError:
            raise ValueError('Unknown hash function: %s' % x)
    raise TypeError('Cannot convert value to a hash function: %r' % orig_x)

def is_hash_op(x):
    """
    >>> is_hash_op(OP_RIPEMD160)
    True
    >>> is_hash_op(OP_PUSHDATA4)
    False
    """
    try:
        to_hash_function(x)
        return True
    except (ValueError, TypeError):
        return False

################################################################################
