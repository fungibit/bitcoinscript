"""
Basic script-related definitions and low-level functions, used throughout
this package.
"""

from enum import Enum
import hashlib
from hashlib import sha256 as _sha256
import bitcoin.base58

from .opcode import OP_RETURN, OP_DUP, OP_HASH160,OP_EQUAL, OP_EQUALVERIFY, OP_CHECKSIG, OP_CHECKMULTISIG


################################################################################
# Protocol-related enums and consts

class ScriptType(Enum):
    PROVABLY_UNSPENDABLE    = 0
    P2PK                    = 1
    P2PKH                   = 2
    P2SH                    = 3
    P2MULTISIG              = 4
    OTHER                   = -1

class AddressVersion(Enum):
    P2PK    = 0x00  # "1"-prefixed address
    P2SH    = 0x05  # "3"-prefixed address

class InvalidScriptError(Exception):
    """ Exception raised for invalid/malformed scripts. """
    pass

MAX_P2SH_REDEEM_SCRIPT_SIZE = 520


################################################################################
# Hash-related functions

def sha256(x):
    return _sha256(x).digest()

def double_sha256(x):
    return sha256(sha256(x))

def ripemd160(x):
    h = hashlib.new('ripemd160')
    h.update(x)
    return h.digest()

def calc_hash160(x):
    return ripemd160(sha256(x))

def addr_to_hash160(addr):
    """
    Convert an address string (e.g. '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2') to its
    hash160 representation.

    >>> addr_to_hash160('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2').hex()
    '77bff20c60e522dfaa3350c39b030a5d004e839a'
    """
    # decode base58, and remove version byte (first byte) and checksum (last 4 bytes):
    return bitcoin.base58.decode(addr)[1:-4]

def pubkey_to_hash160(pubkey):
    """
    Convert a public key (as bytes) to to its hash160-address representation.

    >>> pubkey_to_hash160(bytes.fromhex('0283d81eda35fe96309eaf3f1ea04f45112b52fd9384161a9fdbe6f1f5b32307e1')).hex()
    '7ccf16d3763a134d86ef5504ffa723d8dbf09ba1'
    """
    return calc_hash160(pubkey)

def hash160_to_addr(hash160, is_p2sh = False):
    """
    Convert a hash160-address represenation its address string.
    
    For P2SH addresses (where hash160 is the hash of the redeem script, not a pubkey),
    pass `is_p2sh=True`.

    >>> hash160_to_addr(bytes.fromhex('7ccf16d3763a134d86ef5504ffa723d8dbf09ba1'))
    '1CNvsbUPpWMNHUkEaAnVghMAma6vSYtaHA'
    """
    if is_p2sh:
        version = AddressVersion.P2SH
    else:
        version = AddressVersion.P2PK
    version_byte = version.value.to_bytes(1, byteorder = 'big')
    hash160 = version_byte + hash160
    checksum = double_sha256(hash160)[:4]
    return bitcoin.base58.encode(hash160 + checksum)


################################################################################
# Low-level script manipulation functions

def is_outscript_p2pkh(outscript):
    """ Does the raw outscript look like a P2PKH? """
    try:
        return (
            outscript[0] == OP_DUP and
            outscript[1] == OP_HASH160 and
            outscript[-2] == OP_EQUALVERIFY and
            outscript[-1] == OP_CHECKSIG )
    except IndexError:
        return False

def is_outscript_p2pk(outscript):
    """ Does the raw outscript look like a P2PK? """
    try:
        if len(outscript) > 100: return False  # HACK...
        return outscript[-1] == OP_CHECKSIG and not is_outscript_p2pkh(outscript)
    except IndexError:
        return False

def is_outscript_p2sh(outscript):
    """ Does the raw outscript look like a P2SH? """
    try:
        return (
            len(outscript) == 23 and
            outscript[0] == OP_HASH160 and
            outscript[1] == 0x14 and
            outscript[-1] == OP_EQUAL )
    except IndexError:
        return False

def is_outscript_multisig(outscript):
    """ Does the raw outscript look like a P2MULTISIG? """
    try:
        return outscript[-1] == OP_CHECKMULTISIG
    except IndexError:
        return False

def is_outscript_provably_unspendable(outscript):
    """ Is this raw outscript provably-unspendable? """
    try:
        return outscript[0] == OP_RETURN
    except IndexError:
        return False

def get_hash160_from_outscript_p2pkh(outscript):
    """ Extract the hash160 data from a P2PKH raw outscript. """
    outscript = outscript[2 : ]
    n = outscript[0]
    return outscript[1 : n+1]

def get_pubkey_from_outscript_p2pk(outscript):
    """ Extract the pubkey data from a P2PK raw outscript. """
    n = outscript[0]
    outscript = outscript[1 : n+1]
    try:
        _get_pubkey_format(outscript)
    except ValueError:
        return None
    return outscript

def get_hash160_from_outscript_p2pk(outscript):
    """ Extract pubkey's hash160 from a P2PK raw outscript. """
    pub = get_pubkey_from_outscript_p2pk(outscript)
    if pub is None:
        return None
    return pubkey_to_hash160(pub)

def get_hash160_from_outscript_p2sh(outscript):
    """ Extract the hash160 data from a P2SH raw outscript. """
    outscript = outscript[1 : ]
    n = outscript[0]
    return outscript[1 : n+1]

def get_script_hash160_for_p2sh(outscript, check_size = True):
    """
    Calculate the script-hash to be included in a P2SH-script paying to this redeem script.
    :param check_size: make sure we're not trying to use a redeem script which is more than
        520 bytes (which will make the tx unspendable)
    """
    if check_size and len(outscript) > MAX_P2SH_REDEEM_SCRIPT_SIZE:
        raise InvalidScriptError('P2SH redeem script must be at most %s bytes' % MAX_P2SH_REDEEM_SCRIPT_SIZE)
    return calc_hash160(outscript)

def get_outscript_type(outscript, allow_p2sh = True):
    """
    Determine the script-type of the raw outscript.
    :return: a ScriptType
    """
    if is_outscript_provably_unspendable(outscript):
        return ScriptType.PROVABLY_UNSPENDABLE
    elif is_outscript_p2pkh(outscript):
        return ScriptType.P2PKH
    elif is_outscript_p2pk(outscript):
        return ScriptType.P2PK
    elif allow_p2sh and is_outscript_p2sh(outscript):
        return ScriptType.P2SH
    elif is_outscript_multisig(outscript):
        return ScriptType.P2MULTISIG
    else:
        return ScriptType.OTHER

def _get_pubkey_format(pubkey):
    if len(pubkey) == 65 and pubkey[0] == 0x04:
        return 'bin'
    elif len(pubkey) == 33 and pubkey[0] in [0x02, 0x03]:
        return 'bin_compressed'
    else:
        raise ValueError('Unknown pubkey format: %r' % pubkey)

################################################################################
