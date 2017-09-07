"""
Basic script-related definitions and low-level functions, used throughout
this package.
"""

import functools
import itertools
from enum import Enum
import bitcoin.base58
from bitcoin.core.script import CScript as _CScript, CScriptInvalidError as _CScriptInvalidError

from .opcode import (
    OP_RETURN, OP_DUP, OP_DROP, OP_HASH160,OP_EQUAL, OP_EQUALVERIFY,
    OP_IF, OP_ELSE, OP_ENDIF,
    OP_CHECKSIG, OP_CHECKMULTISIG, OP_CHECKLOCKTIMEVERIFY,
    )
from .opcode import HASH160, HASH256, to_hash_function, is_hash_op


################################################################################
# Protocol-related enums and consts

class ScriptType(Enum):
    PROVABLY_UNSPENDABLE    = 0
    P2PK                    = 1
    P2PKH                   = 2
    P2SH                    = 3
    P2MULTISIG              = 4
    TIMELOCK                = 5
    IF                      = 6
    HASH_PREIMAGE           = 7
    OTHER                   = -1

class AddressVersion(Enum):
    P2PK    = 0x00  # "1"-prefixed address
    P2SH    = 0x05  # "3"-prefixed address

class InvalidScriptError(Exception):
    """ Exception raised for invalid/malformed scripts. """
    pass

MAX_P2SH_REDEEM_SCRIPT_SIZE = 520

LOCKTIME_THRESHOLD = 500000000

################################################################################
# Hash-related functions

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
    return HASH160(pubkey)

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
    checksum = HASH256(hash160)[:4]
    return bitcoin.base58.encode(hash160 + checksum)


################################################################################
# Low-level script manipulation functions

def _suppress_script_errors(is_script_type_func):
    @functools.wraps(is_script_type_func)
    def wrapper(*a, **kw):
        try:
            return is_script_type_func(*a, **kw)
        except (
            _CScriptInvalidError,  # invalid/malformed script
            InvalidScriptError,  # invalid/malformed script
            IndexError,  # expected a longer script
            StopIteration,  # expected a longer script
            ):
            return False
    return wrapper

@_suppress_script_errors
def is_outscript_p2pkh(outscript):
    """ Does the raw outscript look like a P2PKH? """
    return (
        outscript[0] == OP_DUP and
        outscript[1] == OP_HASH160 and
        outscript[-2] == OP_EQUALVERIFY and
        outscript[-1] == OP_CHECKSIG )

@_suppress_script_errors
def is_outscript_p2pk(outscript):
    """ Does the raw outscript look like a P2PK? """
    parts = list(iter_script_parts(outscript))
    return len(parts) == 2 and parts[-1] == OP_CHECKSIG

@_suppress_script_errors
def is_outscript_p2sh(outscript):
    """ Does the raw outscript look like a P2SH? """
    return (
        len(outscript) == 23 and
        outscript[0] == OP_HASH160 and
        outscript[1] == 0x14 and
        outscript[-1] == OP_EQUAL )

@_suppress_script_errors
def is_outscript_timelock(outscript):
    """ Does the raw outscript look like a time-locked script? """
    parts = list(iter_script_parts(outscript))
    return (
        parts[1] == OP_CHECKLOCKTIMEVERIFY and \
        parts[2] == OP_DROP and \
        isinstance(parts[0], bytes) and len(parts[0]) <= 4
    )

@_suppress_script_errors
def is_outscript_multisig(outscript):
    """ Does the raw outscript look like a P2MULTISIG? """
    return outscript[-1] == OP_CHECKMULTISIG

@_suppress_script_errors
def is_outscript_hash_preimage(outscript):
    """ Does the raw outscript look like a HASH_PREIMAGE? """
    hash_function, hashes = parse_hash_preimage(outscript)
    return hash_function is not None

def parse_hash_preimage(outscript):
    """
    Deconstruct a hash-preimage script.
    :return: a 2-tuple of ( hash_function, hashes ), or (None, [])
    """
    hash_function = None
    hashes = []
    parts = list(iter_script_parts(outscript))
    n = len(parts)
    ok = True
    if n > 0 and n % 3 == 0:
        for i, part in enumerate(parts):
            if not ok:
                break
            m = i % 3
            # HASH OP
            if m == 0:
                if is_hash_op(part):
                    h = to_hash_function(part)
                    if hash_function is None:
                        hash_function = h
                    elif hash_function != h:
                        raise InvalidScriptError('Unsupported hash-preimage: heterogeneous hash ops')
                else:
                    ok = False
            # HASH VALUE
            elif m == 1:
                if isinstance(part, bytes):
                    hashes.append(part)
                else:
                    ok = False
            # COMPARISON OP
            elif m == 2:
                # last comparison is done using OP_EQUAL, the rest using OP_EQUALVERIFY
                expected_op = OP_EQUAL if i == n - 1 else OP_EQUALVERIFY
                if part != expected_op:
                    ok = False
    if not ok:
        return None, []
    return hash_function, hashes

@_suppress_script_errors
def is_outscript_if(outscript):
    """ Does the raw outscript look like a IF/ELSE script? """
    if_idx, else_idx, endif_idx = parse_if_else(outscript, at_beginning = True)
    return (
        if_idx is not None
        and endif_idx is not None
        # check that the entire script is if/else/endif:
        and if_idx == 0  # OP_IF is the first OP
        and endif_idx == len(outscript) - 1  # OP_ENDIF is the last OP
    )
    
def parse_if_else(outscript, at_beginning = False):
    """
    Locate the outermost OP_IF / OP_ELSE / OP_ENDIF, and return their locations.
    :return:
        a 3-tuple of ( if_idx, else_idx, endif_idx ).
        possibly all Nones, if script does not contain an if/else/endif structure.
    :raise: InvalidScriptError on invalid if/else/endif structure
    """
    depth = -1
    if_idx = None
    else_idx = None
    endif_idx = None
    for op, _, op_idx in iter_script_raw(outscript):

        # IF
        if op == OP_IF:
            depth += 1
            if depth == 0:
                if_idx = op_idx
        # ELSE
        elif op == OP_ELSE:
            if depth == 0:
                if else_idx is not None:
                    # multiple ELSEs
                    raise InvalidScriptError('Unsupported if/else/endif: multiple OP_ELSEs are not supported')
                else_idx = op_idx
            elif depth < 0:
                raise InvalidScriptError('Invalid if/else/endif: OP_ELSE outside OP_IF/OP_ENDIF block')
        # ENDIF
        elif op == OP_ENDIF:
            if depth == 0:
                endif_idx = op_idx
            elif depth < 0:
                raise InvalidScriptError('Unbalanced if/else/endif: OP_ENDIF with no OP_IF')
            depth -= 1

        if endif_idx is not None:
            break  # found
        
        if at_beginning and depth < 0:
            break  # did not find at the beginning
        
    if depth >= 0:
        raise InvalidScriptError('Unbalanced if/else/endif: OP_IF with no OP_ENDIF')
    assert (if_idx is None) == (endif_idx is None), (outscript, if_idx, else_idx, endif_idx)
    return if_idx, else_idx, endif_idx
    

@_suppress_script_errors
def is_outscript_provably_unspendable(outscript):
    """ Is this raw outscript provably-unspendable? """
    return outscript[0] == OP_RETURN

def get_hash160_from_outscript_p2pkh(outscript):
    """ Extract the hash160 data from a P2PKH raw outscript. """
    hash160 = next(itertools.islice(iter_script_parts(outscript), 2, None))
    if not isinstance(hash160, bytes):
        return None
    return hash160

def get_pubkey_from_outscript_p2pk(outscript):
    """ Extract the pubkey data from a P2PK raw outscript. """
    pk = next(iter_script_parts(outscript))
    if not isinstance(pk, bytes):
        return None
    try:
        _get_pubkey_format(pk)
    except ValueError:
        return None
    return pk

def get_hash160_from_outscript_p2pk(outscript):
    """ Extract pubkey's hash160 from a P2PK raw outscript. """
    pub = get_pubkey_from_outscript_p2pk(outscript)
    if pub is None:
        return None
    return pubkey_to_hash160(pub)

def get_hash160_from_outscript_p2sh(outscript):
    """ Extract the hash160 data from a P2SH raw outscript. """
    hash160 = next(itertools.islice(iter_script_parts(outscript), 1, None))
    if not isinstance(hash160, bytes):
        return None
    return hash160

def get_script_hash160_for_p2sh(outscript, check_size = True):
    """
    Calculate the script-hash to be included in a P2SH-script paying to this redeem script.
    :param check_size: make sure we're not trying to use a redeem script which is more than
        520 bytes (which will make the tx unspendable)
    """
    if check_size and len(outscript) > MAX_P2SH_REDEEM_SCRIPT_SIZE:
        raise InvalidScriptError('P2SH redeem script must be at most %s bytes' % MAX_P2SH_REDEEM_SCRIPT_SIZE)
    return HASH160(outscript)

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
    elif is_outscript_timelock(outscript):
        return ScriptType.TIMELOCK
    elif is_outscript_multisig(outscript):
        return ScriptType.P2MULTISIG
    elif is_outscript_hash_preimage(outscript):
        return ScriptType.HASH_PREIMAGE
    elif is_outscript_if(outscript):
        return ScriptType.IF
    else:
        return ScriptType.OTHER

def _get_pubkey_format(pubkey):
    if len(pubkey) == 65 and pubkey[0] == 0x04:
        return 'bin'
    elif len(pubkey) == 33 and pubkey[0] in [0x02, 0x03]:
        return 'bin_compressed'
    else:
        raise ValueError('Unknown pubkey format: %r' % pubkey)

def iter_script_parts(x):
    """
    Parse the raw script and iterate over the logical parts of, i.e. the OPs and
    the data. The elements are either operator (of type CScriptOp), or data (of type
    bytes).
    
    > list(iter_script_parts(get_sample('P2PKH')[0]))
    [OP_DUP,
     OP_HASH160,
     b'\xc0k\xa0\x8fm\x85\xee\x0cJ&\xd8\xfeUK\x87\x9c\xd9\xd11\x9b',
     OP_EQUALVERIFY,
     OP_CHECKSIG]

    """
    x = getattr(x, 'raw', x)
    x = _CScript(x)
    return iter(x)

def iter_script_raw(x):
    """
    A low-level parsing function, for iterating over the raw parts of the script.
    Each element is a 3-tuple containing: ( opcode, data, sop_idx ).
    For more details, see bitcoin.core.script.CScript.raw_iter().
    
    > list(iter_script_raw(get_sample('P2PKH')[0]))
    [(118, None, 0),
     (169, None, 1),
     (20, b'\xc0k\xa0\x8fm\x85\xee\x0cJ&\xd8\xfeUK\x87\x9c\xd9\xd11\x9b', 2),
     (136, None, 23),
     (172, None, 24)]

    """
    x = getattr(x, 'raw', x)
    return _CScript(x).raw_iter()

################################################################################
