"""
Tools for formatting scripts as human-readable strings.
"""

from bitcoin.core.script import CScript as _CScript
from .opcode import get_opcode_by_name, encode_op_pushdata

################################################################################

def format_script(x, delim = ' '):
    """
    Format a script as a human-readable string.

    >>> format_script(bytes.fromhex('76a91492b8c3a56fac121ddcdffbc85b02fb9ef681038a88ac'))
    'OP_DUP OP_HASH160 92b8c3a56fac121ddcdffbc85b02fb9ef681038a OP_EQUALVERIFY OP_CHECKSIG'
    """
    return delim.join(iter_script_parts_as_strings(x))

def iter_script_parts_as_strings(x):
    for token in iter_script_parts(x):
        try:
            token_str = token.hex()
        except AttributeError:
            token_str = str(token)
        yield token_str
    
def iter_script_parts(x):
    x = getattr(x, 'raw', x)
    x = _CScript(x)
    for token in x:
        yield token

def raw_iter_script(x):
    x = getattr(x, 'raw', x)
    return list(_CScript(x).raw_iter())

def parse_formatted_script(x):
    """
    The opposite of `format_script`.
    :param x: a formatted-script string (e.g. "OP_DUP OP_HASH160 d39...1e OP_EQUALVERIFY OP_CHECKSIG")
    :return: raw script (bytes)
    
    >>> parse_formatted_script('OP_DUP OP_HASH160 92b8c3a56fac121ddcdffbc85b02fb9ef681038a OP_EQUALVERIFY OP_CHECKSIG').hex()
    '76a91492b8c3a56fac121ddcdffbc85b02fb9ef681038a88ac'
    """
    b = b''
    for token in x.split():
        if token.startswith('OP_'):
            # OP_xxx
            b += get_opcode_by_name(token).to_bytes(1, byteorder = 'big')
        else:
            # push data
            b += encode_op_pushdata(bytes.fromhex(token))
    return b
    
################################################################################
