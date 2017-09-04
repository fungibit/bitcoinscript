"""
Tools for formatting scripts as human-readable strings.
"""

from .opcode import get_opcode_by_name, encode_op_pushdata
from .basic import iter_script_parts

################################################################################
# formatting: raw -> formatted string

def format_script(x, delim = ' ', **kwargs):
    """
    Format a script as a human-readable string.

    >>> format_script(bytes.fromhex('76a91492b8c3a56fac121ddcdffbc85b02fb9ef681038a88ac'), max_value_len=100)
    'OP_DUP OP_HASH160 92b8c3a56fac121ddcdffbc85b02fb9ef681038a OP_EQUALVERIFY OP_CHECKSIG'
    """
    return delim.join(iter_script_parts_as_strings(x, **kwargs))

def iter_script_parts_as_strings(x, **kwargs):
    return (
        format_data_token(token, **kwargs)
        for token in iter_script_parts(x)
    )

def format_data_token(token, max_value_len = 19, empty_value_string = '<<empty>>'):
    try:
        token_str = token.hex()
    except AttributeError:
        token_str = str(token)
    if len(token_str) > max_value_len and not token_str.startswith('OP_'):
        part_len = (max_value_len - 3) // 2
        assert part_len > 0, part_len
        token_str = '%s...%s' % (token_str[:part_len], token_str[-part_len:])
    if len(token_str) == 0:
        token_str = empty_value_string
    return token_str

################################################################################
# parsing: formatted string -> raw
    
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
        b += _parse_token(token)
    return b

def _parse_token(token):
    
    if token.endswith('[]'):
        token = token[:-len('[]')]
        
    #### NON_OP:
    if token.startswith('NON_OP('):
        assert token[-1] == ')', token
        return int(token[len('NON_OP(') : -1]).to_bytes(1, byteorder = 'little')
    
    #### OP_xxx:
    if token.startswith('OP_'):
        return get_opcode_by_name(token).to_bytes(1, byteorder = 'big')
    # try a "OP_"-less OP:
    try:
        return _parse_token('OP_' + token)
    except KeyError:
        pass
    
    #### PUSHDATA:
    if token.startswith('PUSHDATA'):
        # explicit pushdata
        assert token[-1] == ']', token
        i = token.find('[')
        hexblob = token[i+1 : -1]
        return encode_op_pushdata(bytes.fromhex(hexblob))
    else:
        # implicit pushdata
        return encode_op_pushdata(bytes.fromhex(token))
    
################################################################################
