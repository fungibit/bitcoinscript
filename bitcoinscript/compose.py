"""
Tools for serializing script's parts into a serialized script.
"""

from .opcode import is_opcode, get_opcode_const, encode_op_pushdata


################################################################################

def compose_from_template(template, **kw):
    return b''.join([ _sub(t, **kw) for t in template ])

def _sub(x, force_pushdata = None, **kw):
    if is_opcode(x):
        # OP_xxx
        return to_byte(x)
    elif type(x) == str:
        # a variable name, possibly with a modifier-prefix
        push_prefix = 'PUSH:'
        const_prefix = 'CONST:'
        if x.startswith(push_prefix):
            varname = x[len(push_prefix):]
            varval = kw[varname]
            if isinstance(varval, int):
                return _sub(get_opcode_const(varval))
            else:
                return encode_op_pushdata(varval, force_pushdata = force_pushdata)
        elif x.startswith(const_prefix):
            varname = x[len(const_prefix):]
            varval = kw[varname]
            return _sub(get_opcode_const(varval))
        else:
            varname = x
            return to_bytes(kw[varname])
    else:
        assert 0, type(x)

def to_byte(x):
    return bytes([x])

def to_bytes(x):
    if isinstance(x, int):
        return to_byte(x)
    elif isinstance(x, bytes):
        return x
    else:
        assert 0, type(x)
    
################################################################################
