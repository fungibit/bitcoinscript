"""
Definition and basic operations related to script opcodes.

:note: Many of the definitions here are imported from python-bitcoinlib's `bitcoin.core.script`,
    or are simple wrappers around definitions from there.
"""

import struct

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
