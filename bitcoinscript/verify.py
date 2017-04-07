"""
Tools for verifying scripts.

:note: This is just a simple wrapper around definitions from python-bitcoinlib's `bitcoin.core.script`.
"""

from bitcoin.core import CTransaction
from bitcoin.core.scripteval import VerifyScript, CScript, SCRIPT_VERIFY_FLAGS_BY_NAME

from bitcoin.core.scripteval import VerifyScriptError, EvalScriptError  # make these importable from here
VerifyScriptError, EvalScriptError  # suppress pyflakes warnings

from .basic import ScriptType


################################################################################

def verify_script(inscript, outscript, rawtx = None, input_idx = None, flags = ()):
    """
    Run the bitcoin-script 
    :param inscript: an InScript object (or its raw representation)
    :param outscript: an OutScript object (or its raw representation)
    :param rawtx: the raw/serialized tx, which contains the inscript.
    :param input_idx: the index of the inscript inside the tx.
    :return: None
    :raises: VerifyScriptError if script does not verify
    """
    
    p2sh_flag = SCRIPT_VERIFY_FLAGS_BY_NAME['P2SH']
    if getattr(outscript, 'type', None) == ScriptType.P2SH and p2sh_flag not in flags:
        flags += (p2sh_flag,)

    inscript = getattr(inscript, 'raw', inscript)
    outscript = getattr(outscript, 'raw', outscript)
    iscript = CScript(inscript)
    oscript = CScript(outscript)
    if rawtx is not None:
        tx = CTransaction.deserialize(rawtx)
    else:
        tx = None
    VerifyScript(iscript, oscript, tx, input_idx, flags = flags)  # raises VerifyScriptError

################################################################################

