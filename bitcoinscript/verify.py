"""
Tools for verifying scripts.

:note: This is just a simple wrapper around definitions from python-bitcoinlib's `bitcoin.core.script`.
"""

from bitcoin.core import CTransaction
from bitcoin.core.scripteval import VerifyScript, CScript

from bitcoin.core.scripteval import VerifyScriptError, EvalScriptError  # make these importable from here
VerifyScriptError, EvalScriptError  # suppress pyflakes warnings


################################################################################

def verify_script(inscript, outscript, rawtx, input_idx):
    """
    Run the bitcoin-script 
    :param inscript: an InScript object (or its raw representation)
    :param outscript: an OutScript object (or its raw representation)
    :param rawtx: the raw/serialized tx, which contains the inscript.
    :param input_idx: the index of the inscript inside the tx.
    :return: None
    :raises: VerifyScriptError if script does not verify
    """
    inscript = getattr(inscript, 'raw', inscript)
    outscript = getattr(outscript, 'raw', outscript)
    iscript = CScript(inscript)
    oscript = CScript(outscript)
    tx = CTransaction.deserialize(rawtx)
    VerifyScript(iscript, oscript, tx, input_idx)  # raises VerifyScriptError

################################################################################

