"""
BitcoinScript
==============

*Friendly interface for bitcoin scripts.*
"""

from .address import Address, to_address
from .signature import Signature, SigHash
from .script import ScriptType, Script, OutScript, InScript, outscript_from_raw, inscript_from_raw
from .samples import get_sample

# suppress pyflakes "imported but unused" warnings:
Address, to_address
Signature, SigHash
ScriptType, Script, OutScript, InScript, outscript_from_raw, inscript_from_raw
get_sample
