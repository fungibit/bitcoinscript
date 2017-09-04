#! /usr/bin/env python3
"""
For each script in the blockchain, deconstruct and reconstruct it.

The reconstructed scripts are compared to the originals, and differences (if any) are
printed.  Ideally, there are no differences at all.

This script is useful for testing this package.

:note: this script takes quite a few hours to run, and uses at least 7GB of RAM (due to chainscan's
    "track_scripts" mode).
"""

from argparse import ArgumentParser
from chainscan import iter_txs

from bitcoinscript import outscript_from_raw, inscript_from_raw, ScriptType
from bitcoinscript.script import OutScript, OutScriptP2PKH, OutScriptP2PK, OutScriptP2SH, OutScriptP2Multisig, OutScriptHashPreImage, OutScriptTimeLock, OutScriptIf, OutScriptProvablyUnspendable
from bitcoinscript.script import InScript, InScriptP2PKH, InScriptP2PK, InScriptP2SH, InScriptP2Multisig, InScriptHashPreImage, InScriptIf


###############################################################################

def reconstruct(script, **kw):
    if script.type == ScriptType.OTHER:
        return script
    
    # OUTPUTS
    if isinstance(script, OutScript):
        if script.type == ScriptType.P2PKH:
            addr = script.get_address()
            if addr is not None:
                return OutScriptP2PKH.from_address(addr, **kw)
        elif script.type == ScriptType.P2PK:
            pk = script.pubkey
            if pk is not None:
                return OutScriptP2PK.from_pubkey(pk, **kw)
        elif script.type == ScriptType.P2SH:
            script_hash = script.script_hash
            if script_hash is not None:
                return OutScriptP2SH.from_script_hash(script_hash, **kw)
        elif script.type == ScriptType.P2MULTISIG:
            pubkeys = script.pubkeys
            num_required = script.num_required
            if pubkeys is not None:
                return OutScriptP2Multisig.from_pubkeys(pubkeys, num_required, **kw)
        elif script.type == ScriptType.HASH_PREIMAGE:
            return OutScriptHashPreImage.from_hashes(script.hash_function, script.hashes, **kw)
        elif script.type == ScriptType.TIMELOCK:
            inner_script2 = reconstruct(script.inner_script, **kw)
            return OutScriptTimeLock.from_script(inner_script2, script.locktime, **kw)
        elif script.type == ScriptType.IF:
            if_true_script2 = reconstruct(script.if_true_script, **kw)
            if script.if_false_script is not None:
                if_false_script2 = reconstruct(script.if_false_script, **kw)
            else:
                if_false_script2 = None
            return OutScriptIf.from_scripts(if_true_script2, if_false_script2, **kw)
        elif script.type == ScriptType.PROVABLY_UNSPENDABLE:
            return OutScriptProvablyUnspendable.from_unused_data(script.unused_data, **kw)
        else:
            assert 0, script.type
    
    # INPUTS
    elif isinstance(script, InScript):
        if script.type == ScriptType.P2PKH:
            signature = script.signature
            pubkey = script.pubkey
            if signature is not None:
                return InScriptP2PKH.from_pubkey_and_signature(pubkey, signature, unused_data = script.unused_data, **kw)
        elif script.type == ScriptType.P2PK:
            signature = script.signature
            if signature is not None:
                return InScriptP2PK.from_signature(signature, **kw)
        elif script.type == ScriptType.P2SH:
            redeem_script = script.redeem_script
            redeem_inscript = script.redeem_inscript
            if redeem_script is not None and redeem_inscript is not None:
                # "deep" reconsruction:
                redeem_script2 = reconstruct(redeem_script, **kw)
                redeem_inscript2 = reconstruct(redeem_inscript, **kw)
                return InScriptP2SH.from_redeem_scripts(redeem_script2, redeem_inscript2, **kw)
        elif script.type == ScriptType.P2MULTISIG:
            signatures = script.signatures
            if signatures is not None:
                return InScriptP2Multisig.from_signatures(signatures, unused_data = script.unused_data, **kw)
        elif script.type == ScriptType.HASH_PREIMAGE:
            return InScriptHashPreImage.from_preimages(script.preimages, **kw)
        elif script.type == ScriptType.IF:
            return InScriptIf.from_condition_value(script.condition_value_raw, script.inner_inscript_raw, **kw)
        else:
            assert 0, script.type
    else:
        assert 0, type(script)
    

def reconstruct_and_test(tx, script, idx, desc):
    if script.type == ScriptType.OTHER:
        return

    raw1 = script.raw
    
    # Note: this attempt to use different pushdata to achieve the original script exactly
    # is still not tight, because the pushdata value is applied "globally" when reconstructing
    # the script (i.e. for all PUSHDATA in the script), while in some cases what we need is
    # different values for different PUSHDATAs.
    for pushdata in [ None, 1, 2, 4 ]:
        try:
            script2 = reconstruct(script, force_pushdata = pushdata)
        except Exception as e:
            print('ERROR: %s %s#%s %s -- %s' % (tx.txid_hex, desc, idx, script.type.name, e))
            return
        if script2 is None:
            return
        raw2 = script2.raw
        if raw1 == raw2:
            #if pushdata is not None:
            #    print('* mismatch reconciled with force_pushdata: %s %s#%s' % (tx.txid_hex, desc, idx))
            return
        if pushdata is None:
            orig_raw2 = raw2

    # mismatch
    print('MISMATCH: %s %s#%s %s' % (tx.txid_hex, desc, idx, script.type.name))
    print('    %s' % (raw1.hex(),))
    print('    %s' % (orig_raw2.hex(),))
    

###############################################################################
# MAIN

def main():
    
    #options = getopt()
    
    for tx in iter_txs(track_scripts = True):
        
        # OUTPUTS
        if True:
            for oidx, txoutput in enumerate(tx.outputs):
                outscript = outscript_from_raw(txoutput.script)
                reconstruct_and_test(tx, outscript, oidx, 'OUT')
        
        # INPUTS
        if not tx.is_coinbase:
            for iidx, txinput in enumerate(tx.inputs):
                outscript = outscript_from_raw(txinput.output_script)
                inscript = inscript_from_raw(txinput.script, outscript)
                reconstruct_and_test(tx, inscript, iidx, 'IN')

###############################################################################

def getopt():
    parser = ArgumentParser()
    return parser.parse_args()

###############################################################################

if __name__ == '__main__':
    main()
