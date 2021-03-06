#! /usr/bin/env python3
"""
Verify all scripts in the blockchain.

This script is useful for testing this package.
"""

# TBD: there is a known error:
# 09Script validation failed for tx 6a26d2ecb67f27d1fa5524763b49029d7106e91e3cc05743073461a719776192, input #0
#    UNEXPECTED ERROR: ArgumentsInvalidError EvalScript: OP_CHECKMULTISIG args invalid: not enough sigs on stack
# To fix, need to avoid using the P2SH-flag in verify_script() for txs from before the time P2SH was activated
# (correct date to use -- to be figured out)


#from argparse import ArgumentParser

from chainscan import iter_txs

from bitcoinscript import inscript_from_raw, outscript_from_raw
from bitcoinscript.verify import verify_script, VerifyScriptError
#from bitcoin.core.scripteval import EvalScriptError


###############################################################################
# MAIN

def main():

    #options = getopt()
    
    for tx in iter_txs(track_scripts = True, include_tx_blob = True, show_progressbar = True):
        if tx.is_coinbase:
            continue
        for input_idx, txinput in enumerate(tx.inputs):
            outscript = outscript_from_raw(txinput.output_script)
            inscript = inscript_from_raw(txinput.script, outscript.type)
            try:
                verify_script(inscript, outscript, tx.blob, input_idx)
            except VerifyScriptError as e:
                print('Script validation failed for tx %s, input #%s' % (tx.txid_hex, input_idx))
                print('    ERROR: %s' % ( e, ))
            except Exception as e:
                print('Script validation failed for tx %s, input #%s' % (tx.txid_hex, input_idx))
                print('    UNEXPECTED ERROR: %s %s' % ( type(e).__name__, e, ))
    
###############################################################################

#def getopt():
#    parser = ArgumentParser()
#    return parser.parse_args()

###############################################################################

if __name__ == '__main__':
    main()
