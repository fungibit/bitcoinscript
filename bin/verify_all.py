#! /usr/bin/env python3
"""
Verify all scripts in the blockchain.

This script is useful for testing this package.
"""

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
