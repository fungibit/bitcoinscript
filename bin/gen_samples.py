#! /usr/bin/env python3
"""
Find scripts in the blockchain, and generate code sample to include in samples.py.
"""

from pprint import pprint
from argparse import ArgumentParser

from chainscan import iter_txs, BlockFilter
from bitcoinscript import outscript_from_raw, inscript_from_raw, ScriptType

###############################################################################

def main():
    
    options = getopt()
    
    scripts = {}
    p2sh_scripts = {}
    for tx in iter_txs(track_scripts = True, include_tx_blob = True,
                       block_filter = BlockFilter(stop_block_height = options.stop_block_height)):

        # OUTPUTS -- for provably-unspendable only
        for oidx, txoutput in enumerate(tx.outputs):
            outscript = outscript_from_raw(txoutput.script)
            if outscript.type == ScriptType.PROVABLY_UNSPENDABLE:
                scripts[outscript.type.name] = dict(
                    outscript = outscript.hex,
                    inscript = None,
                    iidx = None,
                    txid = tx.txid_hex,
                    txblob = bytes(tx.blob).hex(),
                    oidx = oidx,
                )

        if tx.is_coinbase:
            continue

        # INPUTS
        for iidx, txinput in enumerate(tx.inputs):
            outscript = outscript_from_raw(txinput.output_script)
            script_type = outscript.type
            inscript = inscript_from_raw(txinput.script, outscript)
            d = dict(
                outscript = outscript.hex,
                inscript = inscript.hex,
                iidx = iidx,
                txid = tx.txid_hex,
                txblob = bytes(tx.blob).hex(),
                oidx = txinput.spent_output_idx,
            )
            if script_type == ScriptType.P2SH:
                redeem_script = inscript.redeem_script
                if redeem_script is not None:
                    p2sh_scripts[redeem_script.type.name] = dict(d, rscript = redeem_script.hex)
            else:
                scripts[script_type.name] = d

    print('SCRIPT_SAMPLES = \\')
    pprint(scripts)
    print()
    print('P2SH_SCRIPT_SAMPLES = \\')
    pprint(p2sh_scripts)


    ###############################################################################
    # Generate address samples from scripts

    # address from P2PK (includes the pubkey):
    s1 = outscript_from_raw(bytes.fromhex(scripts['P2PK']['outscript']))
    addr1 = {
        'address': s1.get_address().str,
        'hash160': s1.get_address().hash160_hex,
        'pubkey': s1.pubkey.hex(),
        'is_p2sh': False,
        'origin': 'P2PK',
    }
    # address from P2PKH (doesn't include the pubkey):
    s2 = outscript_from_raw(bytes.fromhex(scripts['P2PKH']['outscript']))
    addr2 = {
        'address': s2.get_address().str,
        'hash160': s2.get_address().hash160_hex,
        'pubkey': None,
        'is_p2sh': False,
        'origin': 'P2PKH',
    }
    # address from P2SH:
    s3 = outscript_from_raw(bytes.fromhex(p2sh_scripts['P2MULTISIG']['outscript']))
    addr3 = {
        'address': s3.get_address().str,
        'hash160': s3.get_address().hash160_hex,
        'pubkey': None,
        'is_p2sh': True,
        'origin': 'P2SH/P2MULTISIG',
    }
    addrs = [ addr1, addr2, addr3 ]

    print()
    print('ADDRESS_SAMPLES = \\')
    pprint(addrs)
        

###############################################################################

def getopt():
    parser = ArgumentParser()
    parser.add_argument('-b', '--stop_block_height', type = int, default = 350000)
    return parser.parse_args()

###############################################################################

if __name__ == '__main__':
    main()
