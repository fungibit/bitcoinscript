==============
Code Examples
==============

This section includes various examples of using the bitcoinscript library, and
demonstrates some of the main features.

Bitcoinscript conveniently **includes sample bitcoin scripts**.  These are real-world
scripts extracted from the real blockchain.  The samples are useful for
playing around and trying it out.  Some of the examples here use the sample scripts.


Dissecting a P2PKH Script 
------------------------------

This example shows how to access the parts P2PKH scripts (outscript and inscript)
are made of.  We use the P2PKH scripts included in the samples.

::

    from bitcoinscript import Address
    from bitcoinscript.samples import get_sample
    outscript, inscript = get_sample('P2PKH')
    
    # Various ways to view a script:
    outscript
    => <OutScriptP2PKH paying to 1JYRfuBFd5p6efVV5U5HdZJwSDaAtnVwvG>
    outscript.type
    => <ScriptType.P2PKH: 2>
    outscript.hex
    => '76a914c06ba08f6d85ee0c4a26d8fe554b879cd9d1319b88ac'
    print(outscript)
    => OP_DUP OP_HASH160 c06ba08f6d85ee0c4a26d8fe554b879cd9d1319b OP_EQUALVERIFY OP_CHECKSIG
    inscript
    => <InScriptP2PKH 47304402202705767c9be071b580f8286a058410808cdd9662a359b463f7c1dd42f7c60c2d02202f08d8f6c0d4dd9080d2b6ed4dc2098087e737ec6061b01e733eb85e27bbef50012102f3348097a2d088c43727f554bad3e4135f86c60a6b2b74b13aef87f4af215946>
    inscript.type
    => <ScriptType.P2PKH: 2>
    print(inscript)
    => 304402202705767c9be071b580f8286a058410808cdd9662a359b463f7c1dd42f7c60c2d02202f08d8f6c0d4dd9080d2b6ed4dc2098087e737ec6061b01e733eb85e27bbef5001 02f3348097a2d088c43727f554bad3e4135f86c60a6b2b74b13aef87f4af215946
    
    # P2PKH ouscripts consist of a pubkey-hash, which can also be accessed as an Address object:
    outscript.pubkey_hash.hex()
    => 'c06ba08f6d85ee0c4a26d8fe554b879cd9d1319b'
    outscript.get_address()
    => Address('1JYRfuBFd5p6efVV5U5HdZJwSDaAtnVwvG')
    outscript.get_address().hash160_hex
    => 'c06ba08f6d85ee0c4a26d8fe554b879cd9d1319b'
    
    # P2PKH inscripts consist of a pubkey and a signature. SigHash is part of the signature:
    inscript.pubkey.hex()
    => '02f3348097a2d088c43727f554bad3e4135f86c60a6b2b74b13aef87f4af215946'
    inscript.signature
    => <Signature 304402202705767c9be071b580f8286a058410808cdd9662a359b463f7c1dd42f7c60c2d02202f08d8f6c0d4dd9080d2b6ed4dc2098087e737ec6061b01e733eb85e27bbef5001>
    inscript.signature.sighash
    => <SigHash ALL>
    
    # Some sanity tests:
    assert Address.from_pubkey(inscript.pubkey) == outscript.get_address()
    assert Address.from_pubkey(inscript.pubkey).hash160 == outscript.pubkey_hash


Reconstructing a P2PK Script
------------------------------

This simple example demonstrates how to create a P2PK outscript/inscript pair.
Script data (pubkey and signature) are extracted from a sample script.

::

    from bitcoinscript.script import OutScriptP2PK, InScriptP2PK
    from bitcoinscript.samples import get_sample
    outscript1, inscript1 = get_sample('P2PK')
    # extract the required pubkey (from outscript) and signature (from inscript):
    pubkey = outscript1.pubkey
    signature = inscript1.signature
    # create an outscript from pubkey, and an inscript from the signature:
    outscript2 = OutScriptP2PK.from_pubkey(pubkey)
    inscript2 = InScriptP2PK.from_signature(signature)
    # sanity testing:
    assert outscript1 == outscript2 and inscript1 == inscript2


Reconstructing a P2SH Script
------------------------------

This example is similar to the previous one, but performs a "deep" reconstruction of a
P2SH, including reconstructing the P2MULTISIG redeem scripts embedded in the P2SH inscript.

Again, we start with a sample script.

::

    from bitcoinscript.script import OutScriptP2SH, InScriptP2SH, OutScriptP2Multisig, InScriptP2Multisig
    from bitcoinscript.samples import get_sample
    outscript1, inscript1 = get_sample('P2SH', 'P2MULTISIG')
    outscript1
    => <OutScriptP2SH paying to 3D1uMVMRYsHCQo8RR42RK3s68z9xgc7a4K>
    inscript1
    => <InScriptP2SH containing <OutScriptP2Multisig 2-of-2 paying to 13NcGGDPVym1XUhDdVGAMkuCrLy5AZNYSP,17QTqiik6GqxfdFghefypkosQH7FpHV7xX> >
    
    # extract P2MULTISIG redeem scripts from inscript:
    redeem_script1 = inscript1.redeem_script
    redeem_inscript1 = inscript1.redeem_inscript
    redeem_script1
    => <OutScriptP2Multisig 2-of-2 paying to 13NcGGDPVym1XUhDdVGAMkuCrLy5AZNYSP,17QTqiik6GqxfdFghefypkosQH7FpHV7xX>
    
    # reconstruct redeem script ("num_required" is the "M" from "M-of-N"):
    redeem_script2 = OutScriptP2Multisig.from_pubkeys(redeem_script1.pubkeys, redeem_script1.num_required)
    assert redeem_script1 == redeem_script2
    
    # reconstruct redeem inscript:
    redeem_inscript2 = InScriptP2Multisig.from_signatures(redeem_inscript1.signatures)
    assert redeem_inscript1 == redeem_inscript2
    
    # reconstruct P2SH scripts from redeem scripts:
    outscript2 = OutScriptP2SH.from_script(redeem_script2)
    inscript2 = InScriptP2SH.from_redeem_scripts(redeem_script2, redeem_inscript2)
    assert outscript1 == outscript2 and inscript1 == inscript2


Counting Script Types
-------------------------

We loop over the blockchain using `chainscan <https://chainscan.readthedocs.io/en/latest/index.html>`_,
counting outscripts' script-type.

::

    from collections import Counter
    from chainscan import iter_txs
    from bitcoinscript import outscript_from_raw
    Counter(outscript_from_raw(txo.script).type
            for tx in iter_txs()
            for txo in tx.outputs )

Output::

    Counter({<ScriptType.HASH_PREIMAGE: 7>: 52,
             <ScriptType.PROVABLY_UNSPENDABLE: 0>: 3087707,
             <ScriptType.IF: 6>: 5,
             <ScriptType.P2PKH: 2>: 602810633,
             <ScriptType.P2PK: 1>: 1315266,
             <ScriptType.P2SH: 3>: 76651788,
             <ScriptType.P2MULTISIG: 4>: 574887,
             <ScriptType.OTHER: -1>: 221676})


Counting P2SH "Script Subtypes"
----------------------------------------

In this example we count P2SH redeem-script types.

Naturally, this only includes *spent* P2SH scripts, because redeem scripts are only
revealed upon spending.

Again, we're using `chainscan <https://chainscan.readthedocs.io/en/latest/index.html>`_ for looping over the blockchain.

:note: Running this example consumes at least 7GB of memory (due to `track_scripts` mode).

::

    from chainscan import iter_txs
    from bitcoinscript import outscript_from_raw, inscript_from_raw
    from collections import Counter
    counter = Counter()
    for tx in iter_txs(track_scripts = True):
        if tx.is_coinbase:
            continue
        for txi in tx.inputs:
            outscript = outscript_from_raw(txi.output_script)
            if outscript.type == ScriptType.P2SH:
                rscript = inscript_from_raw(txi.script, ScriptType.P2SH).redeem_script
                if rscript is not None:
                    counter[rscript.type] += 1

Output::

    Counter({<ScriptType.TIMELOCK: 5>: 430,
             <ScriptType.IF: 6>: 2052,
             <ScriptType.P2MULTISIG: 4>: 67757802,
             <ScriptType.OTHER: -1>: 108141,
             <ScriptType.P2PKH: 2>: 447,
             <ScriptType.P2PK: 1>: 6903,
             <ScriptType.HASH_PREIMAGE: 7>: 136})


Verifying All scripts
------------------------------

Bitcoinscript includes the `verify_script` function, which executes scripts.

In this example, we verify all scripts from the blockchain.

:note: This example verifies **everything**.  It takes a few days to complete, and consumes at least
    7GB of memory (due to `track_scripts` mode).

::

    from chainscan import iter_txs
    from bitcoinscript import inscript_from_raw, outscript_from_raw
    from bitcoinscript.verify import verify_script, VerifyScriptError
    for tx in iter_txs(track_scripts = True, include_tx_blob = True):
        if tx.is_coinbase:
            continue
        for input_idx, txinput in enumerate(tx.inputs):
            outscript = outscript_from_raw(txinput.output_script)
            inscript = inscript_from_raw(txinput.script, outscript)
            try:
                verify_script(inscript, outscript, tx.blob, input_idx)
            except VerifyScriptError as e:
                print('Script verification failed for tx %s, input #%s' % (tx.txid_hex, input_idx))
                print('    ERROR: %s' % ( e, ))

