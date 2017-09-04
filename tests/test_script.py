"""
Unit-testing the script types.
"""

import unittest
import datetime

from bitcoinscript.script import (
    outscript_from_raw, inscript_from_raw, ScriptType, OutScript, Address, Signature,
    OutScriptTimeLock, OutScriptHashPreImage, InScriptHashPreImage, )
from bitcoinscript.samples import get_sample, SCRIPT_SAMPLES, P2SH_SCRIPT_SAMPLES, ADDRESS_SAMPLES
from bitcoinscript.opcode import OP_RETURN, HASH_FUNCTIONS


################################################################################

class ScriptTest(unittest.TestCase):

    ################################################################################
    # Common tests and methods

    def _get_sample(self, script_type, SAMPLES = SCRIPT_SAMPLES, test_script_type = None):
        if test_script_type is None:
            test_script_type = script_type
        x = SAMPLES[script_type]
        script_type = to_script_type(script_type)
        test_script_type = ScriptType[test_script_type]
        outscript_raw = bytes.fromhex(x['outscript'])
        outscript = outscript_from_raw(outscript_raw)
        if x['inscript'] is not None:
            inscript_raw = bytes.fromhex(x['inscript'])
            inscript = inscript_from_raw(inscript_raw, outscript)
        else:
            inscript = inscript_raw = None
        
        self._test_basics(outscript, inscript, outscript_raw, inscript_raw, test_script_type)
        
        return outscript, inscript

    def _test_basics(self, outscript, inscript, outscript_raw, inscript_raw, script_type):
        script_type = to_script_type(script_type)
        self.assertEqual(outscript.raw, outscript_raw)
        self.assertEqual(outscript.type, script_type)
        if inscript is not None:
            self.assertEqual(inscript.raw, inscript_raw)
            self.assertEqual(inscript.type, script_type)


    ################################################################################
    # Tests for simple script types

    def test_p2pk(self, *args):
        outscript, inscript = self._get_sample('P2PK') if not args else args
        self.assertTrue(isinstance(outscript.get_address(), Address))
        self.assertEqual(outscript.get_address().str[0], '1')
        self.assertTrue(outscript.pubkey)
        self.assertTrue(isinstance(inscript.signature, Signature))
        # reconstruct:
        self.assertEqual(outscript.from_pubkey(outscript.pubkey), outscript)
        self.assertEqual(inscript.from_signature(inscript.signature), inscript)
    
    def test_p2pkh(self, *args):
        outscript, inscript = self._get_sample('P2PKH') if not args else args
        self.assertTrue(isinstance(outscript.get_address(), Address))
        self.assertEqual(outscript.get_address().str[0], '1')
        self.assertTrue(isinstance(outscript.pubkey_hash, bytes))
        self.assertTrue(outscript.pubkey_hash)
        self.assertTrue(inscript.pubkey)
        self.assertTrue(inscript.signature)
        self.assertTrue(isinstance(inscript.signature, Signature))
        # reconstruct:
        self.assertEqual(outscript.from_pubkey_hash(outscript.pubkey_hash), outscript)
        self.assertEqual(inscript.from_pubkey_and_signature(inscript.pubkey, inscript.signature), inscript)

    def test_p2multisig(self, *args):
        outscript, inscript = self._get_sample('P2MULTISIG') if not args else args
        m = outscript.num_required
        n = outscript.num_total
        self.assertLessEqual(m, n)
        self.assertLessEqual(0, m)
        self.assertLessEqual(1, n)
        self.assertEqual(len(outscript.pubkeys), n)
        self.assertEqual(len(outscript.get_addresses()), n)
        self.assertEqual(len(inscript.signatures), m)
        # reconstruct:
        self.assertEqual(outscript.from_pubkeys(outscript.pubkeys, outscript.num_required), outscript)
        self.assertEqual(inscript.from_signatures(inscript.signatures), inscript)

    def test_hash_preimage(self, *args):
        # test sample:
        outscript, inscript = self._get_sample('HASH_PREIMAGE') if not args else args
        self._test_hash_preimage(outscript, inscript)
        # test various hash functions:
        preimages = [ b'foo', b'bar' ]
        for hash_func in HASH_FUNCTIONS.values():
            for preimages in ( [b'zzz'], [b'foo', b'bar'] ):
                hashes = [ hash_func(pi) for pi in preimages ]
                outscript = OutScriptHashPreImage.from_hashes(hash_func, hashes)
                inscript = InScriptHashPreImage.from_preimages(preimages)
                self._test_hash_preimage(outscript, inscript)
        # reconstruct:
        self.assertEqual(outscript.from_hashes(outscript.hash_function, outscript.hashes), outscript)
        self.assertEqual(outscript.from_preimages(outscript.hash_function, inscript.preimages), outscript)
        self.assertEqual(inscript.from_preimages(inscript.preimages), inscript)
        
    def _test_hash_preimage(self, outscript, inscript):
        n = len(outscript.hashes)
        self.assertEqual(n, len(inscript.preimages))
        self.assertEqual(outscript.hash_opcode, outscript.hash_function.OP)
        self.assertEqual(outscript.hash_type, outscript.hash_function.__name__)
        for hash, preimage in zip(outscript.hashes, inscript.preimages):
            self.assertTrue(isinstance(hash, bytes))
            self.assertTrue(isinstance(preimage, bytes))
            self.assertEqual(outscript.hash_function(preimage), hash)

    def test_if(self, *args):
        outscript, inscript = self._get_sample('IF') if not args else args
        # test outscript
        self.assertTrue(isinstance(outscript.if_true_script, OutScript))
        self.assertTrue(isinstance(outscript.if_false_script, OutScript))
        self.assertSetEqual(set(outscript.inner_scripts.keys()), { True, False })
        self.assertEqual(outscript.inner_scripts[True], outscript.if_true_script)
        self.assertEqual(outscript.inner_scripts[False], outscript.if_false_script)
        # test inscript
        self.assertTrue(isinstance(inscript.condition_value, bool))
        self.assertTrue(isinstance(inscript.inner_inscript_raw, bytes))
        # reconstruct:
        outscript2 = outscript.from_scripts(outscript.if_true_script, outscript.if_false_script)
        self.assertEqual(outscript2, outscript)
        inscript2 = inscript.from_condition_value(inscript.condition_value, inscript.inner_inscript_raw)
        self.assertEqual(inscript2, inscript)

    def test_timelock(self):
        script_type = 'TIMELOCK'
        script_subtype = 'P2PK'  # gen_samples will only include timelocked P2PK scripts
        # extract timelock scripts to be tested, from p2sh scripts
        p2sh_outscript, p2sh_inscript = self._get_sample(script_type, P2SH_SCRIPT_SAMPLES, test_script_type = 'P2SH')
        outscript = p2sh_inscript.redeem_script
        inscript = p2sh_inscript.redeem_inscript
        # OutScriptTimeLock tests:
        self.assertTrue(isinstance(outscript.locktime, int))
        inner_outscript = outscript.inner_script
        self.assertTrue(isinstance(inner_outscript, OutScript))
        # test 2 types of locktime value
        inner_o, _ = self._get_sample('P2PK')
        block_height = 200000
        o = OutScriptTimeLock.from_script(inner_o, block_height)
        self.assertEqual(o.locktime, block_height)
        self.assertEqual(o.locktime_block_height, block_height)
        self.assertEqual(o.locktime_datetime, None)
        time = datetime.datetime.now().replace(microsecond = 0)
        o = OutScriptTimeLock.from_script(inner_o, time)
        self.assertEqual(o.locktime, time.timestamp())
        self.assertEqual(o.locktime_block_height, None)
        self.assertEqual(o.locktime_datetime, time)
        # inner-script tests:
        self._test_basics(inner_outscript, inscript, inner_outscript.raw, inscript.raw, script_subtype)
        # run "standard" tests on inner script, according to the type:
        underlying_test_func = getattr(self, 'test_' + script_subtype.lower())
        underlying_test_func(inner_outscript, inscript)
        
        # reconstruct:
        self.assertEqual(outscript.from_script(outscript.inner_script, outscript.locktime), outscript)

    def test_provably_unspendable(self, *args):
        outscript, inscript = self._get_sample('PROVABLY_UNSPENDABLE') if not args else args
        self.assertEqual(inscript, None)
        self.assertEqual(list(outscript)[0], OP_RETURN)
        # reconstruct:
        self.assertEqual(outscript.from_unused_data(outscript.unused_data), outscript)

    def test_other(self, *args):
        outscript, inscript = self._get_sample('OTHER') if not args else args
        # _get_sample() does basic checks. no other checks to run.

    
    ################################################################################
    # Tests for P2SH
    
    def _test_p2sh(self, script_type):
        outscript, inscript = self._get_sample(script_type, P2SH_SCRIPT_SAMPLES, test_script_type = 'P2SH')

        # OutScriptP2SH tests:
        self.assertTrue(isinstance(outscript.script_hash, bytes))
        self.assertTrue(outscript.script_hash)
        self.assertTrue(isinstance(outscript.get_address(), Address))
        self.assertEqual(outscript.get_address().str[0], '3')

        # InScriptP2SH tests:
        script_type = ScriptType[script_type]
        outscript2 = inscript.redeem_script
        inscript2 = inscript.redeem_inscript
        outscript2_raw = inscript.redeem_script_raw
        inscript2_raw = inscript.redeem_inscript_raw
        self._test_basics(outscript2, inscript2, outscript2_raw, inscript2_raw, script_type)

        # run "standard" tests on the underlying redeem scripts, according to the type:
        underlying_test_func = getattr(self, 'test_' + script_type.name.lower())
        underlying_test_func(outscript2, inscript2)
        
        # reconstruct:
        self.assertEqual(outscript.from_script_hash(outscript.script_hash), outscript)
        self.assertEqual(inscript.from_redeem_scripts(outscript2, inscript2), inscript)

    def test_p2sh_p2pk(self):
        self._test_p2sh('P2PK')

    def test_p2sh_p2pkh(self):
        self._test_p2sh('P2PKH')

    def test_p2sh_p2multisig(self):
        self._test_p2sh('P2MULTISIG')

    def test_p2sh_hash_preimage(self):
        self._test_p2sh('HASH_PREIMAGE')

    def test_p2sh_if(self):
        self._test_p2sh('IF')

    def test_p2sh_other(self):
        self._test_p2sh('OTHER')

    ################################################################################
    # Tests for get_address()

    def test_get_address(self):
        for addr_sample in ADDRESS_SAMPLES:
            outscript, _= get_sample(*(addr_sample['origin'].split('/')))
            addr = outscript.get_address()
            self.assertEqual(addr.str, addr_sample['address'])
            self.assertEqual(addr.hash160_hex, addr_sample['hash160'])
            self.assertEqual(addr.is_p2sh, addr_sample['is_p2sh'])
            if addr.pubkey is not None:
                self.assertEqual(addr.pubkey.hex(), addr_sample['pubkey'])
            else:
                self.assertEqual(None, addr_sample['pubkey'])

def to_script_type(x):
    if isinstance(x, ScriptType):
        return x
    return ScriptType[x]

################################################################################

if __name__ == '__main__':
    unittest.main()
