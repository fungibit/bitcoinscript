"""
Unit-testing the script types.
"""

import unittest

from bitcoinscript.script import outscript_from_raw, inscript_from_raw, ScriptType, Address, Signature, OP_RETURN
from bitcoinscript.samples import get_sample, SCRIPT_SAMPLES, P2SH_SCRIPT_SAMPLES, ADDRESS_SAMPLES


################################################################################

class ScriptTest(unittest.TestCase):

    ################################################################################
    # Common tests and methods

    def _get_sample(self, script_type, SAMPLES = SCRIPT_SAMPLES, test_script_type = None):
        if test_script_type is None:
            test_script_type = script_type
        x = SAMPLES[script_type]
        script_type = ScriptType[script_type]
        test_script_type = ScriptType[test_script_type]
        outscript_raw = bytes.fromhex(x['outscript'])
        outscript = outscript_from_raw(outscript_raw)
        if x['inscript'] is not None:
            inscript_raw = bytes.fromhex(x['inscript'])
            inscript = inscript_from_raw(inscript_raw, outscript)
        else:
            inscript = inscript_raw = None
        
        self._test_basics(outscript, inscript, outscript_raw, inscript_raw, test_script_type)
        
        return outscript, inscript, outscript_raw, inscript_raw

    def _test_basics(self, outscript, inscript, outscript_raw, inscript_raw, script_type):
        self.assertEqual(outscript.raw, outscript_raw)
        self.assertEqual(outscript.type, script_type)
        if inscript is not None:
            self.assertEqual(inscript.raw, inscript_raw)
            self.assertEqual(inscript.type, script_type)


    ################################################################################
    # Tests for simple script types

    def test_p2pk(self, *args):
        outscript, inscript, outscript_raw, inscript_raw = \
            self._get_sample('P2PK') if not args else args
        self.assertTrue(isinstance(outscript.get_address(), Address))
        self.assertEqual(outscript.get_address().str[0], '1')
        self.assertTrue(outscript.pubkey)
        self.assertTrue(isinstance(inscript.signature, Signature))
        # reconstruct:
        self.assertEqual(outscript.from_pubkey(outscript.pubkey).raw, outscript.raw)
        self.assertEqual(inscript.from_signature(inscript.signature).raw, inscript.raw)
    
    def test_p2pkh(self, *args):
        outscript, inscript, outscript_raw, inscript_raw = \
            self._get_sample('P2PKH') if not args else args
        self.assertTrue(isinstance(outscript.get_address(), Address))
        self.assertEqual(outscript.get_address().str[0], '1')
        self.assertTrue(isinstance(outscript.pubkey_hash, bytes))
        self.assertTrue(outscript.pubkey_hash)
        self.assertTrue(inscript.pubkey)
        self.assertTrue(inscript.signature)
        self.assertTrue(isinstance(inscript.signature, Signature))
        # reconstruct:
        self.assertEqual(outscript.from_pubkey_hash(outscript.pubkey_hash).raw, outscript.raw)
        self.assertEqual(inscript.from_pubkey_and_signature(inscript.pubkey, inscript.signature).raw, inscript.raw)

    def test_p2multisig(self, *args):
        outscript, inscript, outscript_raw, inscript_raw = \
            self._get_sample('P2MULTISIG') if not args else args
        m = outscript.num_required
        n = outscript.num_total
        self.assertLessEqual(m, n)
        self.assertLessEqual(0, m)
        self.assertLessEqual(1, n)
        self.assertEqual(len(outscript.pubkeys), n)
        self.assertEqual(len(outscript.get_addresses()), n)
        self.assertEqual(len(inscript.signatures), m)
        # reconstruct:
        self.assertEqual(outscript.from_pubkeys(outscript.pubkeys, outscript.num_required).raw, outscript.raw)
        self.assertEqual(inscript.from_signatures(inscript.signatures).raw, inscript.raw)

    def test_provably_unspendable(self, *args):
        outscript, inscript, outscript_raw, inscript_raw = \
            self._get_sample('PROVABLY_UNSPENDABLE') if not args else args
        self.assertEqual(inscript, None)
        self.assertEqual(list(outscript)[0], OP_RETURN)
        # reconstruct:
        self.assertEqual(outscript.from_unused_data(outscript.unused_data).raw, outscript.raw)

    def test_other(self, *args):
        outscript, inscript, outscript_raw, inscript_raw = \
            self._get_sample('OTHER') if not args else args
        # _get_sample() does basic checks. no other checks to run.

    
    ################################################################################
    # Tests for P2SH
    
    def _test_p2sh(self, script_type):
        outscript, inscript, outscript_raw, inscript_raw = \
            self._get_sample(script_type, P2SH_SCRIPT_SAMPLES, test_script_type = 'P2SH')

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
        underlying_test_func(outscript2, inscript2, outscript2_raw, inscript2_raw)
        
        # reconstruct:
        self.assertEqual(outscript.from_script_hash(outscript.script_hash).raw, outscript.raw)
        self.assertEqual(inscript.from_redeem_scripts(outscript2, inscript2).raw, inscript.raw)

    def test_p2sh_p2pk(self):
        self._test_p2sh('P2PK')

    def test_p2sh_p2pkh(self):
        self._test_p2sh('P2PKH')

    def test_p2sh_p2multisig(self):
        self._test_p2sh('P2MULTISIG')

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

################################################################################

if __name__ == '__main__':
    unittest.main()
