"""
Unit-testing address-related tools.
"""

import unittest

from bitcoinscript.address import Address, AddressVersion, to_address
from bitcoinscript.samples import ADDRESS_SAMPLES


################################################################################

class AddressTest(unittest.TestCase):

    def test_address(self):
        for addr_data in ADDRESS_SAMPLES:
            
            hash160 = bytes.fromhex(addr_data['hash160'])
            addr_str = addr_data['address']
            pubkey = bytes.fromhex(addr_data['pubkey']) if addr_data['pubkey'] else None
            is_p2sh = addr_data['is_p2sh']
    
            if pubkey is not None:
                addr = Address.from_pubkey(pubkey)
            else:
                addr = Address(addr_str)
                
            self.assertEqual(addr_str, str(addr))
            self.assertEqual(hash160, addr.hash160)
            self.assertEqual(hash160.hex(), addr.hash160_hex)
            if pubkey is not None:
                self.assertEqual(pubkey, addr.pubkey)
                self.assertEqual(pubkey.hex(), addr.pubkey_hex)
            self.assertEqual(is_p2sh, addr.is_p2sh)
            self.assertEqual(AddressVersion.P2SH if is_p2sh else AddressVersion.P2PK, addr.version)

    def test_constructors(self):
        for addr_data in ADDRESS_SAMPLES:

            hash160 = bytes.fromhex(addr_data['hash160'])
            addr_str = addr_data['address']
            pubkey = bytes.fromhex(addr_data['pubkey']) if addr_data['pubkey'] else None
            is_p2sh = addr_data['is_p2sh']
            
            addr1 = Address(addr_str)
            self.assertEqual(str(addr1), addr_str)
            self.assertEqual(addr1.hash160, hash160)
            self.assertEqual(addr1.pubkey, None)
    
            addr2 = Address.from_hash160(hash160, is_p2sh = is_p2sh)
            self.assertEqual(str(addr2), addr_str)
            self.assertEqual(addr2.hash160, hash160)
            self.assertEqual(addr2.pubkey, None)
            
            self.assertEqual(addr1, addr2)
    
            if pubkey is not None:
                addr3 = Address.from_pubkey(pubkey)
                self.assertEqual(str(addr3), addr_str)
                self.assertEqual(addr3.hash160, hash160)
                self.assertEqual(addr3.pubkey, pubkey)
                self.assertEqual(addr1, addr3)
                self.assertEqual(addr2, addr3)
        
    def test_to_address_func(self):
        for addr_data in ADDRESS_SAMPLES:

            hash160 = bytes.fromhex(addr_data['hash160'])
            addr_str = addr_data['address']
            #pubkey = bytes.fromhex(addr_data['pubkey']) if addr_data['pubkey'] else None
            is_p2sh = addr_data['is_p2sh']
            kw = dict(is_p2sh = is_p2sh)
            
            addr = Address(addr_str)
            self.assertEqual(to_address(addr_str, **kw), addr)
            self.assertEqual(to_address(hash160, **kw), addr)
            self.assertEqual(to_address(hash160.hex(), **kw), addr)

################################################################################

if __name__ == '__main__':
    unittest.main()
