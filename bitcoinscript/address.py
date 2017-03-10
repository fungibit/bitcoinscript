"""
The bitcoin address class.
"""

from .basic import AddressVersion, pubkey_to_hash160, hash160_to_addr, addr_to_hash160


################################################################################


class Address:
    """
    A bitcoin address.
    
    An address can be represented as its "address string" (e.g. '1CNvsbUPpWMNHUkEaAnVghMAma6vSYtaHA'),
    or its hash160 (e.g. 0x7ccf16d3763a134d86ef5504ffa723d8dbf09ba1), and may be associated with a
    public key.
    
    :see: http://en.bitcoinwiki.org/Bitcoin_address
    """
    
    def __init__(self, address, hash160 = None, pubkey = None):
        self.str = address
        if hash160 is None:
            hash160 = addr_to_hash160(address)
        self.hash160 = hash160
        self.pubkey = pubkey
    
    @property
    def hash160_hex(self):
        return self.hash160.hex()
    
    @property
    def pubkey_hex(self):
        if self.pubkey is not None:
            return self.pubkey.hex()
    
    @property
    def is_p2sh(self):
        return self.version == AddressVersion.P2SH
    
    @property
    def version(self):
        if self.str[0] == '1':
            return AddressVersion.P2PK
        elif self.str[0] == '3':
            return AddressVersion.P2SH
        else:
            assert 0, 'Unknown address-version prefix: %s' % self.str
    
    @classmethod
    def from_hash160(cls, hash160, is_p2sh = False, **kwargs):
        addr = hash160_to_addr(hash160, is_p2sh = is_p2sh)
        return cls(addr, hash160 = hash160, **kwargs)

    @classmethod
    def from_pubkey(cls, pubkey, **kwargs):
        hash160 = pubkey_to_hash160(pubkey)
        return cls.from_hash160(hash160 = hash160, pubkey = pubkey, **kwargs)

    @classmethod
    def from_hash160_hex(cls, hash160_hex, **kwargs):
        return cls.from_hash160(bytes.fromhex(hash160_hex))

    def __repr__(self):
        return '%s(%r)' % ( type(self).__name__, self.str )
    
    def __str__(self):
        return self.str
    
    def __eq__(self, other):
        try:
            return self.str == other.str
        except AttributeError:
            return NotImplemented
    
    def __ne__(self, other):
        return not (self == other)
    
    def __hash__(self):
        return hash(self.str)
    
    
################################################################################

def to_address(x, is_p2sh = False):
    """
    A convenience function for converting different data representations to
    an Address object.
    
    >>> to_address('13LextvmNLyH7UYp4pKUYKEihFwDZaWQHt')  # address
    Address('13LextvmNLyH7UYp4pKUYKEihFwDZaWQHt')
    >>> to_address('19a7d869032368fd1f1e26e5e73a4ad0e474960e')  # hash160 (hex)
    Address('13LextvmNLyH7UYp4pKUYKEihFwDZaWQHt')
    >>> to_address(bytes.fromhex('19a7d869032368fd1f1e26e5e73a4ad0e474960e'))  # hash160 (bytes)
    Address('13LextvmNLyH7UYp4pKUYKEihFwDZaWQHt')
    """
    if isinstance(x, str):
        if 26 <= len(x) <= 35 and x[0] in ('1', '3'):
            return Address(x)
        elif len(x) > 35:
            # assume hex form of hash160
            x = bytes.fromhex(x)
        # else: will raise later on
    if isinstance(x, bytes):
        return Address.from_hash160(x, is_p2sh = is_p2sh)
    raise TypeError('Address not understood: %r' % (x,))

################################################################################

