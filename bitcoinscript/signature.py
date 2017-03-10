"""
Classes for representing signatures, including the SigHash byte.
"""

from .misc import classproperty


################################################################################

class SigHash:
    """
    A SigHash value (aka "hashtype").
    
    This value is included in a signature to indicate what parts of the tx are
    being signed.
    
    :see: https://en.bitcoin.it/wiki/OP_CHECKSIG#How_it_works
    
    "ACP" means "Anyone Can Pay"
    """
    
    _TYPE_MASK = 0x1F
    _ACP_MASK = 0x80
    _TYPE_TO_INT = {
        'ALL': 1, 'NONE': 2, 'SINGLE': 3,
        'ALL*': 0,  # 0 is also interpreted as "ALL", but is not supposed to be used
    }  
    _INT_TO_TYPE = { _v:_k for _k,_v in _TYPE_TO_INT.items()}
    
    
    def __init__(self, type, acp = False):
        self.type = type
        self.acp = acp
    
    @property
    def hex(self):
        return '0x%02x' % self.encode()
    
    def encode(self):
        return self._TYPE_TO_INT[self.type] + self._ACP_MASK * self.acp

    @classmethod
    def decode(cls, x):
        if not 0 <= x < 0xff:
            raise ValueError('Invalid SigHash value: %s' % x)
        if x & (~cls._TYPE_MASK & ~cls._ACP_MASK):
            raise ValueError('Invalid SigHash value: %s' % x)
        try:
            type = cls._INT_TO_TYPE[x & cls._TYPE_MASK]
        except KeyError:
            raise ValueError('Invalid SigHash value: %s' % x)
        acp = (x & cls._ACP_MASK) != 0
        return cls(type, acp)
    
    def with_acp(self, new_acp = True):
        return type(self)(self.type, acp = new_acp)
    
    def __str__(self):
        return self.type + ('|ANYONECANPAY' if self.acp else '')
        
    def __repr__(self):
        return '<%s %s>' % ( type(self).__name__, self )

    def __eq__(self, other):
        try:
            return self.type  == other.type and self.acp == other.acp
        except AttributeError:
            return NotImplemented

    def __ne__(self, other):
        return not (self == other)
    
    def __hash__(self):
        return hash(self.encode())
    
    @classproperty
    def ALL(cls): return cls('ALL')

    @classproperty
    def NONE(cls): return cls('NONE')

    @classproperty
    def SINGLE(cls): return cls('SINGLE')

    @classproperty
    def ALL_ANYONECANPAY(cls): return cls('ALL', acp = True)

    @classproperty
    def NONE_ANYONECANPAY(cls): return cls('NONE', acp = True)

    @classproperty
    def SINGLE_ANYONECANPAY(cls): return cls('SINGLE', acp = True)


class Signature:
    """
    A signature of a transaction, as included in scripts.
    The signature includes the SigHash value.

    :see: https://en.bitcoin.it/wiki/OP_CHECKSIG#How_it_works
    """
    
    def __init__(self, base_sig, sighash):
        self.base_sig = base_sig
        self.sighash = sighash

    @property
    def hex(self):
        return self.encode().hex()

    @property
    def base_sig_hex(self):
        return self.base_sig.hex()

    def encode(self):
        return self.base_sig + self.sighash.encode().to_bytes(1, byteorder = 'little')
        
    @classmethod
    def decode(cls, raw):
        return cls(raw[:-1], SigHash.decode(raw[-1]))

    def __str__(self):
        return self.hex
        
    def __repr__(self):
        return '<%s %s>' % ( type(self).__name__, self )

    def __eq__(self, other):
        try:
            return self.base_sig == other.base_sig and self.sighash == other.sighash
        except AttributeError:
            return NotImplemented

    def __ne__(self, other):
        return not (self == other)
    
    def __hash__(self):
        return hash(self.encode())

################################################################################

