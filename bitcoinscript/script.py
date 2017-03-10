"""
Definition of the concrete (in and out) script types.
"""

from .misc import classproperty
from .basic import (
    ScriptType, InvalidScriptError,
    get_hash160_from_outscript_p2pkh, get_hash160_from_outscript_p2pk,
    get_hash160_from_outscript_p2sh, get_pubkey_from_outscript_p2pk,
    get_script_hash160_for_p2sh, get_outscript_type, )
from .address import Address
from .signature import Signature
from .compose import compose_from_template
from .format import format_script, iter_script_parts, raw_iter_script
from .opcode import OP_RETURN, OP_DUP, OP_HASH160,OP_EQUAL, OP_EQUALVERIFY, OP_CHECKSIG, OP_CHECKMULTISIG


################################################################################

UNKNOWN_STRING = '???'

################################################################################
# Base Script type

class Script:
    """
    A script baseclass, including the parts common to OutScript and InScript.
    """
    
    def __init__(self, raw):
        self.raw = bytes(raw)

    @property
    def hex(self):
        return self.raw.hex()

    def format(self, delim = ' ', *args, **kwargs):
        """
        Format the script as a human-readable string.
        """
        return format_script(self, delim = delim, *args, **kwargs)
        
    def __repr__(self):
        return '<%s %s>' % ( type(self).__name__, self.hex )
    
    def __str__(self):
        return self.format()

    def __hash__(self):
        return hash(self.raw)
    
    def __eq__(self, other):
        try:
            return self.raw == other.raw
        except AssertionError:
            return NotImplemented
    
    def __ne__(self, other):
        return not (self == other)

    def __iter__(self):
        return iter_script_parts(self.raw)


################################################################################
# OutScript types

class OutScript(Script):
    """
    A generic out script (script included in a tx output).
    
    This class serves as a baseclass to all specialized-OutScript types (e.g. OutScriptP2PKH),
    and also represents the "other" out scripts, ones which are not represented by
    any of the specializations.
    """

    type = ScriptType.OTHER
    
    @classproperty
    def InScriptType(cls):
        return InScript
    
    def get_address(self):
        return None

    def __repr__(self):
        addr = self.get_address()
        return '<%s paying to %s>' % ( type(self).__name__, addr if addr else UNKNOWN_STRING )
    
class OutScriptP2PKH(OutScript):
    """
    A P2PKH (pay-to-public-key-hash) OutScript, containing the hash160 of the pubkey to pay to.
    """

    type = ScriptType.P2PKH
    
    _TEMPLATE = [ OP_DUP, OP_HASH160, 'PUSH:hash160', OP_EQUALVERIFY, OP_CHECKSIG ]

    @classproperty
    def InScriptType(cls):
        return InScriptP2PKH
    
    @property
    def pubkey_hash(self):
        return get_hash160_from_outscript_p2pkh(self.raw)
    
    def get_address(self):
        h = self.pubkey_hash
        if h is None:
            return None
        return Address.from_hash160(h)

    @classmethod
    def from_pubkey_hash(cls, pubkey_hash, **kw):
        return cls(cls._compose(pubkey_hash, **kw))

    @classmethod
    def from_address(cls, address, **kw):
        return cls(cls._compose(address.hash160, **kw))

    @classmethod
    def _compose(cls, hash160, **kwargs):
        return compose_from_template(cls._TEMPLATE, hash160 = hash160, **kwargs)

class OutScriptP2PK(OutScript):
    """
    A P2PK (pay-to-public-key) OutScript, containing the pubkey to pay to.
    """

    type = ScriptType.P2PK
    
    _TEMPLATE = [ 'PUSH:pubkey', OP_CHECKSIG ]

    @classproperty
    def InScriptType(cls):
        return InScriptP2PK
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # test script is valid
        try:
            pubkey = self.pubkey
        except Exception as e:
            raise InvalidScriptError('Invalid OutScriptP2PK') from e
        else:
            if pubkey is None:
                raise InvalidScriptError('Cannot extract pubkey from OutScriptP2PK')
    
    @property
    def pubkey(self):
        return get_pubkey_from_outscript_p2pk(self.raw)
    
    def get_address(self):
        pubkey = self.pubkey
        h = get_hash160_from_outscript_p2pk(self.raw)
        if h is None:
            return None
        return Address.from_hash160(h, pubkey = pubkey)

    @classmethod
    def from_pubkey(cls, pubkey, **kw):
        return cls(cls._compose(pubkey, **kw))

    @classmethod
    def from_address(cls, address, **kw):
        pubkey = address.pubkey
        if pubkey is None:
            raise RuntimeError('PubKey not known for address %s' % address)
        return cls(cls._compose(pubkey, **kw))

    @classmethod
    def _compose(cls, pubkey, **kwargs):
        return compose_from_template(cls._TEMPLATE, pubkey = pubkey, **kwargs)

class OutScriptP2SH(OutScript):
    """
    A P2SH (pay-to-script-hash) OutScript, containing the hash160 of the redeem script
    to pay to.
    """

    type = ScriptType.P2SH
    
    _TEMPLATE = [ OP_HASH160, 'PUSH:script_hash', OP_EQUAL ]

    @classproperty
    def InScriptType(cls):
        return InScriptP2SH
    
    @property
    def script_hash(self):
        addr = self.get_address()
        if addr is not None:
            return addr.hash160

    def get_address(self):
        h = get_hash160_from_outscript_p2sh(self.raw)
        return Address.from_hash160(h, is_p2sh = True)
    
    @classmethod
    def from_script_hash(cls, script_hash, **kw):
        return cls(cls._compose(script_hash, **kw))

    @classmethod
    def from_script(cls, script, **kw):
        script_hash = get_script_hash160_for_p2sh(script.raw)
        return cls(cls._compose(script_hash, **kw))

    @classmethod
    def _compose(cls, script_hash, **kwargs):
        return compose_from_template(cls._TEMPLATE, script_hash = script_hash, **kwargs)

class OutScriptP2Multisig(OutScript):
    """
    A standard M-of-N P2MULTISIG (pay-to-multisig) OutScript, containing total number of
    "payees" ("N"), how many of them are required to sign ("M"), and the N pubkeys to pay to.
    """

    type = ScriptType.P2MULTISIG

    _TEMPLATE = [ 'CONST:num_required', 'inner', 'CONST:num_total', OP_CHECKMULTISIG ]
    _INNER_TEMPLATE = [ 'PUSH:pubkey' ]

    @classproperty
    def InScriptType(cls):
        return InScriptP2Multisig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # test script is valid
        try:
            num_required = self.num_required
            num_total = self.num_total
        except Exception as e:
            raise InvalidScriptError('Invalid OutScriptP2Multisig') from e
        else:
            if num_required > num_total:
                raise InvalidScriptError('Multisig\'s num_required must be <= num_total. Got: %s and %s' % (
                    num_required, num_total))
        pubkeys = self.pubkeys
        if pubkeys is None or None in pubkeys:
            raise InvalidScriptError('Failed extracting pubkeys from OutScriptP2Multisig')
        if len(pubkeys) != num_total:
            raise InvalidScriptError('Wrong number of pubkeys in OutScriptP2Multisig: expected %d, got %d' % (
                num_total, len(pubkeys)))

    @property
    def num_required(self):
        """
        The "M" from the "M-of-N".
        """
        return int(list(self)[0])

    @property
    def num_total(self):
        """
        The "N" from the "M-of-N".
        """
        return int(list(self)[-2])
    
    @property
    def pubkeys(self):
        pubkeys = list(iter_script_parts(self.raw))[1:-2]
        if len(pubkeys) == self.num_total:
            return pubkeys

    def get_addresses(self):

        def to_addr(pubkey):
            try:
                return Address.from_pubkey(pubkey)
            except TypeError:
                return None

        pubkeys = self.pubkeys
        if pubkeys is not None:
            return [ to_addr(pubkey) for pubkey in self.pubkeys ]

    @classmethod
    def from_pubkeys(cls, pubkeys, num_required, **kw):
        return cls(cls._compose(pubkeys, num_required, **kw))

    @classmethod
    def from_addresses(cls, addresses, num_required, **kw):
        pubkeys = [ addr.pubkey for addr in addresses ]
        if None in pubkeys:
            raise ValueError('Got None in pubkeys: %s' % pubkeys)
        return cls(cls._compose(pubkeys, num_required, **kw))

    @classmethod
    def _compose(cls, pubkeys, num_required, **kwargs):
        num_total = len(pubkeys)
        inner = b''.join( compose_from_template(cls._INNER_TEMPLATE, pubkey = pubkey, **kwargs) for pubkey in pubkeys )
        return compose_from_template(cls._TEMPLATE, num_required = num_required, num_total = num_total, inner = inner, **kwargs)

    def __repr__(self):
        addrs = self.get_addresses()
        addrs_str = ','.join(str(addr) for addr in addrs) if addrs else UNKNOWN_STRING
        return '<%s %d-of-%d paying to %s>' % ( type(self).__name__, self.num_required, self.num_total, addrs_str, )

class OutScriptProvablyUnspendable(OutScript):
    """
    A provably-unspendable OutScript.
    """

    type = ScriptType.PROVABLY_UNSPENDABLE

    _TEMPLATE = [ OP_RETURN, ]
    
    @classproperty
    def InScriptType(cls):
        # by definition, there is no InScriptType
        return None

    @property
    def unused_data(self):
        # find index of second operator:
        try:
            _, _, second_op_idx = raw_iter_script(self.raw)[1]
        except IndexError:
            return None
        else:
            return self.raw[second_op_idx:]

    @classmethod
    def from_unused_data(cls, unused_data, **kw):
        return cls(cls._compose(unused_data, **kw))

    @classmethod
    def _compose(cls, unused_data = None, **kwargs):
        s = compose_from_template(cls._TEMPLATE, **kwargs)
        if unused_data is not None:
            s += unused_data
        return s

    def __repr__(self):
        return '<%s>' % ( type(self).__name__, )


################################################################################
# InScript types

class InScript(Script):
    """
    A generic in script (script included in a tx input).
    
    This class serves as a baseclass to all specialized-InScript types (e.g. InScriptP2PKH),
    and also represents the "other" in scripts, ones which are not represented by
    any of the specializations.
    """

    @classproperty
    def type(cls):
        return cls.OutScriptType.type

    @classproperty
    def OutScriptType(cls):
        return OutScript

class InScriptP2PKH(InScript):
    """
    A P2PKH (pay-to-public-key-hash) InScript, containing the pubkey whose hash is included
    in the outscript, and a signature (using the private key corresponding to the pubkey).
    """
    
    _TEMPLATE = [ 'PUSH:signature', 'PUSH:pubkey' ]

    @classproperty
    def OutScriptType(cls):
        return OutScriptP2PKH
    
    @property
    def signature(self):
        sig, pubkey = self._get_sig_and_pubkey()
        return Signature.decode(sig)
    
    @property
    def pubkey(self):
        sig, pubkey = self._get_sig_and_pubkey()
        return pubkey
    
    @property
    def unused_data(self):
        # find index of next-to-last operator:
        try:
            _, _, next_to_last_op_idx = raw_iter_script(self.raw)[-2]
        except IndexError:
            return None
        else:
            if next_to_last_op_idx > 0:
                return self.raw[:next_to_last_op_idx]
    
    def _get_sig_and_pubkey(self):
        sig, pubkey = list(self)[-2:]
        return sig, pubkey

    @classmethod
    def from_pubkey_and_signature(cls, pubkey, signature, **kw):
        return cls(cls._compose(pubkey, signature, **kw))

    @classmethod
    def from_address_and_signature(cls, address, signature, **kw):
        pubkey = address.pubkey
        if pubkey is None:
            raise RuntimeError('PubKey not known for address %s' % address)
        return cls(cls._compose(pubkey, signature, **kw))

    @classmethod
    def _compose(cls, pubkey, signature, unused_data = None, **kwargs):
        x = compose_from_template(cls._TEMPLATE, signature = signature.encode(), pubkey = pubkey, **kwargs)
        if unused_data is not None:
            x = unused_data + x
        return x

class InScriptP2PK(InScript):
    """
    A P2PK (pay-to-public-key) InScript, containing a signature (using the private key
    corresponding to the pubkey).
    """

    _TEMPLATE = [ 'PUSH:signature' ]

    @classproperty
    def OutScriptType(cls):
        return OutScriptP2PK

    @property
    def signature(self):
        return Signature.decode(self._get_sig())
    
    def _get_sig(self):
        sig, = iter(self)
        return sig

    @classmethod
    def from_signature(cls, signature, **kw):
        return cls(cls._compose(signature, **kw))

    @classmethod
    def _compose(cls, signature, **kwargs):
        return compose_from_template(cls._TEMPLATE, signature = signature.encode(), **kwargs)

class InScriptP2SH(InScript):
    """
    A P2SH (pay-to-script-hash) InScript.
    
    This InScript includes the redeem-script (which is an OutScript), and the redeem-input-script,
    which is the inscript corresponding to the redeem-script.
    
    Redeem-script's script-type can be any of the known types, except for P2SH (nested P2SH scripts are
    not allowed).
    """

    _TEMPLATE = [ 'redeem_inscript', 'PUSH:redeem_script' ]

    @classproperty
    def OutScriptType(cls):
        return OutScriptP2SH

    @property
    def redeem_script_raw(self):
        parts = list(self)
        if len(parts) >= 2:
            rscript = parts[-1]
            if isinstance(rscript, bytes):
                return rscript
    
    @property
    def redeem_script(self):
        raw = self.redeem_script_raw
        if raw is not None:
            return outscript_from_raw(raw, allow_p2sh = False)

    @property
    def redeem_inscript_raw(self):
        # find index of last operator:
        _, _, last_op_idx = list(raw_iter_script(self.raw))[-1]
        return self.raw[:last_op_idx]
    
    @property
    def redeem_inscript(self):
        rscript = self.redeem_script
        if rscript is not None:
            return inscript_from_raw(self.redeem_inscript_raw, rscript)

    @classmethod
    def from_redeem_scripts(cls, redeem_script, redeem_inscript, **kw):
        return cls(cls._compose(redeem_script, redeem_inscript, **kw))

    @classmethod
    def _compose(cls, redeem_script, redeem_inscript, **kwargs):
        redeem_script = getattr(redeem_script, 'raw', redeem_script)
        redeem_inscript = getattr(redeem_inscript, 'raw', redeem_inscript)
        return compose_from_template(cls._TEMPLATE, redeem_script = redeem_script, redeem_inscript = redeem_inscript, **kwargs)
    
    def __repr__(self):
        rscript_str = repr(self.redeem_script) if self.redeem_script else UNKNOWN_STRING
        return '<%s containing %s >' % ( type(self).__name__, rscript_str )

class InScriptP2Multisig(InScript):
    """
    A standard M-of-N P2MULTISIG (pay-to-multisig) InScript, containing M signatures,
    using M of the N pubkeys from the outscript.
    """

    _TEMPLATE = [ 'inner' ]
    _INNER_TEMPLATE = [ 'PUSH:signature' ]

    @classproperty
    def OutScriptType(cls):
        return OutScriptP2Multisig

    @property
    def signatures(self):
        num_signatures, _ = self._find_split_point()
        data = list(self)
        sigs = data[len(data) - num_signatures:]
        return [ Signature.decode(sig) for sig in sigs ]
    
    @property
    def unused_data(self):
        _, idx = self._find_split_point()
        return self.raw[:idx]
    
    def _find_split_point(self):
        # Note: this is only a guess, and might not work in all cases.
        # We can't know for sure where the unused data ends and the signatures start without
        # knowing how many signatures there are.
        op_idxs = []
        signatures = []
        for _, data, op_idx in raw_iter_script(self.raw):
            op_idxs.append(op_idx)
            signatures.append(data)
        op_idxs.append(len(self.raw))  # "end" idx
        num_signatures = 0
        for sig in reversed(signatures):
            if isinstance(sig, bytes) and 50 < len(sig) < 75:
                num_signatures += 1
            else:
                break
        return num_signatures, op_idxs[len(op_idxs) - num_signatures - 1]

    @classmethod
    def from_signatures(cls, signatures, **kw):
        return cls(cls._compose(signatures, **kw))

    @classmethod
    def _compose(cls, signatures, unused_data = None, **kwargs):
        inner = b''.join(
            compose_from_template(cls._INNER_TEMPLATE, signature = sig.encode(), **kwargs)
            for sig in signatures
        )
        s = compose_from_template(cls._TEMPLATE, inner = inner, **kwargs)
        if unused_data is None:
            # Must push at least one "unused" byte
            unused_data = b'\x00'
        if unused_data is not None:
            s = unused_data + s
        return s


################################################################################
# Useful functions:

OUTPUT_SCRIPT_CLASS_BY_TYPE = {
    _cls.type : _cls for _cls in
    [ OutScript, OutScriptP2PKH, OutScriptP2PK, OutScriptP2SH, OutScriptP2Multisig, OutScriptProvablyUnspendable ]
}

INPUT_SCRIPT_CLASS_BY_TYPE = {
    _cls.type : _cls for _cls in
    [ InScript, InScriptP2PKH, InScriptP2PK, InScriptP2SH, InScriptP2Multisig ]
}


def outscript_from_raw(outscript, allow_p2sh = True):
    """
    Create an OutScript object from a raw outscript, with the proper OutScript subclass.
    """
    script_type = get_outscript_type(outscript, allow_p2sh = allow_p2sh)
    try:
        return OUTPUT_SCRIPT_CLASS_BY_TYPE[script_type](outscript)
    except InvalidScriptError:
        # we probably got an non-standard or invalid script which looked like a specific
        # type, but failed getting deserialized as such.
        return OutScript(outscript)

def inscript_from_raw(inscript, type_or_outscript):
    """
    Create an InScript object from a raw inscript, with the proper InScript subclass.
    :param type_or_outscript: either a ScriptType, or a OutScript instance whose
        script-type we need to match.
    """
    try:
        # if caller provided an OutScript, we use its InScriptType directly
        inscript_cls = type_or_outscript.InScriptType
    except AttributeError:
        # caller provided a ScriptType
        script_type = type_or_outscript
        inscript_cls = INPUT_SCRIPT_CLASS_BY_TYPE[script_type]
    return inscript_cls(inscript)

################################################################################
