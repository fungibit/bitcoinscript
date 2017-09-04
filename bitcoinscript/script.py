"""
Definition of the concrete (in and out) script types.
"""

import datetime
import itertools

from .misc import classproperty
from .basic import (
    ScriptType, InvalidScriptError,
    get_hash160_from_outscript_p2pkh, get_hash160_from_outscript_p2pk,
    get_hash160_from_outscript_p2sh, get_pubkey_from_outscript_p2pk,
    get_script_hash160_for_p2sh,
    get_outscript_type, parse_if_else,
    iter_script_parts, iter_script_raw,
    LOCKTIME_THRESHOLD, )
from .opcode import to_hash_function
from .address import Address
from .signature import Signature
from .compose import compose_from_template
from .format import format_script, format_data_token
from .opcode import (
    OP_RETURN, OP_DUP, OP_DROP, OP_HASH160,OP_EQUAL, OP_EQUALVERIFY,
    OP_IF, OP_ELSE, OP_ENDIF, OP_TRUE, OP_FALSE,
    OP_CHECKSIG, OP_CHECKMULTISIG, OP_CHECKLOCKTIMEVERIFY,
    )


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

class OutScriptTimeLock(OutScript):
    """
    A time-locked OutScript, containing a time-lock condition, and the "rest" of the script
    (the "inner" script), which is itself an OutScript.
    """

    type = ScriptType.TIMELOCK
    
    _TEMPLATE = [ 'PUSH:locktime', OP_CHECKLOCKTIMEVERIFY, OP_DROP, 'inner_script' ]

    @classproperty
    def InScriptType(cls):
        # Could be any InScript (depending on the type of self.inner_script)
        return None
    
    @property
    def locktime(self):
        """
        The "raw" locktime value (int).  Can represent either block height or specific time.
        """
        locktime_bytes = next(iter(self))
        return int.from_bytes(locktime_bytes, byteorder = 'little')
    
    @property
    def locktime_block_height(self):
        """
        The block-height value of locktime. This is None unless locktime represents a block height.
        """
        if self.is_locked_to_block_height:
            return self.locktime
    
    @property
    def locktime_datetime(self):
        """
        The datetime value of locktime. This is None unless locktime represents specific time.
        """
        if not self.is_locked_to_block_height:
            return datetime.datetime.fromtimestamp(self.locktime)
    
    @property
    def is_locked_to_block_height(self):
        return self.locktime < LOCKTIME_THRESHOLD

    @property
    def inner_script(self):
        return outscript_from_raw(self.inner_script_raw)

    @property
    def inner_script_raw(self):
        for op, _, op_idx in iter_script_raw(self.raw):
            if op == OP_DROP:
                break
        return self.raw[op_idx+1:]  # everything after the OP_DROP

    def __repr__(self):
        if self.is_locked_to_block_height:
            lock_str = 'block %s' % self.locktime_block_height
        else:
            lock_str = '%s' % self.locktime_datetime
        return '<%s %r time-locked to %s>' % ( type(self).__name__, self.inner_script, lock_str )

    @classmethod
    def from_script(cls, inner_script, locktime, **kw):
        if isinstance(locktime, datetime.datetime):
            orig_locktime = locktime
            locktime = int(locktime.timestamp())
            if locktime < LOCKTIME_THRESHOLD:
                raise ValueError('Invalid locktime value: %r' % orig_locktime)
        inner_script = getattr(inner_script, 'raw', inner_script)
        return cls(cls._compose(inner_script, locktime, **kw))

    @classmethod
    def _compose(cls, inner_script, locktime, **kwargs):
        # convert locktime to bytes
        if isinstance(locktime, int):
            locktime = locktime.to_bytes(4, byteorder = 'little')
        return compose_from_template(cls._TEMPLATE, locktime = locktime, inner_script = inner_script, **kwargs)

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

class OutScriptHashPreImage(OutScript):
    """
    A hash-preimate OutScript, redeemable by providing the preimage of a hash, or
    multiple hashes.
    
    The structure of the script is the following triplet, repeated for each hash-preimage
    required: ( hash_op, hash_value, comparison_op ), where hash_op can be any of the hashing
    operators (OP_SHA256, OP_HASH160, etc.), and comparison_op is OP_EQUAL for the last triplet,
    and OP_EQUALVERIFY for all the rest.
    """

    type = ScriptType.HASH_PREIMAGE
    
    _TEMPLATE = [ 'hash_op', 'PUSH:hash', 'comparison_op']  # can be repeated

    @classproperty
    def InScriptType(cls):
        return InScriptHashPreImage
    
    @property
    def hashes(self):
        return list(itertools.islice(iter_script_parts(self.raw), 1, None, 3))
    
    @property
    def hash_type(self):
        return self.hash_function.__name__

    @property
    def hash_function(self):
        return to_hash_function(self.hash_opcode)

    @property
    def hash_opcode(self):
        return next(iter_script_parts(self.raw))
    
    def __repr__(self):
        hashes_str = ', '.join( format_data_token(hash) for hash in self.hashes )
        return '<%s[%s] %s>' % ( type(self).__name__, self.hash_type, hashes_str )
    
    @classmethod
    def from_hashes(cls, hash_func, hashes, **kw):
        return cls(cls._compose(hash_func, hashes, **kw))

    @classmethod
    def from_preimages(cls, hash_func, preimages, **kw):
        hash_func = to_hash_function(hash_func)
        hashes = [ hash_func(pi) for pi in preimages ]
        return cls.from_hashes(hash_func, hashes, **kw)

    @classmethod
    def _compose(cls, hash_func, hashes, **kwargs):
        hash_op = to_hash_function(hash_func).OP
        n = len(hashes)
        return b''.join([
            cls._compose_single(hash_op, hash, is_last = (i==n-1), **kwargs)
            for i, hash in enumerate(hashes)
        ])

    @classmethod
    def _compose_single(cls, hash_op, hash, is_last, **kwargs):
        return compose_from_template(
            cls._TEMPLATE,
            hash_op = hash_op,
            hash = hash,
            comparison_op = OP_EQUAL if is_last else OP_EQUALVERIFY,
            **kwargs
        )

class OutScriptIf(OutScript):
    """
    An if/else OutScript, containing if-true and optional if-false scripts.
    Note that having multiple OP_ELSE's is not supported by this class.
    """

    type = ScriptType.IF
    
    _TEMPLATE_WITH_ELSE = [ OP_IF, 'if_true_script', OP_ELSE, 'if_false_script', OP_ENDIF ]
    _TEMPLATE_NO_ELSE  =  [ OP_IF, 'if_true_script',                             OP_ENDIF ]

    @classproperty
    def InScriptType(cls):
        return InScriptIf
    
    @property
    def if_true_script(self):
        return self.inner_scripts[True]

    @property
    def if_false_script(self):
        return self.inner_scripts[False]

    @property
    def has_else(self):
        _, else_idx, _ = parse_if_else(self.raw)
        return else_idx is not None

    @property
    def inner_scripts(self):
        """
        A dict with keys [True, False] and values [if_true_script, if_false_script]
        """
        return {
            k: outscript_from_raw(outscript) if outscript is not None else None
            for k, outscript in self.inner_scripts_raw.items()
        }
        
    @property
    def inner_scripts_raw(self):
        """
        Same as self.inner_scripts, but the values are the raw scripts (bytes).
        This is faster than using self.inner_scripts.
        """
        if_idx, else_idx, endif_idx = parse_if_else(self.raw)
        if else_idx is not None:
            return {
                True:  self.raw[if_idx + 1 : else_idx],
                False: self.raw[else_idx + 1 : endif_idx],
            }
        else:
            # no OP_ELSE:
            return {
                True:  self.raw[if_idx + 1 : endif_idx],
                False: None,
            }

    def __repr__(self):
        if self.has_else:
            else_str = 'ELSE %r' % self.if_false_script
        else:
            else_str = '(no else)'
        return '<%s %r %s>' % ( type(self).__name__, self.if_true_script, else_str )

    @classmethod
    def from_scripts(cls, if_true_script, if_false_script, **kw):
        if_true_script = getattr(if_true_script, 'raw', if_true_script)
        if_false_script = getattr(if_false_script, 'raw', if_false_script)
        return cls(cls._compose(if_true_script, if_false_script, **kw))

    @classmethod
    def _compose(cls, if_true_script, if_false_script, **kwargs):
        if if_false_script is not None:
            return compose_from_template(
                cls._TEMPLATE_WITH_ELSE,
                if_true_script = if_true_script,
                if_false_script = if_false_script,
                **kwargs
            )
        else:
            return compose_from_template(
                cls._TEMPLATE_NO_ELSE,
                if_true_script = if_true_script,
                **kwargs
            )

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
        return self.raw[1:]

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
            _, _, next_to_last_op_idx = list(iter_script_raw(self.raw))[-2]
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
        _, _, last_op_idx = list(iter_script_raw(self.raw))[-1]
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
        for _, data, op_idx in iter_script_raw(self.raw):
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

class InScriptHashPreImage(InScript):
    """
    A hash-preimage InScript, containing the preimages of the hashes in the outscript.
    """
    
    _TEMPLATE = [ 'PUSH:preimage', ]

    @classproperty
    def OutScriptType(cls):
        return OutScriptHashPreImage
    
    @property
    def preimages(self):
        return list(self)
    
    @classmethod
    def from_preimages(cls, preimages, **kw):
        return cls(cls._compose(preimages, **kw))

    @classmethod
    def _compose(cls, preimages, **kwargs):
        return b''.join([
            compose_from_template(cls._TEMPLATE, preimage = preimage, **kwargs)
            for preimage in preimages
        ])

class InScriptIf(InScript):
    """
    An inscript satisfying an IF outscript.  Contains a condition_value (OP_TRUE or OP_FALSE),
    which indicates if the inscript is satisfying outscripts if_true_script or if_false_script.
    Also contains an inner inscript, which satisfies the appropriate outscript's inner script
    (if_true_script or if_false_script).
    """

    _TEMPLATE = [ 'inner_inscript', 'condition_value' ]

    @classproperty
    def OutScriptType(cls):
        return OutScriptIf

    @property
    def condition_value(self):
        """
        Condition value as bool.
        """
        return self.condition_value_raw != OP_FALSE

    @property
    def condition_value_raw(self):
        """
        Condition value as a single byte.
        """
        return self.raw[-1]
        
    @property
    def inner_inscript_raw(self):
        """
        Inner inscript as bytes.
        """
        return self.raw[:-1]

    def get_inner_inscript(self, type_or_outscript = None):
        """
        Inner inscript, with type corresponding to given outscript type.
        """
        return inscript_from_raw(self.inner_inscript_raw, type_or_outscript)

    def __repr__(self):
        inner = self.get_inner_inscript()
        return '<%s %r for %s-branch>' % ( type(self).__name__, inner, str(self.condition_value).upper())
    
    @classmethod
    def from_condition_value(cls, condition_value, inner_inscript, **kw):
        return cls(cls._compose(condition_value, inner_inscript, **kw))

    @classmethod
    def _compose(cls, condition_value, inner_inscript, **kwargs):
        if isinstance(condition_value, bool):
            condition_value = OP_TRUE if condition_value else OP_FALSE
        return compose_from_template(
            cls._TEMPLATE,
            condition_value = condition_value,
            inner_inscript = inner_inscript,
            **kwargs
        )
    

################################################################################
# Useful functions:

OUTPUT_SCRIPT_CLASS_BY_TYPE = {
    _cls.type : _cls for _cls in
    [ OutScript, OutScriptP2PKH, OutScriptP2PK, OutScriptP2SH, OutScriptTimeLock, OutScriptIf, OutScriptP2Multisig, OutScriptHashPreImage, OutScriptProvablyUnspendable ]
}

INPUT_SCRIPT_CLASS_BY_TYPE = {
    _cls.type : _cls for _cls in
    [ InScript, InScriptP2PKH, InScriptP2PK, InScriptP2SH, InScriptP2Multisig, InScriptHashPreImage, InScriptIf ]
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

def inscript_from_raw(inscript, type_or_outscript = None):
    """
    Create an InScript object from a raw inscript, with the proper InScript subclass.
    :param type_or_outscript: either a ScriptType, or a OutScript instance whose
        script-type we need to match.
    """
    
    if type_or_outscript is None:
        type_or_outscript = ScriptType.OTHER
    
    # support timelock: for timelock outscripts, inscript_type corresponds
    # to outscript.inner_script.type
    try:
        inner_script = type_or_outscript.inner_script
    except AttributeError:
        pass
    else:
        return inscript_from_raw(inscript, inner_script)
    
    try:
        # if caller provided an OutScript, we use its InScriptType directly
        inscript_cls = type_or_outscript.InScriptType
    except AttributeError:
        # caller provided a ScriptType
        script_type = type_or_outscript
        inscript_cls = INPUT_SCRIPT_CLASS_BY_TYPE[script_type]
    return inscript_cls(inscript)

def strip_if_scripts(if_outscript, if_inscript):
    """
    Given an OutScriptIf and an InScriptIf satisfying it, return the "active" parts
    of them.  I.e., if if_inscript.condition_value=True, return the "true" branch, else
    the "false" branch.
    :return: a 2-tuple of (OutScript, InScript)
    """
    # extract condition_value from inscript:
    cond = if_inscript.condition_value
    # extract corresponding branch of outscript:
    inner_outscript = if_outscript.inner_scripts[cond]
    # extract inner inscript, with script_type corresponding to inner_outscript:
    inner_inscript = if_inscript.get_inner_inscript(inner_outscript)
    return inner_outscript, inner_inscript
    
################################################################################
