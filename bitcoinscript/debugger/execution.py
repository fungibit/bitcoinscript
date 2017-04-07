"""
Tools for executing scripts.
"""

import copy
import hashlib

from bitcoin.core import CTransaction
import bitcoin.core._bignum
import bitcoin.core.serialize

from bitcoin.core.scripteval import DISABLED_OPCODES,_ISA_BINOP,_ISA_UNOP,MAX_SCRIPT_OPCODES,OP_1,OP_16,OP_1NEGATE,OP_2DROP,OP_2DUP,OP_2OVER,OP_2ROT,OP_2SWAP,OP_3DUP,OP_CHECKMULTISIG,OP_CHECKMULTISIGVERIFY,OP_CHECKSIG,OP_CHECKSIGVERIFY,OPCODE_NAMES,OP_CODESEPARATOR,OP_DEPTH,OP_DROP,OP_DUP,OP_ELSE,OP_ENDIF,OP_EQUAL,OP_EQUALVERIFY,OP_FROMALTSTACK,OP_HASH160,OP_HASH256,OP_IF,OP_IFDUP,OP_NIP,OP_NOP,OP_NOP1,OP_NOP10,OP_NOTIF,OP_OVER,OP_PICK,OP_PUSHDATA4,OP_RETURN,OP_RIPEMD160,OP_ROLL,OP_ROT,OP_SHA1,OP_SHA256,OP_SIZE,OP_SWAP,OP_TOALTSTACK,OP_TUCK,OP_VERIFY,OP_WITHIN,SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,SCRIPT_VERIFY_CLEANSTACK
from bitcoin.core.scripteval import _BinOp,_CastToBigNum,_CastToBool,_CheckExec,_CheckMultiSig,_CheckSig,CScript,EvalScriptError,VerifyScriptError,FindAndDelete,MaxOpCountError,MAX_SCRIPT_ELEMENT_SIZE,MAX_SCRIPT_SIZE,MAX_STACK_ITEMS,MissingOpArgumentsError,_UnaryOp,VerifyOpFailedError, CScriptInvalidError, SCRIPT_VERIFY_P2SH

################################################################################

class ScriptExecutionState:
    """
    Representing the state of a script execution.
    """
    
    def __init__(self,
        stack = None,
        altstack = None,
        vfExec = None,
        pbegincodehash = None,
        nOpCount = None,
        
        scriptIn = None,
        txTo = None,
        inIdx = None,
        flags = None,
        
        last_op = None,
        scriptRole = None,
        
        error = None,
        is_final = False,
        ):
        
        self.stack = stack
        self.altstack = altstack
        self.vfExec = vfExec
        self.pbegincodehash = pbegincodehash
        self.nOpCount = nOpCount
        
        self.scriptIn = scriptIn
        self.txTo = txTo
        self.inIdx = inIdx
        self.flags = flags
        
        self.last_op = last_op
        self.scriptRole = scriptRole
        
        self.error = error
        self.is_final = is_final or (self.error is not None)

    @classmethod
    def from_another_state(cls, state, **kw):
        d = dict(state.__dict__)
        d.update(kw)
        return cls(**d)

    @property
    def is_error(self):
        return self.error is not None

    @property
    def error_string(self):
        if self.error is not None:
            return '[%s] %s' % ( type(self.error).__name__, self.error )

    @property
    def is_final_success(self):
        return self.is_final and not self.is_error

################################################################################

def _EvalScriptGenerator(stack, scriptIn, txTo, inIdx, flags=(), **state_kwargs):
    """
    Evaluate a script, generating ScriptExecutionState's.
    
    :note: This is copy-pasted-modified version of _EvalScript() function in
        module bitcoin.core.scripteval.  Ultimately, should refactor the function
        and submit a pull request so copy-pasting isn't necessary.

    """
    if len(scriptIn) > MAX_SCRIPT_SIZE:
        raise EvalScriptError('script too large; got %d bytes; maximum %d bytes' %
                                        (len(scriptIn), MAX_SCRIPT_SIZE),
                              stack=stack,
                              scriptIn=scriptIn,
                              txTo=txTo,
                              inIdx=inIdx,
                              flags=flags)

    altstack = []
    vfExec = []
    pbegincodehash = 0
    nOpCount = [0]
    
    ### -->
    def _make_state(last_op):
        return ScriptExecutionState(
            stack = stack,
            altstack = altstack,
            vfExec = vfExec,
            pbegincodehash = pbegincodehash,
            nOpCount = nOpCount,
            
            scriptIn = scriptIn,
            txTo = txTo.serialize() if txTo is not None else txTo,
            inIdx = inIdx,
            flags = flags,
            
            last_op = last_op,
            **state_kwargs
        )
    
    yield _make_state(None)

    ### <--
    
    for op_idx, (sop, sop_data, sop_pc) in enumerate(scriptIn.raw_iter()):
        fExec = _CheckExec(vfExec)

        def err_raiser(cls, *args):
            """Helper function for raising EvalScriptError exceptions

            cls   - subclass you want to raise

            *args - arguments

            Fills in the state of execution for you.
            """
            raise cls(*args,
                    sop=sop,
                    sop_data=sop_data,
                    sop_pc=sop_pc,
                    stack=stack, scriptIn=scriptIn, txTo=txTo, inIdx=inIdx, flags=flags,
                    altstack=altstack, vfExec=vfExec, pbegincodehash=pbegincodehash, nOpCount=nOpCount[0])


        if sop in DISABLED_OPCODES:
            err_raiser(EvalScriptError, 'opcode %s is disabled' % OPCODE_NAMES[sop])

        if sop > OP_16:
            nOpCount[0] += 1
            if nOpCount[0] > MAX_SCRIPT_OPCODES:
                err_raiser(MaxOpCountError)

        def check_args(n):
            if len(stack) < n:
                err_raiser(MissingOpArgumentsError, sop, stack, n)


        if sop <= OP_PUSHDATA4:
            if len(sop_data) > MAX_SCRIPT_ELEMENT_SIZE:
                err_raiser(EvalScriptError,
                           'PUSHDATA of length %d; maximum allowed is %d' %
                                (len(sop_data), MAX_SCRIPT_ELEMENT_SIZE))

            elif fExec:
                stack.append(sop_data)

                ### -->
                yield _make_state((sop, sop_data, sop_pc, op_idx))
                ### <--
                
                continue

        elif fExec or (OP_IF <= sop <= OP_ENDIF):

            if sop == OP_1NEGATE or ((sop >= OP_1) and (sop <= OP_16)):
                v = sop - (OP_1 - 1)
                stack.append(bitcoin.core._bignum.bn2vch(v))

            elif sop in _ISA_BINOP:
                _BinOp(sop, stack, err_raiser)

            elif sop in _ISA_UNOP:
                _UnaryOp(sop, stack, err_raiser)

            elif sop == OP_2DROP:
                check_args(2)
                stack.pop()
                stack.pop()

            elif sop == OP_2DUP:
                check_args(2)
                v1 = stack[-2]
                v2 = stack[-1]
                stack.append(v1)
                stack.append(v2)

            elif sop == OP_2OVER:
                check_args(4)
                v1 = stack[-4]
                v2 = stack[-3]
                stack.append(v1)
                stack.append(v2)

            elif sop == OP_2ROT:
                check_args(6)
                v1 = stack[-6]
                v2 = stack[-5]
                del stack[-6]
                del stack[-5]
                stack.append(v1)
                stack.append(v2)

            elif sop == OP_2SWAP:
                check_args(4)
                tmp = stack[-4]
                stack[-4] = stack[-2]
                stack[-2] = tmp

                tmp = stack[-3]
                stack[-3] = stack[-1]
                stack[-1] = tmp

            elif sop == OP_3DUP:
                check_args(3)
                v1 = stack[-3]
                v2 = stack[-2]
                v3 = stack[-1]
                stack.append(v1)
                stack.append(v2)
                stack.append(v3)

            elif sop == OP_CHECKMULTISIG or sop == OP_CHECKMULTISIGVERIFY:
                tmpScript = CScript(scriptIn[pbegincodehash:])
                _CheckMultiSig(sop, tmpScript, stack, txTo, inIdx, flags, err_raiser, nOpCount)

            elif sop == OP_CHECKSIG or sop == OP_CHECKSIGVERIFY:
                check_args(2)
                vchPubKey = stack[-1]
                vchSig = stack[-2]
                tmpScript = CScript(scriptIn[pbegincodehash:])

                # Drop the signature, since there's no way for a signature to sign itself
                #
                # Of course, this can only come up in very contrived cases now that
                # scriptSig and scriptPubKey are processed separately.
                tmpScript = FindAndDelete(tmpScript, CScript([vchSig]))

                ok = _CheckSig(vchSig, vchPubKey, tmpScript, txTo, inIdx,
                               err_raiser)
                if not ok and sop == OP_CHECKSIGVERIFY:
                    err_raiser(VerifyOpFailedError, sop)

                else:
                    stack.pop()
                    stack.pop()

                    if ok:
                        if sop != OP_CHECKSIGVERIFY:
                            stack.append(b"\x01")
                    else:
                        # FIXME: this is incorrect, but not caught by existing
                        # test cases
                        stack.append(b"\x00")

            elif sop == OP_CODESEPARATOR:
                pbegincodehash = sop_pc

            elif sop == OP_DEPTH:
                bn = len(stack)
                stack.append(bitcoin.core._bignum.bn2vch(bn))

            elif sop == OP_DROP:
                check_args(1)
                stack.pop()

            elif sop == OP_DUP:
                check_args(1)
                v = stack[-1]
                stack.append(v)

            elif sop == OP_ELSE:
                if len(vfExec) == 0:
                    err_raiser(EvalScriptError, 'ELSE found without prior IF')
                vfExec[-1] = not vfExec[-1]

            elif sop == OP_ENDIF:
                if len(vfExec) == 0:
                    err_raiser(EvalScriptError, 'ENDIF found without prior IF')
                vfExec.pop()

            elif sop == OP_EQUAL:
                check_args(2)
                v1 = stack.pop()
                v2 = stack.pop()

                if v1 == v2:
                    stack.append(b"\x01")
                else:
                    stack.append(b"")

            elif sop == OP_EQUALVERIFY:
                check_args(2)
                v1 = stack[-1]
                v2 = stack[-2]

                if v1 == v2:
                    stack.pop()
                    stack.pop()
                else:
                    err_raiser(VerifyOpFailedError, sop)

            elif sop == OP_FROMALTSTACK:
                if len(altstack) < 1:
                    err_raiser(MissingOpArgumentsError, sop, altstack, 1)
                v = altstack.pop()
                stack.append(v)

            elif sop == OP_HASH160:
                check_args(1)
                stack.append(bitcoin.core.serialize.Hash160(stack.pop()))

            elif sop == OP_HASH256:
                check_args(1)
                stack.append(bitcoin.core.serialize.Hash(stack.pop()))

            elif sop == OP_IF or sop == OP_NOTIF:
                val = False

                if fExec:
                    check_args(1)
                    vch = stack.pop()
                    val = _CastToBool(vch)
                    if sop == OP_NOTIF:
                        val = not val

                vfExec.append(val)


            elif sop == OP_IFDUP:
                check_args(1)
                vch = stack[-1]
                if _CastToBool(vch):
                    stack.append(vch)

            elif sop == OP_NIP:
                check_args(2)
                del stack[-2]

            elif sop == OP_NOP:
                pass

            elif sop >= OP_NOP1 and sop <= OP_NOP10:
                if SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS in flags:
                    err_raiser(EvalScriptError, "%s reserved for soft-fork upgrades" % OPCODE_NAMES[sop])
                else:
                    pass

            elif sop == OP_OVER:
                check_args(2)
                vch = stack[-2]
                stack.append(vch)

            elif sop == OP_PICK or sop == OP_ROLL:
                check_args(2)
                n = _CastToBigNum(stack.pop(), err_raiser)
                if n < 0 or n >= len(stack):
                    err_raiser(EvalScriptError, "Argument for %s out of bounds" % OPCODE_NAMES[sop])
                vch = stack[-n-1]
                if sop == OP_ROLL:
                    del stack[-n-1]
                stack.append(vch)

            elif sop == OP_RETURN:
                err_raiser(EvalScriptError, "OP_RETURN called")

            elif sop == OP_RIPEMD160:
                check_args(1)

                h = hashlib.new('ripemd160')
                h.update(stack.pop())
                stack.append(h.digest())

            elif sop == OP_ROT:
                check_args(3)
                tmp = stack[-3]
                stack[-3] = stack[-2]
                stack[-2] = tmp

                tmp = stack[-2]
                stack[-2] = stack[-1]
                stack[-1] = tmp

            elif sop == OP_SIZE:
                check_args(1)
                bn = len(stack[-1])
                stack.append(bitcoin.core._bignum.bn2vch(bn))

            elif sop == OP_SHA1:
                check_args(1)
                stack.append(hashlib.sha1(stack.pop()).digest())

            elif sop == OP_SHA256:
                check_args(1)
                stack.append(hashlib.sha256(stack.pop()).digest())

            elif sop == OP_SWAP:
                check_args(2)
                tmp = stack[-2]
                stack[-2] = stack[-1]
                stack[-1] = tmp

            elif sop == OP_TOALTSTACK:
                check_args(1)
                v = stack.pop()
                altstack.append(v)

            elif sop == OP_TUCK:
                check_args(2)
                vch = stack[-1]
                stack.insert(len(stack) - 2, vch)

            elif sop == OP_VERIFY:
                check_args(1)
                v = _CastToBool(stack[-1])
                if v:
                    stack.pop()
                else:
                    raise err_raiser(VerifyOpFailedError, sop)

            elif sop == OP_WITHIN:
                check_args(3)
                bn3 = _CastToBigNum(stack[-1], err_raiser)
                bn2 = _CastToBigNum(stack[-2], err_raiser)
                bn1 = _CastToBigNum(stack[-3], err_raiser)
                stack.pop()
                stack.pop()
                stack.pop()
                v = (bn2 <= bn1) and (bn1 < bn3)
                if v:
                    stack.append(b"\x01")
                else:
                    # FIXME: this is incorrect, but not caught by existing
                    # test cases
                    stack.append(b"\x00")

            else:
                err_raiser(EvalScriptError, 'unsupported opcode 0x%x' % sop)

            ### -->
            yield _make_state((sop, sop_data, sop_pc, op_idx))
            ### <--


        # size limits
        if len(stack) + len(altstack) > MAX_STACK_ITEMS:
            err_raiser(EvalScriptError, 'max stack items limit reached')

    # Unterminated IF/NOTIF/ELSE block
    if len(vfExec):
        raise EvalScriptError('Unterminated IF/ELSE block',
                              stack=stack,
                              scriptIn=scriptIn,
                              txTo=txTo,
                              inIdx=inIdx,
                              flags=flags)

def _EvalScriptSteps(stack, scriptIn, txTo, inIdx, flags=(), raise_error = False, **state_kwargs):
    """
    A wrapper around _EvalScriptGenerator, which handles errors by representing them as
    a error-ScriptExecutionState.
    """

    if stack is None:
        stack = []
    prev_state = None
    try:
        for state in _EvalScriptGenerator(stack, scriptIn, txTo, inIdx, flags=flags, **state_kwargs):
            prev_state = state
            yield state
    except CScriptInvalidError as err:
        err2 = EvalScriptError(repr(err),
                              stack=stack,
                              scriptIn=scriptIn,
                              txTo=txTo,
                              inIdx=inIdx,
                              flags=flags)
        if raise_error:
            raise err2 from err
        else:
            if prev_state is not None:
                yield ScriptExecutionState.from_another_state(prev_state, error = err2)
            else:
                yield ScriptExecutionState(error = err2)

def _VerifyScriptGenerator(scriptSig, scriptPubKey, txTo, inIdx, flags=()):
    """Verify a scriptSig satisfies a scriptPubKey

    scriptSig    - Signature

    scriptPubKey - PubKey

    txTo         - Spending transaction

    inIdx        - Index of the transaction input containing scriptSig

    Raises a ValidationError subclass if the validation fails.

    :note: This is copy-pasted-modified version of VerifyScript() function in
        module bitcoin.core.scripteval.  Ultimately, should refactor the function
        and submit a pull request so copy-pasting isn't necessary.

    """
    stack = []
    yield from _EvalScriptSteps(stack, scriptSig, txTo, inIdx, flags=flags, raise_error = True,
                                scriptRole = 'Input Script')
    if SCRIPT_VERIFY_P2SH in flags:
        stackCopy = list(stack)
    yield from _EvalScriptSteps(stack, scriptPubKey, txTo, inIdx, flags=flags, raise_error = True,
                                scriptRole = 'Output Script')
    if len(stack) == 0:
        raise VerifyScriptError("scriptPubKey left an empty stack")
    if not _CastToBool(stack[-1]):
        raise VerifyScriptError("scriptPubKey returned false")

    # Additional validation for spend-to-script-hash transactions
    if SCRIPT_VERIFY_P2SH in flags and scriptPubKey.is_p2sh():
        if not scriptSig.is_push_only():
            raise VerifyScriptError("P2SH scriptSig not is_push_only()")

        # restore stack
        stack = stackCopy

        # stack cannot be empty here, because if it was the
        # P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        # an empty stack and the _EvalScriptSteps above would return false.
        assert len(stack)

        pubKey2 = CScript(stack.pop())

        yield from _EvalScriptSteps(stack, pubKey2, txTo, inIdx, flags=flags, raise_error = True,
                                    scriptRole = 'P2SH Redeem Script')

        if not len(stack):
            raise VerifyScriptError("P2SH inner scriptPubKey left an empty stack")

        if not _CastToBool(stack[-1]):
            raise VerifyScriptError("P2SH inner scriptPubKey returned false")

    if SCRIPT_VERIFY_CLEANSTACK in flags:
        assert SCRIPT_VERIFY_P2SH in flags

        if len(stack) != 1:
            raise VerifyScriptError("scriptPubKey left extra items on stack")

def _VerifyScriptSteps(scriptSig, scriptPubKey, txTo, inIdx, flags=()):
    """
    A wrapper around _VerifyScriptGenerator, which handles errors by representing them as
    a error-ScriptExecutionState.
    :return: a list of ScriptExecutionState's
    """
    states = []
    prev_state = None
    try:
        for state in _VerifyScriptGenerator(scriptSig, scriptPubKey, txTo, inIdx, flags=flags):
            state = copy.deepcopy(state)
            states.append(state)
            prev_state = state
    except Exception as err:
        if prev_state is not None:
            state = ScriptExecutionState.from_another_state(prev_state, error = err)
        else:
            state = ScriptExecutionState(error = err)
        states.append(state)
    # add "success" state at the end:
    if states and not any( s.is_error for s in states ):
        states.append(ScriptExecutionState.from_another_state(states[-1], is_final = True))
    return states

################################################################################
# integration with bitcoinscript

def get_inout_script_execution_steps(inscript, outscript, rawtx = None, input_idx = None, flags = ()):
    """
    Run the script, recording all states of the execution.
    :return: a list of ScriptExecutionState's
    """
    inscript2 = CScript(inscript.raw)
    outscript2 = CScript(outscript.raw)
    if rawtx is not None:
        tx = CTransaction.deserialize(rawtx)
    else:
        tx = None
    return [
        state for state in
        _VerifyScriptSteps(inscript2, outscript2, tx, input_idx, flags = flags)
    ]

################################################################################

