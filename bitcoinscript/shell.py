"""
Definition (and activation) of BitcoinScript ipython-magics, for
interactively composing bitcoin-scripts in a ipython session.

BitcoinScript magics can be activated by invoking ipython like::

    ipython -i bitcoinscript.shell
    
or by importing this module in the ipython session::

    import bitcoinscript.shell

"""

from IPython.core import magic as _MAGIC
from IPython.core.magic import line_magic as _line_magic

from bitcoin.core import _bignum
from bitcoin.core import scripteval as _scripteval

from bitcoinscript import opcode as _OPCODE
import bitcoinscript as _BS
from bitcoinscript.format import parse_formatted_script as _parse_formatted_script
from bitcoinscript.verify import verify_script as _verify_script
from bitcoinscript.debugger import run_in_debugger as _run_in_debugger
from bitcoinscript.samples import get_sample_exec_args as _get_sample_exec_args


###############################################################################

_SCRIPT_VERIFY_FLAG_TO_NAME = { v:k for k,v in _scripteval.SCRIPT_VERIFY_FLAGS_BY_NAME.items() }

###############################################################################

class BitcoinScriptMagics(_MAGIC.Magics):

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._reset()
        self._echoing = True

    def _reset(self):
        self._scripts = { 'out': b'', 'in': b'' }
        self._active_script = 'out'
        self._ctx = { 'rawtx': None, 'input_idx': None }
        self._flags = ()

    
    ###############################################################################
    # properties and basic operations
    
    @property
    def outscript_blob(self):
        return self._scripts['out']
    
    @property
    def inscript_blob(self):
        return self._scripts['in']
    
    @property
    def active_blob(self):
        return self._scripts[self._active_script]

    @property
    def outscript(self):
        return _BS.outscript_from_raw(self.outscript_blob)
    
    @property
    def inscript(self):
        return _BS.inscript_from_raw(self.inscript_blob, self.outscript)
    
    @property
    def active_script(self):
        if self._active_script == 'in':
            return self.inscript
        else:
            return self.outscript

    ###############################################################################
    # MAGICS -- display / echo
    
    @_line_magic
    def Sechoon(self, line):
        """ Turn script-echoing ON """
        self._echoing = True
        print('ECHO is now ON')

    @_line_magic
    def Sechooff(self, line):
        """ Turn script-echoing OFF """
        self._echoing = False
        print('ECHO is now OFF')

    @_line_magic
    def Sshow(self, line):
        """ Display current scripts, along with flags and context """
        self.print_scripts(force = True)
    
    def print_scripts(self, force = False):
        if not self._echoing and not force:
            return
        self._print_script(self.inscript, role = 'in')
        self._print_script(self.outscript, role = 'out')
        if self._flags:
            print(' Flags:  %s' % ' '.join(_SCRIPT_VERIFY_FLAG_TO_NAME[f] for f in self._flags))
        for k, v in sorted(self._ctx.items()):
            if v is None:
                continue
            if isinstance(v, bytes):
                v = v.hex()
            print(' Context: %s = %s' % (k, v))

    def _print_script(self, script, role):
        if script is None:
            return
        active_marker = '*' if role == self._active_script else ' '
        role_str = '%-9s ' % (role.capitalize() + 'Script')
        script_str = str(script)
        print('%s%s: [%s]' % (active_marker, role_str, script_str))
    
    ###############################################################################
    # MAGICS -- modify script, control

    @_line_magic
    def Sinscript(self, line):
        """ Set InScript as the active script """
        self._active_script = 'in'
        print('INSCRIPT is now active')

    @_line_magic
    def Soutscript(self, line):
        """ Set OutScript as the active script """
        self._active_script = 'out'
        print('OUTSCRIPT is now active')

    @_line_magic
    def Sclear(self, line):
        """ Clear the active script """
        self._scripts[self._active_script] = b''
        self.print_scripts()

    @_line_magic
    def Sreset(self, line):
        """ Clear all script-related data. Affects scripts, flags, and context. """
        self._reset()
        self.print_scripts()

    @_line_magic
    def Ssetscript(self, line):
        """ Set script from human readable string (overwriting active script) """
        blob = _parse_formatted_script(line)
        self._scripts[self._active_script] = blob
        self.print_scripts()

    @_line_magic
    def Sloadsample(self, line):
        """ Set scripts from a sample """
        script_types = line.split()
        (inscript, outscript), ctx = _get_sample_exec_args(*script_types)
        self._scripts['in'] = inscript.raw
        self._scripts['out'] = outscript.raw
        self._ctx['rawtx'] = ctx['rawtx']
        self._ctx['input_idx'] = ctx['input_idx']
        self._flags = ctx['flags']
        self.print_scripts()

    @_line_magic
    def Spushdata(self, line):
        """ Push data using an appropriate OP_PUSHDATA op (OP_PUSHDATA/1/2/4) """
        data = self._arg_to_data(line)
        if data is None:
            return
        if isinstance(data, int):
            # int -> bytes
            data = _bignum.bn2vch(data)
        if not isinstance(data, bytes):
            raise TypeError('Cannot push data of type %s' % type(data).__name__)
        self._append(_OPCODE.encode_op_pushdata(data))
        self.print_scripts()

    def _append(self, b):
        self._scripts[self._active_script] += b

    def _append_opcode(self, opcode):
        self._append(opcode.to_bytes(1, byteorder = 'little'))

    def _arg_to_data(self, line):
        line = line.strip()
        if not line:
            return None
        if line.startswith('0x'):
            # interpret as hex data
            v = bytes.fromhex(line[2:])
        else:
            v = eval(line)
        return v

    ###############################################################################
    # MAGICS -- flags and context
    
    @_line_magic
    def Sflagset(self, line):
        """ Enable a script-execution flag. E.g., SCRIPT_VERIFY_CLEANSTACK """
        flagname, flag = self._get_flag(line)
        if flag is None:
            return
        if flag not in self._flags:
            self._flags += (flag,)
        print('Flag enabled: %s' % flagname)
        self.print_scripts()
    
    @_line_magic
    def Sflagunset(self, line):
        """ Disable a script-execution flag. E.g., SCRIPT_VERIFY_CLEANSTACK """
        flagname, flag = self._get_flag(line)
        if flag is None:
            return
        self._flags = tuple([ f for f in self._flags if f != flag ])
        print('Flag disabled: %s' % flagname)
        self.print_scripts()
    
    def _get_flag(self, line):
        flagname = line.strip()
        if not flagname:
            return None, None
        if not flagname.startswith('SCRIPT_VERIFY_'):
            flagname = 'SCRIPT_VERIFY_' + flagname
        flag = getattr(_scripteval, flagname, None)
        if flag is None:
            print('No such flag: %s' % flagname)
        return flagname, flag

    @_line_magic
    def Stxset(self, line):
        """ Set the raw Tx to use for signature-related OPs """
        data = self._arg_to_data(line)
        if not isinstance(data, bytes):
            raise TypeError('Cannot set tx of type %s' % type(data).__name__)
        self._ctx['rawtx'] = data
        self.print_scripts()

    @_line_magic
    def Stxunset(self, line):
        """ Unset the raw Tx """
        self._ctx.pop('rawtx', None)
        self.print_scripts()
    
    @_line_magic
    def Siidxset(self, line):
        """ Set input_idx to use for signature-related OPs """
        data = self._arg_to_data(line)
        if not isinstance(data, int):
            raise TypeError('Cannot set input_idx of type %s' % type(data).__name__)
        self._ctx['input_idx'] = data
        self.print_scripts()

    @_line_magic
    def Siidxunset(self, line):
        """ Unset input_idx """
        self._ctx.pop('input_idx', None)
        self.print_scripts()
    
    ###############################################################################
    # MAGICS -- verify and debug
    
    @_line_magic
    def Sdebug(self, line):
        """ Start a debugger session with current scripts """
        a, kw = self._get_exec_args()
        _run_in_debugger(*a, **kw)
    
    @_line_magic
    def Sverify(self, line):
        """ Run the scripts, and print the result (sucess or error) """
        a, kw = self._get_exec_args()
        try:
            _verify_script(*a, **kw)
        except Exception as e:
            print('*ERROR* [%s] %s' % ( type(e).__name__, e ))
        else:
            print('SUCCESS')
        
    def _get_exec_args(self):
        flags = self._flags
        if self.outscript.type == _BS.ScriptType.P2SH and _scripteval.SCRIPT_VERIFY_P2SH not in flags:
            flags += (_scripteval.SCRIPT_VERIFY_P2SH,)
        return (self.inscript, self.outscript), dict(flags = flags, **self._ctx)

    ###############################################################################
    # MAGICS -- other
    
    @_line_magic
    def Sp2shify(self, line):
        """ Transform scripts to a P2SH form """
        p2sh_inscript = _BS.InScriptP2SH.from_redeem_scripts(self.outscript, self.inscript)
        p2sh_outscript = _BS.OutScriptP2SH.from_script(self.outscript)
        self._scripts['in'] = p2sh_inscript.raw
        self._scripts['out'] = p2sh_outscript.raw
        self.print_scripts()

    @_line_magic
    def Shelp(self, line):
        """ List all BitcoinScript shell magics """
        all_magics = self.magics['line']
        op_magics = [ m for m in all_magics if m.startswith('OP_') ]
        other_magics = [ m for m in all_magics if m not in op_magics ]
        print()
        print('Sxxx MAGICS:')
        for magicname in sorted(other_magics):
            magicfunc = all_magics[magicname]
            print(' %-24s %s' % (magicname, magicfunc.__doc__))
        print()
        print('OP_xxx MAGICS:')
        for magicname in sorted(op_magics):
            magicfunc = all_magics[magicname]
            print(' %-24s %s' % (magicname, magicfunc.__doc__))
        print()
        
    
###############################################################################
# Automatically add all OP_xxx consts as magics:

def _op_push_func(opname):
    def op_push(self, line):
        self._append_opcode(getattr(_OPCODE, opname))
        self.print_scripts()
    op_push.__name__ = opname
    op_push.__doc__ = "Push %s to active script" % opname
    return op_push

for _opname in dir(_OPCODE):
    if _opname.startswith('OP_'):
        setattr(BitcoinScriptMagics, _opname, _line_magic(_op_push_func(_opname)))


###############################################################################
# Register magics with IPython:

if 0: get_ipython = None  # Avoid pyflakes warnings
try:
    get_ipython
except NameError:
    # Not running in an ipython session. Do nothing.
    pass
else:
    BitcoinScriptMagics = _MAGIC.magics_class(BitcoinScriptMagics)
    ip = get_ipython()
    ip.register_magics(BitcoinScriptMagics)
    print('*** BitcoinScript shell magics are Enabled. Enter `%Shelp` for more details. ***')

###############################################################################
