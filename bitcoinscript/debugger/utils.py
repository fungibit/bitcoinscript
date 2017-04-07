"""
Debugger-related utility functions.
"""

from ..samples import get_sample_exec_args
from .dbg import run_in_debugger

################################################################################

def debug_sample(script_type, p2sh_script_subtype = None, flags = ()):
    """
    Run the debugger on scripts from the samples.
    """
    # read sample scripts
    a, kw = get_sample_exec_args(script_type, p2sh_script_subtype, flags = flags)
    # run the scripts and start the debugger
    return run_in_debugger(*a, **kw)

################################################################################
