#! /usr/bin/env python3
"""
The easiest way to try out the debugger: starting it with a sample script.
"""

from argparse import ArgumentParser
from bitcoinscript.debugger.utils import debug_sample

def main():

    parser = ArgumentParser(description = 'Run the bitcoinscript debugger on a sample script')
    parser.add_argument('script_type', nargs = '+',
                        help = 'sample script type, e.g. "P2PKH", or "P2SH P2MULTISIG"')
    options = parser.parse_args()

    debug_sample(*options.script_type)

if __name__ == '__main__':
    main()
