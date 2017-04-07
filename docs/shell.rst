=====================================
The BitcoinScript Interactive Shell
=====================================

The easiest way to play around with the bitcoin scripting language is
using an interactive shell.

**BitcoinScript integrates with IPython**, by adding a bunch of IPython-magics.  This way, you can perform
bitcoin-script operations inside a IPython session, while enjoying all the nice features of IPython.

:note: The examples here use the `automagic` IPython setting, so they don't require a `%`-prefix
    before each magic call.  If you don't use `automagic`, you'd need to add the `%`-prefix as required.

Starting the Interactive Shell
=================================

Start an IPython session, and activate the BitcoinScript magics by importing `bitcoinscript.shell`::

    % ipython3
    > import bitcoinscript.shell
    *** BitcoinScript shell magics are Enabled. Enter `%Shelp` for more details. ***
    > 

Alternatively, you can load the BitcoinScript magics explicitly when starting ipython::

    % ipython3 -i bitcoinscript/shell.py
    *** BitcoinScript shell magics are Enabled. Enter `%Shelp` for more details. ***
    > 

To find the path to pass to ipython's `-i` option, run::

    python3 -c 'import bitcoinscript.shell; print(bitcoinscript.shell.__file__)'


Interactive Shell Example
=================================

A simple example, for the challange of finding the hash-preimage of `c0b057f584795eff8b06d5e420e71d747587d20de836f501921fd1b5741f1283`::

    % ipython3

    ### Activate BitcoinScript magics:
    
    > import bitcoinscript.shell
    *** BitcoinScript shell magics are Enabled. Enter `%Shelp` for more details. ***
    
    ### Compose the output script: given an input, hash it, push the expected hash, and compare.
    ### The scripts are printed after each addition. We could use `Sechooff` to supress echoing.
    
    > OP_HASH256
     InScript  : []
    *OutScript : [OP_HASH256]
    
    > Spushdata 0xc0b057f584795eff8b06d5e420e71d747587d20de836f501921fd1b5741f1283
     InScript  : []
    *OutScript : [OP_HASH256 c0b057f5...741f1283]
    
    > OP_EQUAL
     InScript  : []
    *OutScript : [OP_HASH256 c0b057f5...741f1283 OP_EQUAL]
    
    ### We get an error if we run the script without providing an input.
    
    > Sverify
    *ERROR* [MissingOpArgumentsError] EvalScript: missing arguments for OP_HASH256; need 1 items, but only 0 on stack
    
    ### Add an input. Maybe the answer is 2?
    
    > Sinscript
    INSCRIPT is now active
    
    > OP_2
    *InScript  : [2]
     OutScript : [OP_HASH256 c0b057f5...741f1283 OP_EQUAL]
    
    > Sverify
    *ERROR* [VerifyScriptError] scriptPubKey returned false
    
    ### Try another input. Maybe the answer is 0xff?
    
    > Sclear
    *InScript  : []
     OutScript : [OP_HASH256 c0b057f5...741f1283 OP_EQUAL]
    
    > Spushdata 0xff
    *InScript  : [ff]
     OutScript : [OP_HASH256 c0b057f5...741f1283 OP_EQUAL]
    
    > Sverify
    SUCCESS
    
    ### YES!!
    
