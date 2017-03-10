"""
Samples of real scripts from the blockchains.

Part of this file is GENERATED USING bin/gen_samples.py! (by running it and copy/pasting the output).
"""

from .script import ScriptType, outscript_from_raw, inscript_from_raw

################################################################################
################################################################################
# *** BEGINNING OF GENERATED CODE *** --->
################################################################################
################################################################################

SCRIPT_SAMPLES = \
{'OTHER': {'iidx': 42,
           'inscript': '084f505f455155414c',
           'oidx': 0,
           'outscript': 'a8209c0f28fc262f58e9ad1f021ab707662cad96c754ecf3ad43be5c26e49c08123387',
           'txid': 'a0da2be1d90cd615e0791ef8f06e3a1536cc917f2f78d37c44cd0015f4575a1d'},
 'P2MULTISIG': {'iidx': 1,
                'inscript': '00483045022100cde0a92d914447f0468c62c7d1a22e7927893a0ddf33f36225f7a52550af930402201b660eec9b7ea442ad6aeb77e8cb6e7aa52b0e3c7b77888de544d60c6914746701',
                'oidx': 0,
                'outscript': '512103e3d0df29ddcc44bd99a405568a5c2e62845aab2394815e3a1a819b6c20881a232102c08786d63f78bd0a6777ffe9c978cf5899756cfc32bfad09a89e211aeb92624252ae',
                'txid': 'aba1fd2fd2fbb2286f951a745c3235a0e5d8b6ac58da96accc9f14f44bb7e375'},
 'P2PK': {'iidx': 0,
          'inscript': '47304402202de03f3ccd34d68f546b5a755b63b1776ead080c5173a3c7281e5e62e7ecbd75022030f2ccd0abb583039d2ef0d3f9dabcfedfac7354a0e873ed0922b62bd84da16401',
          'oidx': 1,
          'outscript': '210283d81eda35fe96309eaf3f1ea04f45112b52fd9384161a9fdbe6f1f5b32307e1ac',
          'txid': 'fb7a3486137abd66d91460d4c94eeca47048689967345bd4ab86819ad26662ee'},
 'P2PKH': {'iidx': 0,
           'inscript': '47304402202705767c9be071b580f8286a058410808cdd9662a359b463f7c1dd42f7c60c2d02202f08d8f6c0d4dd9080d2b6ed4dc2098087e737ec6061b01e733eb85e27bbef50012102f3348097a2d088c43727f554bad3e4135f86c60a6b2b74b13aef87f4af215946',
           'oidx': 0,
           'outscript': '76a914c06ba08f6d85ee0c4a26d8fe554b879cd9d1319b88ac',
           'txid': '55cb9e70b341823c4fc6090f61237747026981ab8e56b6c8a046045ddf62a023'},
 'PROVABLY_UNSPENDABLE': {'iidx': None,
                          'inscript': None,
                          'oidx': 1,
                          'outscript': '6a084f41010001892700',
                          'txid': 'f1ffb97e051d812265d57671700c33bcc666c4c16b1b2cc747e3b1360641a1ce'}}

P2SH_SCRIPT_SAMPLES = \
{'OTHER': {'iidx': 0,
           'inscript': '0017a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87',
           'oidx': 0,
           'outscript': 'a91492a04bc86e23f169691bd6926d11853cc61e185287',
           'rscript': 'a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87',
           'txid': '66f8cc964f57daced07db4e180bd1a3423925c4f30079df0fb20dd368bc67aac'},
 'P2MULTISIG': {'iidx': 0,
                'inscript': '00473044022049ab986462e76fccc3f2fc96258b299651712fe809b9605296254554ddbee80b0220032be54c97dffbc4748f677d4f4425a15828707f82b8cbefe5ed20dc4157d202014630430220546ab316f975498bf53992ce61503964435b415e8a18021760a94c5b256dfef0021f62687bc46c51f78f72fe8b2d3d906b1f6ec775520b89e41e7b09a9025af72d01475221022ef2a960d47b3da72ef75044caf7860247fe2a76f320b391d9954ae901ad6ee721027ee29e8879196715a921c4e931502c99864e1f8135ff472cc7c9868fb511839252ae',
                'oidx': 1,
                'outscript': 'a9147c3bcd788a514b8ff108d646da5bad291764a22087',
                'rscript': '5221022ef2a960d47b3da72ef75044caf7860247fe2a76f320b391d9954ae901ad6ee721027ee29e8879196715a921c4e931502c99864e1f8135ff472cc7c9868fb511839252ae',
                'txid': 'b29370841b9d677411010b1ef4fb1f628b6e00d5ef8ad88ce196270a7757d075'},
 'P2PK': {'iidx': 1,
          'inscript': '473044022071a064e2ab0c24f177798eebfaf71fc3cafb0d50de57bf924dbd8ea7fa9e473302205f8f5fe978d5ca5d70db6068989ab9810481739c8b05dfe9fcd06d20a61da68c01232103abac1b5d57c1783dcf659c4e5943b9f7ef6eadcaa11032b34d45046fdd5db48bac',
          'oidx': 1,
          'outscript': 'a914e2e25979f31eb94c8063be28796c73e129d6576587',
          'rscript': '2103abac1b5d57c1783dcf659c4e5943b9f7ef6eadcaa11032b34d45046fdd5db48bac',
          'txid': '022276bb7bd0a47b153a1380f3024fdd59559e738c22bc16d997f9265d0cff6a'},
 'P2PKH': {'iidx': 0,
           'inscript': '4830450220689224a044a3aebe141f24c39a7209b51f364ebc349e45cd4e48155d80f168e6022100d101f14336713155938bc7c251736fe5b4c0eb474d5d0d8d5647f97babd0d644012102585bcac7d353fd8165677b233aaea21321e41e4bdfc5d8ec3035ef9077bd7bb31976a9149231207a857b20989d5a3419bb7162bc8d6c4c9188ac',
           'oidx': 1,
           'outscript': 'a9148425e38b7247a5df6db35a072b6aa12a19f895e787',
           'rscript': '76a9149231207a857b20989d5a3419bb7162bc8d6c4c9188ac',
           'txid': '15709efed1151591d3d29a9e987bfa30a54a05c39e00c17815229ae719dd9861'}}

ADDRESS_SAMPLES = \
[{'address': '1CNvsbUPpWMNHUkEaAnVghMAma6vSYtaHA',
  'hash160': '7ccf16d3763a134d86ef5504ffa723d8dbf09ba1',
  'is_p2sh': False,
  'origin': 'P2PK',
  'pubkey': '0283d81eda35fe96309eaf3f1ea04f45112b52fd9384161a9fdbe6f1f5b32307e1'},
 {'address': '1JYRfuBFd5p6efVV5U5HdZJwSDaAtnVwvG',
  'hash160': 'c06ba08f6d85ee0c4a26d8fe554b879cd9d1319b',
  'is_p2sh': False,
  'origin': 'P2PKH',
  'pubkey': None},
 {'address': '3D1uMVMRYsHCQo8RR42RK3s68z9xgc7a4K',
  'hash160': '7c3bcd788a514b8ff108d646da5bad291764a220',
  'is_p2sh': True,
  'origin': 'P2SH/P2MULTISIG',
  'pubkey': None}]

################################################################################
################################################################################
# <--- *** END OF GENERATED CODE ***
################################################################################
################################################################################


def get_sample(script_type, p2sh_script_subtype = None):
    """
    :return: a 2-tuple of (outscript, inscript)
    """
    script_type = ScriptType[script_type]
    if script_type == ScriptType.P2SH:
        if p2sh_script_subtype is None:
            p2sh_script_subtype = ScriptType.P2MULTISIG
        else:
            p2sh_script_subtype = ScriptType[p2sh_script_subtype]
        d = P2SH_SCRIPT_SAMPLES[p2sh_script_subtype.name]
    else:
        d = SCRIPT_SAMPLES[script_type.name]
    o = outscript_from_raw(bytes.fromhex(d['outscript']))
    i = inscript_from_raw(bytes.fromhex(d['inscript']), o)
    return o, i
    
################################################################################
