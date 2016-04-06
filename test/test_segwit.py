#! /usr/bin/env python
from __future__ import absolute_import
'''Test creation of segwit transactions.'''

import sys
import os
import time
import binascii
import pexpect
import random
import subprocess
import unittest
import json
from commontest import local_command, interact, make_wallets
from pprint import pformat
import bitcoin as btc
import pytest
from joinmarket import load_program_config, jm_single
from joinmarket import get_p2pk_vbyte, get_log, Wallet
from joinmarket.support import chunks, select_gradual, \
     select_greedy, select_greediest

log = get_log()

def test_segwit_valid_txs(setup_segwit):
    with open("test/tx_segwit_valid.json", "r") as f:
            json_data = f.read()
    valid_txs = json.loads(json_data)
    for j in valid_txs:
        if len(j) < 2:
            continue
        #print j
        print pformat(btc.deserialize(str(j[1])))
        #print deserialized
        #assert j[0] == btc.serialize(deserialized)

@pytest.fixture(scope="module")
def setup_segwit():
    load_program_config()

    '''
    An example of a valid segwit from the json with parsing
    
    ["Valid P2WPKH (Private key of segwit tests is 
    L5AQtV2HDm4xGsseLokK2VAT2EtYKcTm3c7HwqnJBFt9LdaQULsM)"],
    
    [[["0000000000000000000000000000000000000000000000000000000000000100", 
    0, "0x00 0x14 0x4c9c3dfac4207d5d8cb89df5722cb3d712385e3f", 1000]],
    
    "01000000
    00
    01
    ins start
    in num
    01
    in txid
    000100000000000000000000000000000000000000000000000000000000000000
    in txid out index
    00000000
    sequence
    ffffffff
    num outs
    01
    amount
    e803000000000000
    script
    1976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac
    (number of witnesses = 1, implied by txin length)
    witnesses : number 1
    item count for this witness
    02
    signature length
    48
    signature + hashcode 01
    3045022100cfb07164b36ba64c1b1e8c7720a56ad64d96f6ef332d3d37f9cb3c96477dc4450220
    0a464cd7a9cf94cd70f66ce4f4f0625ef650052c7afcfe29d7d7e01830ff91ed01
    pubkey length
    21
    pubkey
    03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
    locktime
    00000000", "P2SH,WITNESS"],
    '''
    
    '''
    P2WSH example
    01000000
    00
    01
    01
    00010000000000000000000000000000000000000000000000000000000000000000000000
    ffffffff
    01
    e803000000000000
    1976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac
    num items in witness 1
    02
    length of sig
    48
    3045022100aa5d8aa40a90f23ce2c3d11bc845ca4a12acd99cbea37de6b9f6d86edebba8cb0220
    22dedc2aa0a255f74d04c0b76ece2d7c691f9dd11a64a8ac49f62a99c3a05f9d01
    length of scriptSig
    23
    serialized script: PUSH DATA(33) PUBKEY CHECKSIG
    2103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ac
    locktime
    00000000
    
"01000000
00
01
04
0001000000000000000000000000000000000000000000000000000000000000
0200000000
ffffffff
0001000000000000000000000000000000000000000000000000000000000000
0100000000
ffffffff
0001000000000000000000000000000000000000000000000000000000000000
0000000000
ffffffff
0001000000000000000000000000000000000000000000000000000000000000
0300000000
ffffffff
05
540b0000000000000151d0070000000000000151840300000000000001513c0f00000000000001512c010000000000000151000248304502210092f4777a0f17bf5aeb8ae768dec5f2c14feabf9d1fe2c89c78dfed0f13fdb86902206da90a86042e252bcd1e80a168c719e4a1ddcc3cebea24b9812c5453c79107e9832103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71000000000000
    '''
