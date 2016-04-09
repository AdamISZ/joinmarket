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
'''
def test_segwit_valid_txs(setup_segwit):
    with open("test/tx_segwit_valid.json", "r") as f:
            json_data = f.read()
    valid_txs = json.loads(json_data)
    for j in valid_txs:
        if len(j) < 2:
            continue
        #print j
        deserialized_tx = btc.deserialize(str(j[1]))
        print pformat(deserialized_tx)
        #TODO use bcinterface to decoderawtransaction
        #and compare the json values
'''


def test_spend_p2wpkh(setup_segwit):
    #first spend to an output which is of type p2wpkh
    priv = binascii.hexlify('\x03' * 32 + '\x01')
    pub = btc.privtopub(priv)
    #receiving address is of form p2sh_p2wpkh
    addr1 = btc.pubkey_to_p2sh_p2wpkh_address(pub, magicbyte=196)
    print "got address for p2shp2wpkh: " + addr1
    txid = jm_single().bc_interface.grab_coins(addr1, 1)
    time.sleep(3)
    in_amt = 100000000
    fee = 10000
    changeamount = 50000000
    outamount = in_amt - fee - changeamount

    #second, use this new tx input 0 as input to a new transaction,
    #then sign using segwit flag
    output_addr = btc.privkey_to_address(
        binascii.hexlify('\x07' * 32 + '\x01'),
        magicbyte=get_p2pk_vbyte())
    change_addr = btc.privkey_to_address(
        binascii.hexlify('\x08' * 32 + '\x01'),
        magicbyte=get_p2pk_vbyte())
    #find the correct outpoint for what we've just received;
    #normally this job is done by "sync wallet" in blockchaininterface
    rawtx = jm_single().bc_interface.rpc("getrawtransaction", [txid, 1])
    ins = []
    print rawtx["vout"]
    for u in rawtx["vout"]:
        if u["scriptPubKey"]["addresses"][0] == addr1:
            ins.append(txid + ":" + str(u["n"]))
    assert len(ins) == 1

    outs = [{'value': outamount,
             'address': output_addr}, {'value': changeamount,
                                       'address': change_addr}]
    tx = btc.mktx(ins, outs)
    print btc.deserialize(tx)
    #signature must cover amount; script is calculated automatically for tx type
    tx2 = btc.p2sh_p2wpkh_sign(tx, 0, priv, in_amt)
    print btc.deserialize(tx2)
    txid2 = jm_single().bc_interface.pushtx(tx2)
    assert txid2
    time.sleep(3)
    received = jm_single().bc_interface.get_received_by_addr(
        [output_addr], None)['data'][0]['balance']
    assert received == outamount


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
    00010000000000000000000000000000000000000000000000000000000000000000
    000000
    ffffffff
    01
    amount
    e803000000000000
    length 25
    19
    OP_DUP OP_HASH160
    76a9
    hash length
    14
    ripemd160(sha256(pubkey))
    4c9c3dfac4207d5d8cb89df5722cb3d712385e3f
    OP_EQUALVERIFY OP_CHECKSIG
    88ac
    num items in witness 1
    02
    length of sig
    48
    3045022100aa5d8aa40a90f23ce2c3d11bc845ca4a12acd99cbea37de6b9f6d86edebba8cb0220
    22dedc2aa0a255f74d04c0b76ece2d7c691f9dd11a64a8ac49f62a99c3a05f9d01
    length of scriptSig
    23
    length of pubkey
    21
    pubkey
    03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
    CHECKSIG
    ac
    locktime
    00000000
    
"
Example with SIGHASH_SINGLE|SIGHASH_ANYONECANPAY
version
01000000
marker
00
flag
01
num in
04
in1 txid
0001000000000000000000000000000000000000000000000000000000000000
in 1 index
0200000000
in 1 sequence
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
num outs
05
out 0 amount
540b000000000000
length
01
OP_TRUE - looks like anyonecanspend
51
out 1
amount
d007000000000000
length
01
OP_TRUE
51
out 2
amount
8403000000000000
length
01
OP_TRUE
51
out 3
amount
3c0f000000000000
length
01
OP_TRUE
51
out 4
amount
2c01000000000000
length
01
OP_TRUE
51
witness starts here
first txin witness - none
00
second witness item
num items in witness
02
sig length
48
signature
304502210092f4777a0f17bf5aeb8ae768dec5f2c14feabf9d1fe2c89c78dfed0f13fdb869
02206da90a86042e252bcd1e80a168c719e4a1ddcc3cebea24b9812c5453c79107e983 - SIGHASH_SINGLE|SIGHASH_ANYONECANPAY
length pubkey
21
pubkey
03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
locktime
000000000000


"01000000
00
01
01
0001000000000000000000000000000000000000000000000000000000000000
0000000000
ffffffff
01
e803000000000000
19
76a9
14
4c9c3dfac4207d5d8cb89df5722cb3d712385e3f
88
ac
02
48
3045022100aa5d8aa40a90f23ce2c3d11bc845ca4a12acd99cbea37de6b9f6d86edebba8cb
022022dedc2aa0a255f74d04c0b76ece2d7c691f9dd11a64a8ac49f62a99c3a05f9d01
23
21
03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
ac
00000000", "P2SH,WITNESS"],


["Valid P2SH(P2WPKH)"],
[[["0000000000000000000000000000000000000000000000000000000000000100", 
0, 
**NOTE: this hash160 is of 00 14 <hash160 of pubkey>** - how P2SHP2WPKH works
"HASH160 0x14 0xfe9c7dacc9fcfbf7e3b7d5ad06aa2b28c5a7b7e3 EQUAL", 1000]],

"
01000000
00
01
01
0001000000000000000000000000000000000000000000000000000000000000
00000000
length of scriptsig
17
length of item
16
witness versoin byte
00
length of item
14
hash160 - of PUBKEY
4c9c3dfac4207d5d8cb89df5722cb3d712385e3f
sequence
ffffffff
num outs
01
amount
e803000000000000
output
1976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac
witness for input 0
num items
02
48
3045022100cfb07164b36ba64c1b1e8c7720a56ad64d96f6ef332d3d37f9cb3c96477dc445
02200a464cd7a9cf94cd70f66ce4f4f0625ef650052c7afcfe29d7d7e01830ff91ed01
len pub
21
pub
03596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71
locktime
00000000", "P2SH,WITNESS"],
'''
