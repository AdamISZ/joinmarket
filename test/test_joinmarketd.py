#! /usr/bin/env python
from __future__ import absolute_import
'''Tests of joinmarket bots end-to-end (including IRC and bitcoin) '''

import subprocess
import signal
from commontest import local_command, make_wallets
import os
import shutil
import pytest
import time
from joinmarket import (load_program_config, IRCMessageChannel)
from joinmarket import startup_joinmarketd
from joinmarket import jm_single, get_irc_mchannels
from joinmarket import MessageChannelCollection
from joinmarket import get_log, choose_sweep_orders, choose_orders, \
    pick_order, cheapest_order_choose, weighted_order_choose, debug_dump_object


#for running bots as subprocesses
python_cmd = 'python2'
yg_cmd = 'yield-generator-basic.py'
#yg_cmd = 'yg-pe.py'
def test_joinmarketdaemon(setup_joinmarketd):
    #Start some ygs so we have someone to talk to
    makercount = 4
    mean_amt = 1
    wallet_structures = [[2,1,0,0,0]]*makercount
    wallets = make_wallets(makercount,
                           wallet_structures=wallet_structures,
                           mean_amt=mean_amt)

    yigen_procs = []
    for i in range(makercount):
        ygp = local_command([python_cmd, yg_cmd,\
                             str(wallets[i]['seed'])], bg=True)
        time.sleep(2)  #give it a chance
        yigen_procs.append(ygp)

    def finalizer(y):
        if any(y):
            for ygp in y:
                #NB *GENTLE* shutdown is essential for
                #test coverage reporting!
                ygp.send_signal(signal.SIGINT)
                ygp.wait()

    #A significant delay is needed to wait for the yield generators to sync
    time.sleep(5)
    
    #Initialization of daemon:
    port = 12345
    mcs = [IRCMessageChannel(c, realname='btcint=' + jm_single().config.get(
                                     "BLOCKCHAIN", "blockchain_source")
                             ) for c in get_irc_mchannels()]
    mcc = MessageChannelCollection(mcs)

    startup_joinmarketd(mcc, port, finalizer, yigen_procs)

@pytest.fixture(scope="module")
def setup_joinmarketd():
    load_program_config()
