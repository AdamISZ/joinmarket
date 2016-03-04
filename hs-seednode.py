#! /usr/bin/env python
from __future__ import absolute_import, print_function

'''Bundled all code to run a test of multiple ygs and one
sendpayment, all messaging done over HS. The message channel
interface is implemented in joinmarket/hsmc.py.
'''

import datetime
import os
import time
import binascii

from joinmarket.hsmc import JMHSPeer

import tempfile
import functools
import time
import json
import base64

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.web import server, resource
from twisted.python import log as tlog

import random
import txtorcon

from pprint import pformat

from twisted.internet import task

seedpeer_nick = "SEED1"
hs_port = 9876
hs_public_port = 8080

def updates(prog, tag, summary):
    print("%d%%: %s" % (prog, summary))

def setup_complete(config, proto):
    sn_peer.tor_is_ready = True
    onion_address = config.HiddenServices[0].hostname

    print("I have a hidden (web) service running at:")
    print("http://%s (port %d)" % (onion_address, hs_public_port))
    print("The temporary directory for it is at:", config.HiddenServices[0].dir)

def setup_failed(arg):
    print("SETUP FAILED", arg)
    reactor.stop()

def init_peer(result):
    task.deferLater(reactor, 1, sn_peer.hspeer_run, [], config, 0)
    sn_peer.hs_init_privkey(config.HiddenServices[0].dir)
    seed_pubkey = binascii.hexlify(sn_peer.hs_get_pubkeyDER())
    print("Joinmarket seed peer started. It is configured as: ")
    for x in zip(["Nick", "Host", "Public port", "Pubkey"], 
                 [seedpeer_nick, config.HiddenServices[0].hostname,
                  str(hs_public_port), seed_pubkey]):
        print(": ".join(x))

hs_temp = tempfile.mkdtemp(prefix='torhiddenservice')

# register something to clean up our tempdir
# TODO address whether having the HS entirely 'ephemeral' like
# this could be sub-optimal somehow, although we expect users
# not to use static HSs.
reactor.addSystemEventTrigger(
    'before', 'shutdown',
    functools.partial(
        txtorcon.util.delete_file_or_tree,
        hs_temp
    )
)

# HS configuration
config = txtorcon.TorConfig()
config.SOCKSPort = 9150
config.ORPort = 9089

config.HiddenServices.append(
        txtorcon.HiddenService(
            config,
            hs_temp,
            ["%d 127.0.0.1:%d" % (hs_public_port, hs_port)]
        )
    )

config.save()

#Set up a static seed node peer
sn_peer = JMHSPeer(hs_public_port, [], fixed_name="SEED1")

# set up HS server, start Tor
site = server.Site(sn_peer)
hs_endpoint = TCP4ServerEndpoint(reactor, hs_port, interface='127.0.0.1')
hs_endpoint.listen(site)
d = txtorcon.launch_tor(config, reactor, progress_updates=updates)
#add chain of callbacks for actions after Tor is set up correctly.
d.addCallback(functools.partial(setup_complete, config))
d.addErrback(setup_failed)
d.addCallback(init_peer)

tlog.startLogging(open('jm_seedpeer.log', 'w'))

reactor.run()
