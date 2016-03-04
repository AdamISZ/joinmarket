#! /usr/bin/env python
from __future__ import absolute_import, print_function

'''Bare bones implementation of a single 
Hidden Service peer for joinmarket. Intended
to be run as a long term seed peer that can 
be published to others for bootstrap.
'''

import os
import binascii
import sys

from joinmarket.hsmc import JMHSPeer
from joinmarket.tor import start_tor, tconfig

from twisted.internet import reactor
from twisted.web import server, resource
from twisted.python import log as tlog

from pprint import pformat

from twisted.internet import task
seed_nick = "SEED1"
seed_pubkey = '30819f300d06092a864886f70d010101050003818d0030818902818100cfe2c87a5430bf1adf2e2e90e2b9a7e65a99c4aa5f40c938cca2322814a24d36cca347e2f187941e84f7824afbf42703517fc51f1302795725bd567af49415cfb838e13d908cd11f325daa62f08f0269f01aeda7f2056968281a9fb5278df111d700512c9a0363a537d598a0da80f71baa870da49a01f4f85c1bb3ce1786e0230203010001'
seed_host = 'g5tlzhinshwioi7a.onion'
seed_port = 8080

def init_peer(result, peer):
    task.deferLater(reactor, 1, peer.hspeer_run,
                    [(seed_nick, seed_host, seed_port, seed_pubkey)], tconfig, 0)
    peer.hs_init_privkey(tconfig.HiddenServices[0].dir)
    print("Joinmarket peer started. It is configured as: ")
    for x in zip(["Nick", "Host", "Public port", "Pubkey"], 
                 [peer.peername, tconfig.HiddenServices[0].hostname,
                  str(hs_public_port), seed_pubkey]):
        print(": ".join(x))


def main(nick, hs_port, hs_public_port):
    #Set up a single seed node peer
    peer = JMHSPeer(hs_public_port, [], fixed_name=nick)
    d = start_tor([peer], [hs_public_port], [hs_port])
    d.addCallback(init_peer, peer)
    tlog.startLogging(open(nick + '.log', 'w'))
    reactor.run()

if __name__ == '__main__':
    nick, hs_port, hs_public_port = sys.argv[1:]
    hs_port = int(hs_port)
    hs_public_port = int(hs_public_port)
    main(nick, hs_port, hs_public_port)
    