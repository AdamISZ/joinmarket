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

def init_peer(result, sn_peer):
    task.deferLater(reactor, 1, sn_peer.hspeer_run, [], tconfig, 0)
    sn_peer.hs_init_privkey(tconfig.HiddenServices[0].dir)
    seed_pubkey = binascii.hexlify(sn_peer.hs_get_pubkeyDER())
    print("Joinmarket seed peer started. It is configured as: ")
    for x in zip(["Nick", "Host", "Public port", "Pubkey"], 
                 [seedpeer_nick, tconfig.HiddenServices[0].hostname,
                  str(hs_public_port), seed_pubkey]):
        print(": ".join(x))


def main(seedpeer_nick, hs_port, hs_public_port):
    #Set up a single seed node peer
    sn_peer = JMHSPeer(hs_public_port, [], fixed_name=seedpeer_nick)
    d = start_tor([sn_peer], [hs_public_port], [hs_port])
    d.addCallback(init_peer, sn_peer)
    tlog.startLogging(open(seedpeer_nick + '.log', 'w'))
    reactor.run()

if __name__ == '__main__':
    seedpeer_nick, hs_port, hs_public_port = sys.argv[1:]
    hs_port = int(hs_port)
    hs_public_port = int(hs_public_port)
    main(seedpeer_nick, hs_port, hs_public_port)
    