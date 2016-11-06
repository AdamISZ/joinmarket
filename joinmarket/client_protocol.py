#! /usr/bin/env python
from __future__ import print_function
from twisted.internet import protocol, reactor
from twisted.protocols import basic
import json
import random
import string
import time

from joinmarket import (JMProtocol, Taker, Wallet, jm_single,
                        load_program_config, get_log)


jlog = get_log()

class JMTakerClientProtocol(JMProtocol):

    def __init__(self, factory, taker):
        self.taker = taker
        self.factory = factory
        self.orderbook = None
        self.supported_messages = ["JM_UP", "JM_SETUP_DONE", "JM_FILL_RESPONSE",
                                   "JM_OFFERS", "JM_SIG_RECEIVED"]

    def connectionMade(self):
        jsondata = {"JM_INIT": []}
        self.send_data("JM_INIT", [])

    def send_data(self, cmd, data):
        JMProtocol.send_data(self, cmd, data)

    def on_JM_UP(self):
        self.send_data("JM_SETUP", ["TAKER", 4])

    def on_JM_SETUP_DONE(self):
        jlog.info("JM daemon setup complete")
        #The daemon is ready and has requested the orderbook
        #from the pit; we can request the entire orderbook
        #and filter it as we choose.
        jlog.info("Waiting a few seconds")
        time.sleep(5)
        self.get_offers()

    def on_JM_FILL_RESPONSE(self, success, ioauth_data):
        """Receives the entire set of phase 1 data (principally utxos)
        from the counterparties and passes through to the Taker for
        tx construction, if successful. Then passes back the phase 2
        initiating data to the daemon.
        """
        if not success:
            jlog.info("Makers didnt respond blah blah")
        else:
            jlog.info("Makers responded with: " + json.dumps(ioauth_data))
            retval = self.taker.receive_utxos(ioauth_data)
            if not retval[0]:
                jlog.info("Taker is not continuing, phase 2 abandoned.")
                jlog.info("Reason: " + str(retval[1]))
            else:
                nick_list, txhex = retval[1:]
                self.make_tx(nick_list, txhex)

    def on_JM_MESSAGING_UP(self):
        jlog.info("The daemon reports that it has joined all message channels.")
        self.get_offers()

    def on_JM_OFFERS(self, offerdict):
        self.orderbook = offerdict
        jlog.info("Got the orderbook: " + str(offerdict))
        retval = self.taker.initialize(self.orderbook)
        #format of retval is:
        #True, self.cjamount, commitment, revelation, self.filtered_orderbook)
        if not retval[0]:
            jlog.info("Taker not continuing after receipt of orderbook")
            return
        amt, cmt, rev, foffers = retval[1:]
        self.send_data("JM_FILL", [amt, cmt, rev, foffers])

    def on_JM_SIG_RECEIVED(self, nick, sig):
        retval = self.taker.on_sig(nick, sig)
        if retval:
            #flag indicating completion; but Taker
            #handles tx pushing, just update state
            self.state = 4

    def get_offers(self):
        self.send_data("JM_REQUEST_OFFERS", [])

    def make_tx(self, nick_list, txhex):
        self.send_data("JM_MAKE_TX", [nick_list, txhex])


class JMTakerClientProtocolFactory(protocol.ClientFactory):
    protocol = JMTakerClientProtocol

    def __init__(self, taker):
        self.taker = taker

    def buildProtocol(self, addr):
        return JMTakerClientProtocol(self, self.taker)

def start_reactor(host, port, factory):
    reactor.connectTCP(host, port, factory)
    reactor.run()
