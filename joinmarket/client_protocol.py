#! /usr/bin/env python
from __future__ import print_function
from twisted.internet import protocol, reactor
from twisted.protocols import basic
import json
import random
import string
import time
import hashlib
import os
from joinmarket import (JMProtocol, Taker, Wallet, jm_single,
                        load_program_config, get_log, get_irc_mchannels)

import bitcoin as btc

jlog = get_log()


class JMTakerClientProtocol(JMProtocol):

    def __init__(self, factory, taker, nick_priv=None):
        self.taker = taker
        self.factory = factory
        self.orderbook = None
        self.supported_messages = ["JM_UP", "JM_SETUP_DONE", "JM_FILL_RESPONSE",
                                   "JM_OFFERS", "JM_SIG_RECEIVED",
                                   "JM_REQUEST_MSGSIG",
                                   "JM_REQUEST_MSGSIG_VERIFY", "JM_INIT_PROTO"]
        if not nick_priv:
            self.nick_priv = hashlib.sha256(os.urandom(16)).hexdigest() + '01'
        else:
            self.nick_priv = nick_priv

    def connectionMade(self):
        """Upon confirmation of network connection
        to daemon, request message channel initialization
        with relevant config data for our message channels
        """
        #needed only for channel naming convention
        blockchain_source = jm_single().config.get("BLOCKCHAIN",
                                                   "blockchain_source")
        network = jm_single().config.get("BLOCKCHAIN", "network")
        irc_configs = get_irc_mchannels()
        self.send_data("JM_INIT", [blockchain_source, network, irc_configs])

    def send_data(self, cmd, data):
        JMProtocol.send_data(self, cmd, data)

    def set_nick(self):
        self.nick_pubkey = btc.privtopub(self.nick_priv)
        self.nick_pkh_raw = hashlib.sha256(self.nick_pubkey).digest()[
                    :self.nick_hashlen]
        self.nick_pkh = btc.changebase(self.nick_pkh_raw, 256, 58)
        #right pad to maximum possible; b58 is not fixed length.
        #Use 'O' as one of the 4 not included chars in base58.
        self.nick_pkh += 'O' * (self.nick_maxencoded - len(self.nick_pkh))
        #The constructed length will be 1 + 1 + NICK_MAX_ENCODED
        self.nick = self.nick_header + str(self.jm_version) + self.nick_pkh
        jm_single().nickname = self.nick

    def on_JM_INIT_PROTO(self, nick_hashlen, nick_maxencoded, nick_header,
                         jm_version):
        """Daemon indicates init-ed status and passes back protocol constants.
        Use protocol settings to set actual nick from nick private key,
        then call setup to instantiate message channel connections in the daemon.
        """
        self.nick_hashlen = nick_hashlen
        self.nick_maxencoded = nick_maxencoded
        self.nick_header = nick_header
        self.jm_version = jm_version
        self.set_nick()
        self.send_data("JM_START_MC", [self.nick])

    def on_JM_UP(self):
        self.send_data("JM_SETUP", ["TAKER", 4])

    def on_JM_SETUP_DONE(self):
        jlog.info("JM daemon setup complete")
        #The daemon is ready and has requested the orderbook
        #from the pit; we can request the entire orderbook
        #and filter it as we choose.
        reactor.callLater(jm_single().maker_timeout_sec, self.get_offers)

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

    def on_JM_REQUEST_MSGSIG(self, nick, cmd, msg, msg_to_be_signed, hostid):
        sig = btc.ecdsa_sign(str(msg_to_be_signed), self.nick_priv)
        msg_to_return = str(msg) + " " + self.nick_pubkey + " " + sig
        self.send_data("JM_MSGSIGNATURE", [nick, cmd, msg_to_return, hostid])

    def on_JM_REQUEST_MSGSIG_VERIFY(self, msg, fullmsg, sig, pubkey, nick,
                                    hashlen, max_encoded, hostid):
        jlog.info("Got a request to verify a signature")
        verif_result = True
        if not btc.ecdsa_verify(str(msg), sig, pubkey):
            jlog.debug("nick signature verification failed, ignoring.")
            verif_result = False
        #check that nick matches hash of pubkey
        nick_pkh_raw = hashlib.sha256(pubkey).digest()[:hashlen]
        nick_stripped = nick[2:2 + max_encoded]
        #strip right padding
        nick_unpadded = ''.join([x for x in nick_stripped if x != 'O'])
        if not nick_unpadded == btc.changebase(nick_pkh_raw, 256, 58):
            jlog.debug("Nick hash check failed, expected: " + str(nick_unpadded)
                       + ", got: " + str(btc.changebase(nick_pkh_raw, 256, 58)))
            verif_result = False
        jlog.info("Sending a verifcation result: " + str(verif_result))
        self.send_data("JM_MSGSIGNATURE_VERIFY", [verif_result, nick, fullmsg,
                                                  hostid])

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
