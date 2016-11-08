#! /usr/bin/env python
from __future__ import print_function
import sys
from joinmarket import (IRCMessageChannel, MessageChannelCollection,
                        get_irc_mchannels, load_program_config, jm_single,
                        OrderbookWatch, as_init_encryption, init_pubkey,
                        NaclError, init_keypair)
from twisted.python import log
import json
import time
import threading
from twisted.internet import protocol, reactor
from twisted.protocols import basic

"""Joinmarket application protocol control flow.
For documentation on protocol (formats, message sequence) see
https://github.com/JoinMarket-Org/JoinMarket-Docs/blob/master/
Joinmarket-messaging-protocol.md
"""

"""
***
API
***

Taker code:
===========

Calling code must be prepared to act as both server and client, as the
communication is asynchronous both ways.

The typical Taker workflow for making use of this API will be:
1. Send message JM_INIT, which will set up the underlying
messaging connections (e.g. IRC). This will not cause an error if the Protocol
object is already inited.
2. Wait for the message JM_UP.
4. Send message JM_SETUP, passing N to indicate the number of counterparties
desired, and role TAKER.
3. Send the request JM_GET_OFFERS to retrieve, from the database maintained here,
a list of offers satisfying your requirements.
4. Do business logic in calling code to filter and select the offers you want
to fill.
Then, follow the protocol in 2 phases:
5. Prepare a taker commitment (using PoDLE by default) for your fill request.
6. Send message JM_FILL_OFFERS with the chosen offers and the taker's commitment data.
7. Wait for JM_FILL_ACCEPTED message, retrieve utxos and receiving addresses.
8. After validating the return data meets your needs (including the number of
counterparties responding), send request make_tx with a Bitcoin transaction
template constructed based on the data from 4.
9. Wait for JM_TX_ACCEPTED message, retrieve the signatures of your counterparties.
10. Fill in the signatures to your transaction template. Then, sign yourself and
broadcast the transaction if it meets all requirements.

A taker can go through this workflow more than once of course. Only get_offers is
stateless and can be called at any time, the other methods must be called in the
above sequence.

*******
METHODS
*******

 setup(role, N)

Start protocol instance.

ARGUMENTS:
arg1: role, must be "TAKER", other role not yet implemented.
arg2: number of potential maker counterparties
arg3: callback function which will be called on completion of on_fill_offers
arg4: callback function which will be called on completion of make_tx
RETURNS:
True or False if setup failed.


 fill_offers(amount, commitment, commitment_revelation, {nick1: oid1, nick2: oid2, ...})

Initiate phase 1 of the protocol.

ARGUMENTS:
arg1: amount of coinjoin in satoshis (0 for sweep),
arg3: commitment for request (type PoDLE by default)
arg4: revelation data for above commitment
arg5: dict representing counterparty nicks and their order ids. Must be length N.
RETURNS:
True if arguments valid, or False otherwise
CALLBACK on_fill_offers_response has arguments:
either error or:
{nick1: {'utxos':[list of utxos in hex], 'coinjoin_addr': addr1, 'change_addr': addr2},
nick2: {..}, .. }
Note that the list returned may be < N, up to consuming code to decide whether to
proceed with transaction with less than requested.


 make_tx(txhex, nicks):

Initiate phase 2 of the protocol.
Complete transaction negotiation, and get signatures. It is the calling code's
responsibility to ensure that the txhex satisfies *its own* spending rules (i.e.
that it receives enough to its own wallet), but also the calling code should
validate that the counterparties receive an amount in accordance with the rules
that they specified in their orders.

ARGUMENTS:
arg1: serialized transaction to be sent to counterparties
arg2: the list of counterparty nicks you choose to send the transaction to; it
must be a subset of the set that was *returned* by fill_offers()
RETURNS:
Serialized signed transaction or False if any failure occurred.

Additionally, these functions can be called statelessly (i.e. at any time):

 get_offers(amount)

Find offers available for the given coinjoin amount. The calling code
can take the returned dict of offers and apply its own business logic to filter
it before deciding who to include in the fill_offers call (see above).

ARGUMENTS:
arg1: amount in satoshis
RETURNS:
dict of available offers, format: [{'counterparty': nick1, 'ordertype': ot,
'oid': oid, 'minsize': x, 'txfee': t, 'maxsize': y, 'cjfee': f}, {},..]


Maker code
==========

Not yet implemented.
"""

#**************************************************************************
#PROTOCOL DATA SECTION
#**************************************************************************
separator = " "
offertypes = {"reloffer": [(int, "oid"), (int, "minsize"), (int, "maxsize"),
                           (int, "txfee"), (float, "cjfee")],
              "absoffer": [(int, "oid"), (int, "minsize"), (int, "maxsize"),
                           (int, "txfee"), (int, "cjfee")]}

offername_list = offertypes.keys()

ORDER_KEYS = ['counterparty', 'oid', 'ordertype', 'minsize', 'maxsize', 'txfee',
              'cjfee']

COMMAND_PREFIX = '!'
JOINMARKET_NICK_HEADER = 'J'
NICK_HASH_LENGTH = 10
NICK_MAX_ENCODED = 14  #comes from base58 expansion; recalculate if above changes

#Lists of valid commands
encrypted_commands = ["auth", "ioauth", "tx", "sig"]
plaintext_commands = ["fill", "error", "pubkey", "orderbook", "push"]
commitment_broadcast_list = ["hp2"]
plaintext_commands += offername_list
plaintext_commands += commitment_broadcast_list
public_commands = commitment_broadcast_list + ["orderbook", "cancel"
                                              ] + offername_list
private_commands = encrypted_commands + plaintext_commands

#**************************************************************************
#END PROTOCOL DATA SECTION
#**************************************************************************


class MCThread(threading.Thread):

    def __init__(self, mc):
        threading.Thread.__init__(self, name='MCThread')
        self.mc = mc
        self.daemon = True

    def run(self):
        self.mc.run()

class JMProtocolError(Exception):
    pass

class JMProtocol(basic.LineReceiver):

    def send_data(self, cmd, data):
        assert isinstance(data, list)
        self.sendLine(json.dumps({cmd: data}))

    def lineReceived(self, line):
        #All lines in JSON, format is:
        #{command:[data_as_list]}; more than one command supported.
        def fail(x):
            print("Invalid line received: " + str(x))
            return

        try:
            received_json = json.loads(line)
        except:
            return fail(line)

        #Check valid data structure received
        if not isinstance(received_json, dict):
            return fail(received_json)
        if not len(received_json.keys()):
            return fail(received_json)
        if not all([isinstance(x, list) for x in received_json.values()]):
            return fail(received_json)

        #The key to the dict must be one of the existing functions in the API
        for k, v in received_json.iteritems():
            if k not in self.supported_messages:
                print("Command not supported: " + str(k) + ", ignoring")
                continue
            return getattr(self, 'on_' + k)(*v)


class JMServerDaemonProtocol(JMProtocol, OrderbookWatch):

    def __init__(self, factory):
        self.factory = factory
        OrderbookWatch.__init__(self, self.factory.msgchan)
        #register taker-specific msgchan callbacks here
        self.factory.msgchan.register_taker_callbacks(
            self.on_error, self.on_pubkey, self.on_ioauth, self.on_sig)
        self.factory.msgchan.set_daemon(self)
        self.supported_messages = ["JM_INIT", "JM_SETUP", "JM_FILL",
                                   "JM_MAKE_TX", "JM_REQUEST_OFFERS",
                                   "JM_MAKE_TX"]

    def get_crypto_box_from_nick(self, nick):
        if nick in self.crypto_boxes and self.crypto_boxes[nick] != None:
            return self.crypto_boxes[nick][1]  # libsodium encryption object
        else:
            log.debug('something wrong, no crypto object, nick=' + nick +
                      ', message will be dropped')
            return None

    def init_connections(self):
        self.state = 0  #uninited
        MCThread(self.factory.msgchan).start()

    def on_welcome(self):
        """Fired when channel indicated state readiness
        """
        self.send_data("JM_UP", [])

    def on_error(self):
        print("Unimplemented on_error")

    def mc_shutdown(self):
        print("Message channels shut down in proto")
        self.factory.msgchan.shutdown()

    def on_JM_INIT(self):
        print("got a hello: ")
        self.init_connections()

    def on_JM_SETUP(self, role, n_counterparties):
        assert self.state == 0
        assert n_counterparties > 1
        #TODO consider MAKER role implementation here
        assert role == "TAKER"
        self.requested_counterparties = n_counterparties
        self.crypto_boxes = {}
        self.kp = init_keypair()
        print("Received setup command")
        self.send_data("JM_SETUP_DONE", [])
        #Request orderbook here, on explicit setup request from client,
        #assumes messagechannels are in "up" state. Orders are read
        #in the callback on_order_seen in OrderbookWatch.
        self.factory.msgchan.pubmsg(COMMAND_PREFIX + "orderbook")
        self.state = 1

    def on_JM_REQUEST_OFFERS(self):
        """Reports the current state of the orderbook.
        This call is stateless."""
        rows = self.db.execute('SELECT * FROM orderbook;').fetchall()
        self.orderbook = [dict([(k, o[k]) for k in ORDER_KEYS]) for o in rows]
        self.send_data("JM_OFFERS", [self.orderbook])

    def on_JM_FILL(self, amount, commitment, revelation, nick_offer_dict):
        assert self.state == 1
        assert isinstance(amount, int)
        assert amount >= 0
        self.cjamount = amount
        self.commitment = commitment
        self.revelation = revelation
        #Reset utxo data to null for this new transaction
        self.ioauth_data = {}
        self.active_orders = nick_offer_dict
        for nick, offer_dict in nick_offer_dict.iteritems():
            offer_fill_msg = " ".join([str(offer_dict["oid"]), str(amount), str(
                self.kp.hex_pk()), str(commitment)])
            self.factory.msgchan.privmsg(nick, "fill", offer_fill_msg)
        self.state = 2

    def on_JM_MAKE_TX(self, nick_list, txhex):
        assert self.state == 2
        self.factory.msgchan.send_tx(nick_list, txhex)

    def on_sig(self, nick, sig):
        """Pass signature through to Taker.
        """
        self.send_data("JM_SIG_RECEIVED", [nick, sig])

    def on_pubkey(self, nick, maker_pk):
        """This is handled locally in the daemon; set up e2e
        encrypted messaging with this counterparty
        """
        if nick not in self.active_orders.keys():
            log.debug("Counterparty not part of this transaction. Ignoring")
            return
        try:
            self.crypto_boxes[nick] = [maker_pk, as_init_encryption(
                self.kp, init_pubkey(maker_pk))]
        except NaclError as e:
            print("Unable to setup crypto box with " + nick + ": " + repr(e))
            self.factory.msgchan.send_error(nick,
                                            "invalid nacl pubkey: " + maker_pk)
            return
        self.factory.msgchan.send_auth(nick, self.revelation)

    def on_ioauth(self, nick, utxo_list, auth_pub, cj_addr, change_addr,
                  btc_sig):
        """Passes through to Taker the information from counterparties once
        they've all been received; note that we must also pass back the maker_pk
        so it can be verified against the btc-sigs for anti-MITM
        """
        if nick not in self.active_orders.keys():
            print("Got an unexpected ioauth from nick: " + str(nick))
            return
        self.ioauth_data[nick] = [utxo_list, auth_pub, cj_addr, change_addr,
                                  btc_sig, self.crypto_boxes[nick][0]]
        #TODO apply timeout on the issue of when to send back if not all
        #responded.
        if self.ioauth_data.keys() == self.active_orders.keys():
            self.send_data("JM_FILL_RESPONSE", [True, self.ioauth_data])
        else:
            #for now just send a failure message if the data is insufficient
            self.send_data("JM_FILL_RESPONSE", [False, []])


class JMServerDaemonProtocolFactory(protocol.ServerFactory):
    protocol = JMServerDaemonProtocol

    def __init__(self, msgchan):
        self.msgchan = msgchan

    def buildProtocol(self, addr):
        return JMServerDaemonProtocol(self)


def startup_joinmarketd(mcc, port, finalizer=None, finalizer_args=None):
    """Start event loop for joinmarket daemon here.
    Args:
    mcc : a joinmarket.MessageChannelCollection instance
    port : port over which to serve the daemon
    finalizer: a function which is called after the reactor has shut down.
    finalizer_args : arguments to finalizer function.
    """
    log.startLogging(sys.stdout)
    factory = JMServerDaemonProtocolFactory(mcc)
    reactor.listenTCP(port, factory)
    if finalizer:
        reactor.addSystemEventTrigger("after", "shutdown", finalizer,
                                      finalizer_args)
    reactor.run()


if __name__ == "__main__":
    port = int(sys.argv[1])
    load_program_config()
    mcs = [IRCMessageChannel(c,
                             realname='btcint=' + jm_single().config.get(
                                 "BLOCKCHAIN", "blockchain_source"))
           for c in get_irc_mchannels()]
    mcc = MessageChannelCollection(mcs)
    startup_joinmarketd(mcc, port)
