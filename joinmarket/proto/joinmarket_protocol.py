#! /usr/bin/env python
from __future__ import print_function
import abc
from abstract_protocol import AbstractNPartyProtocol

"""Joinmarket application protocol control flow.
For documentation on protocol (formats, message sequence) see
https://github.com/JoinMarket-Org/JoinMarket-Docs/blob/master/
Joinmarket-messaging-protocol.md
"""

"""
API

Taker code:


init(N)

Start protocol instance.

ARGUMENTS:
arg1: number of potential maker counterparties
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
either error or:
{nick1: {'utxos':[list of utxos in hex], 'coinjoin_addr': addr1, 'change_addr': addr2},
nick2: {..}, .. }
Note that the list returned may be < N, up to consuming code to decide whether to
proceed with transaction with less than requested.


make_tx(txhex, nicks):

Complete transaction negotiation, and get signatures.

ARGUMENTS:
arg1: serialized transaction to be sent to counterparties
arg2: the list of counterparty nicks you choose to send the transaction to; it
must be a subset of the set that was *returned* by fill_offers()
RETURNS:
Serialized signed transaction or False if any failure occurred.
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

COMMAND_PREFIX = '!'
JOINMARKET_NICK_HEADER = 'J'
NICK_HASH_LENGTH = 10
NICK_MAX_ENCODED = 14 #comes from base58 expansion; recalculate if above changes

#Lists of valid commands
encrypted_commands = ["auth", "ioauth", "tx", "sig"]
plaintext_commands = ["fill", "error", "pubkey", "orderbook", "push"]
commitment_broadcast_list = ["hp2"]
plaintext_commands += offername_list
plaintext_commands += commitment_broadcast_list
public_commands = commitment_broadcast_list + ["orderbook",
                                               "cancel"] + offername_list
private_commands = encrypted_commands + plaintext_commands

#**************************************************************************
#END PROTOCOL DATA SECTION
#**************************************************************************

class JMProtocolError(Exception):
    pass

class JoinMarketProtocolManager(AbstractNPartyProtocol):
    """A class which manages the flow of the joinmarket protocol
    for each transaction occurring; it is used by both Maker
    and Takers. It registers callbacks with the message channel to
    receive events from remote parties, and the local party can also
    inject events into it. The protocol control flow is managed
    by the abstract base class, while the JM protocol semantics
    are managed here.
    The counterparties are thus required only to know the API functions
    used to inject events, and not any of the underlying communication
    protocol.
    It's important to note that protocol flow control is enabled for
    multiple simultaneous 2-way conversations, indexed by the "nick"
    of the counterparty.
    """
    events = {
        -7: ["MAKER_ORDER_CANCEL_SEND", True, False],
        -6: ['CHANNEL_WELCOME', True, False], #used to signal readiness 
        -5: ['CHANNEL_NICK_CHANGE', True, False],
        -4: ['CHANNEL_NICK_LEAVE', True, False],
        -3: ['CHANNEL_SET_TOPIC', True, False],
        -2: ['CHANNEL_CONNECT', True, False],
        -1: ['CHANNEL_DISCONNECT', True, False],
        0: ['READY', True, False],
        1: ['TAKER_ORDERBOOK_REQUEST_SEND', True, False],
        2: ['MAKER_OFFER_SEND', True, False],
        3: ['MAKER_OFFER_SEND_FINISH', False, False],
        4: ['TAKER_FILL', True, True],
        5: ['TAKER_POST_COMMITMENT', True, True],
        6: ['TAKER_INIT_DH_SEND', True, True],
        7: ['TAKER_INIT_DH_SEND_FINISH', False, True],
        8: ['MAKER_ACCEPT_FILL', True, True],
        9: ['MAKER_ACCEPT_COMMITMENT', True, True],
        10: ['MAKER_REJECT_COMMITMENT', True, True],
        11: ['MAKER_INIT_DH_SEND', True, True],
        12: ['MAKER_INIT_DH_SEND_FINISH', False, True],
        13: ['TAKER_COMMITMENT_OPENING_SEND', True, True], #triggers after all 8-12 complete
        14: ['TAKER_COMMITMENT_OPENING_SEND_FINISH', False, True],
        15: ['MAKER_ACCEPT_REQUEST_COMMITMENT_OPENING', True, True],
        16: ['MAKER_REJECT_REQUEST_COMMITMENT_OPENING', True, True],
        17: ['MAKER_POST_TRANSACTION_DATA', True, True],
        18: ['MAKER_AUTHENTICATE_E2E_SEND', True, True],
        19: ['MAKER_AUTHENTICATE_E2E_SEND_FINISH', False, True],
        20: ['TAKER_ACCEPT_E2E_AUTHENTICATION', True, True],
        21: ['TAKER_REJECT_E2E_AUTHENTICATION', True, True],
        22: ['TAKER_TX_TEMPLATE_SEND', True, True], #triggers after all 15-21 complete
        23: ['TAKER_TX_TEMPLATE_SEND_FINISH', False, True],
        24: ['MAKER_TX_SIG_SEND', True, True],
        25: ['MAKER_TX_SIG_SEND_FINISH', False, True],
        26: ['TX_ON_NETWORK', False, False],
        27: ['TX_CONFIRMED', False, False],
        28: ['TAKER_ERROR_SEND', True, True],
        29: ['MAKER_ERROR_SEND', True, True]
        }
    error_events = [10, 16, 21, 28, 29]
    #Events with stateful=False have no effect on the protocol.
    #All protocol sequences start from zero, and all can be terminated
    #if at any point event 28 or 29 occurs.
    #Events whose names end in SEND must return the set of arguments
    #to be used as inputs to the corresponding msgchannel functions on
    #sender side and be triggered by msgchannel callbacks on receiver side.
    #The receiver of a SEND event can (if appropriate) 
    #automatically trigger the SEND_FINISH
    #event afterwards; for the sender (who may send more than one), the
    #SEND_FINISH must be manually triggered by program logic.
    
    def __init__(self):
        self.role = None

    #Not __init__ as constructed on connection; call setup explicitly
    def setup(self, role):
        #maker or taker role
        self.set_role(role)
        #A pointer to our current location in the valid sequence of events;
        #always start at the event *before* the first stateful event
        #(which is 4, TAKER_FILL).
        self.current_event = {}
        #Remember the event flow, may be useful for debugging.
        self.event_history = {}
        #all events marked "SEND" are treated differently (see above)
        self.taker_sending_events = []
        self.maker_sending_events = []
        for k, v in self.events.iteritems():
            if v[0].endswith("SEND") and v[0].startswith("TAKER"):
                self.taker_sending_events.append(k)
            if v[0].endswith("SEND") and v[0].startswith("MAKER"):
                self.maker_sending_events.append(k)

    def get_sending_events(self):
        if self.role == "TAKER":
            return self.taker_sending_events
        elif self.role == "MAKER":
            return self.maker_sending_events
        else:
            raise JMProtocolError("Invalid protocol role: " + str(self.role))

    def get_initial_event(self):
        return 3

    def set_role(self, role):
        """Whether performing taker or maker side; must be "TAKER" or "MAKER"
        (Note that while bots might perform both sides, they can only take
        one role in a single protocol run).
        """
        self.role = role
        if not self.role in ["TAKER", "MAKER"]:
            raise JMProtocolError("Invalid protocol role: " + str(self.role))

    def process_error(self, event, *args):
        """Returns a helpful error message to indicate
        that the event has occurred out of sequence, or that
        a protocol failure has occurred.
        """
        if event == 28:
            return "The taker sent an error: " + str(args)
        elif event == 29:
            return "The maker sent an error: " + str(args)
        elif event == 10:
            return "The taker sent an invalid commitment"
        elif event == 21:
            return "The maker sent an invalid encryption authentication"
        elif event == 16:
            return "The taker sent an invalid commitment opening"
        else:
            return "Event code: " + str(event) + " occurred out of sequence."

    def on_connect(self):
        self.receive_event(-2)

    def on_disconnect(self):
        self.receive_event(-1)

    def on_nick_leave(self, nick):
        self.receive_event(-4, nick)

    #TODO on_pubmsg and on_privmsg can be folded together
    def on_pubmsg(self, nick, msg):
        """Interprets, according to the Joinmarket protocol logic,
        the contents of a message received on the public/broadcast
        mode of the messagechannel collection.
        """
        if msg[0] != COMMAND_PREFIX:
            print("Received invalid pubmsg, ignoring: " + msg)
        parsed_msg = msg[1:].split(separator)
        first_command = parsed_msg[0]
        if first_command not in public_commands:
            print("Received unknown public command, ignoring: " + first_command)
        if len(parsed_msg) == 1:
            rest_of_msg = []
        else:
            rest_of_msg = parsed_msg[1:]
        return getattr(self, 'on_'+first_command)(nick, rest_of_msg)

    def on_privmsg(self, nick, msg):
        """Interprets, according to the Joinmarket protocol logic,
        the contents of a message received on the public/broadcast
        mode of the messagechannel collection.
        """
        if msg[0] != COMMAND_PREFIX:
            print("Received invalid privmsg, ignoring: " + msg)
        parsed_msg = msg[1:].split(separator)
        first_command = parsed_msg[0]
        if first_command not in private_commands:
            print("Received unknown private command, ignoring: " + first_command)
        if len(parsed_msg) == 1:
            rest_of_msg = []
        else:
            rest_of_msg = parsed_msg[1:]
        return getattr(self, 'on_'+first_command)(nick, rest_of_msg)

    def on_welcome(self):
        self.receive_event(-6)

    def on_set_topic(self, newtopic):
        chunks = newtopic.split('|')
        for msg in chunks[1:]:
            try:
                msg = msg.strip()
                params = msg.split(' ')
                min_version = int(params[0])
                max_version = int(params[1])
                alert = msg[msg.index(params[1]) + len(params[1]):].strip()
            except ValueError, IndexError:
                continue
            if min_version < jm_single().JM_VERSION < max_version:
                print('=' * 60)
                print('JOINMARKET ALERT')
                print(alert)
                print('=' * 60)
                jm_single().joinmarket_alert[0] = alert
        self.receive_event(-3)
    #************************************************************************
    #PROTOCOL CALLBACKS SECTION.
    #This is currently an implementation of the rules specified here:
    #https://github.com/JoinMarket-Org/JoinMarket-Docs/blob/master/
    #Joinmarket-messaging-protocol.md#private-conversation-in-detail
    #************************************************************************
    
    def default_callback(self, *args):
        #do nothing
        return (True, ["Default callback called", str(args)])

    def on_orderbook(self, nick, msg):
        """The contents of the orderbook request after the first
        instance of !orderbook are explicitly ignored (no DOS).
        """
        self.receive_event(1, nick)

    def on_reloffer(self, nick, msg):
        return self.on_x_offer(nick, msg, "reloffer")
    
    def on_absoffer(self, nick, msg):
        return self.on_x_offer(nick, msg, "absoffer")

    def on_x_offer(self, nick, msg, first_ordertype):
        """Special processing: parse 'msg' as
        rest of message, which includes the rest of this order
        and all others.
        """
        msg = separator.join(msg)
        rest = msg.split(COMMAND_PREFIX)
        orderlines = []
        orderlines.append([first_ordertype] + rest[0].split(separator))
        for r in rest[1:]:
            parsed_line = r.strip().split(separator)
            orderlines.append(parsed_line)
        for orderline in orderlines:
            if len(orderline) != 6:
                print("Invalid order, ignoring: " + str(orderline))
                #Fail completely on any one invalid order
                return
            ordertype, oid, minsize, maxsize, txfee, cjfee = orderline
            self.receive_event(2, nick, [oid, ordertype, minsize, maxsize,
                               txfee, cjfee])

    def on_cancel(self, nick, msg):
        if len(msg) != 1:
            print("Invalid cancel command, ignoring: " + str(msg))
            return
        try:
            oid = int(msg[0])
        except ValueError:
            print("Invalid orderid to cancel, ignoring: " + str(msg))
            return
        self.receive_event(-7, nick, oid)

    def on_fill(self, nick, msg):
        if len(msg) != 4:
            print("Invalid fill request, ignoring: " + separator.join(msg))
            return
        oid, amount, taker_pubkey, commit = msg
        #This is the entry point to the state machine for the
        #maker side; 4 is the first stateful event.
        res, data = self.receive_event(4, nick, oid, amount)
        if not res:
            self.receive_event(29, nick, "Invalid fill request", data)
        #any commit type is allowed at the protocol level
        res, data = self.receive_event(5, nick, commit)
        if not res:
            self.receive_event(10, nick, "Invalid commitment", data)
        #Init DH
        res, data = self.receive_event(6, nick, taker_pubkey)
        if not res:
            self.receive_event(29, nick, "Invalid ECDH key", data)
        else:
            pubkey = data[0]
        #7 is triggered immediately (one 6 per tx from maker side)
        self.receive_event(7, nick)
        #commitment and fill OK
        self.receive_event(8, nick)
        self.receive_event(9, nick)
        #send !pubkey
        res, data = self.receive_event(11, False, nick, "pubkey", pubkey)
        if not res:
            self.receive_event(29, nick, data)
        self.receive_event(12, nick)

    
    def on_pubkey(self, nick, msg):
        if len(msg) != 1:
            print("Invalid pubkey message, ignoring: " + separator.join(msg))
        pubkey = msg[0]
        #Acceptance of fill and commit is implicit from receipt of !pubkey
        self.receive_event(8, nick)
        self.receive_event(9, nick)
        #Init DH - actually receive the pubkey
        res, data = self.receive_event(11, nick, pubkey)
        if res:
            if data[0]:
                self.receive_event(12)
                reveal = data[1]
                for n in data[2:]:
                    self.receive_event(13, False, n, "auth", reveal)
                self.receive_event(14)
        else:
            self.receive_event(28, "Invalid pubkey message")
        #E2E is now established, future messages encrypted.
    
    def on_auth(self, nick, msg):
        if len(msg) != 1:
            print("Invalid commitment opening, ignoring: " + separator.join(msg))
        commitment_reveal = msg[0]
        #Process the reveal of the commitment
        result, data = self.receive_event(13, nick, commitment_reveal)
        #Finish triggered automatically maker side
        self.receive_event(14, nick)
        if not result:
            #Commitment not accepted.
            self.receive_event(16, nick)
        else:
            self.receive_event(15, nick, data)
            #acceptance triggers ioauth
            utxos, auth_pub, cj_addr, change_addr, btc_sig = data
            #TODO 17 is not a "SEND" event
            #TODO utxos is a list, syntax wrong
            self.receive_event(17, False, nick, "ioauth",
                               utxos, auth_pub, cj_addr, change_addr,
                               btc_sig)
            #18 and 19 implicit on maker side
            self.receive_event(18, nick)
            self.receive_event(19, nick)
    
    def on_ioauth(self, nick, msg):
        if len(msg) != 5:
            print("Invalid ioauth message, ignoring: " + separator.join(msg))
        ulist, maker_auth_pub, coinjoin_addr, change_addr, bitcoin_sig = msg
        #Commitment acceptance is implicit from receipt of ioauth.
        res, data = self.receive_event(15, "Maker: " + nick + \
                                       " accepted commitment.")
        #Process the maker's transaction data
        result, data = self.receive_event(17, nick, ulist, coinjoin_addr,
                                          change_addr)
        if not result:
            #This could happen if the utxos are invalid
            self.receive_event(28, data)
        #Authenticate - The anti-MITM measure
        result, data = self.receive_event(18, nick, maker_auth_pub, bitcoin_sig)
        if not result:
            self.receive_event(21, nick)
        else:
            self.receive_event(19, nick)
            self.receive_event(20, nick)
            if data[0]:
                txhex = data[1]
                nicks = data[2:]
                for n in nicks:
                    self.receive_event(22, False, n, "tx", txhex)
        self.receive_event(23)


    def on_tx(self, nick, msg):
        if len(msg) != 1:
            print("Invalid tx message, ignoring: " + separator.join(msg))
            return
        #20 implicit on receipt of !tx
        self.receive_event(20, nick)
        tx = msg[0]
        res, data = self.receive_event(22, nick, tx)
        if not res:
            self.receive_event(29, nick, data)
        else:
            self.receive_event(23, nick)
            for sig in data[0]:
                self.receive_event(24, False, nick, "sig", sig)
            self.receive_event(25, nick)

    
    def on_sig(self, nick, msg):
        if len(msg) != 1:
            print("Invalid sig message, ignoring: " + separator.join(msg))
            return
        sig = msg[0]
        res, data = self.receive_event(24, nick, sig)
        if res: #failures are just ignored
            if data[0]:
                self.receive_event(25) #triggers complete
    #************************************************************************
    #END PROTOCOL CALLBACKS SECTION.
    #************************************************************************
    
    #************************************************************************
    #PROTOCOL INJECTIONS SECTION.
    #This is currently an implementation of the rules specified here:
    #https://github.com/JoinMarket-Org/JoinMarket-Docs/blob/master/
    #Joinmarket-messaging-protocol.md#private-conversation-in-detail
    #************************************************************************
"""
    def maker_order_cancel(self, oid):
        self.receive_event(-7, None, [True, None, "cancel", str(oid)])
    
    def taker_orderbook_request(self, nick):
        pub = True if nick else False
        self.receive_event(1, nick, [pub, nick, "orderbook"])
    
    def maker_offer_send(self,
"""