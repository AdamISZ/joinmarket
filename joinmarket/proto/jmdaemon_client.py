#!/usr/bin/env python
from __future__ import print_function
from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint
import sys
import json
from joinmarket_protocol import public_commands, private_commands, \
     JMProtocolError, COMMAND_PREFIX

class JMClientProtocol(Protocol):
    def __init__(self, role, event_callbacks=None, msgchan=None):
        self.role = role
        self.event_callbacks = event_callbacks
        if msgchan:
            msgchan.register_callbacks(on_connect=self.on_connect,
                                   on_disconnect=self.on_disconnect,
                                   on_pubmsg=self.on_pubmsg,
                                   on_privmsg=self.on_privmsg)
    def sendMessage(self, msg):
        self.transport.write("%s\n" % msg)

    def dataReceived(self, raw_data):
        print("Got data: %s" % raw_data)
        try:
            jsonline = json.loads(raw_data)
            event, success, data = jsonline
        except:
            print("Error passing json in client")
            print("Got: ", raw_data)
            return
        if event == "welcome_message":
                print("Welcome!: ", data)
                return
        if event == "client_established":
            print("Successfully connected to joinmarketd")
            return
        if event == "invalid_role":
            print("Failed to connect to joinmarketd, invalid role: " + data[0])
    
        if self.role == "MSGCHAN":
            #Apart from setup events,
            #the message channel client only *receives* messages to be sent
            #via priv/pubmsg
            msgargs = jsonline
            self.send_msg(msgargs)
        else:
            if not self.event_callbacks or event not in self.event_callbacks:
                print("Non existent callback error")
            self.event_callbacks[event](success, data)

    def send_msg(self, msgargs):
        #msgargs:
        #0: public or private (True/False)
        #1: nick (none if public/ignored)
        #2: command
        #3+ remaining arguments of command
        public = True if msgargs[0] else False
        nick = msgargs[1] if not public else None
        command = msgargs[2]
        #TODO special handling of "orderlist" magic command;
        #it follows a different syntax because multiple orderlist
        #commands are munged into one message.
        if public:
            if command not in public_commands:
                raise JMProtocolError("Command : " + command + \
                                      " cannot be broadcast")
            self.msgchan.pubmsg(separator.join(
                [COMMAND_PREFIX + command] + msgargs[3:]))
        else:
            if command not in private_commands:
                raise JMProtocolError("Command: " + command + \
                                      " cannot be privmsged")
            self.msgchan.privmsg(nick, command, separator.join(msgargs[3:]))

    def on_pubmsg(self, nick, msg):
        print("Got msg in callback: ", msg, " from nick: ", nick)
        self.sendMessage(json.dumps(["on_pubmsg", nick, [msg]]))
    
    def on_privmsg(self, nick, msg):
        print("Got msg in callback: ", msg, " from nick: ", nick)
        self.sendMessage(json.dumps(["on_privmsg", nick, [msg]]))
    
    def on_connect(self):
        print("Client of msgchan connected")
        self.sendMessage(json.dumps(["on_connect", None, []]))
    
    def on_disconnect(self):
        print("Client of msgchan disconnected")
        self.sendMessage(json.dumps(["on_disconnect", None, []]))

class JMClientProtocolFactory(Factory):
    def __init__(self, role, event_callbacks=None, msgchan=None):
        self.role = role
        self.msgchan = msgchan
        self.event_callbacks = event_callbacks
    def buildProtocol(self, addr):
        return JMClientProtocol(self.role, self.event_callbacks, self.msgchan)

def gotProtocol(p):
    """Just for testing
    """
    p.sendMessage(json.dumps([-100, "backendnick", ["MSGCHAN"]]))
    print("Backend is ready")

if __name__ == "__main__":
    role = sys.argv[1]
    print("using role: " + role)
    
    point = TCP4ClientEndpoint(reactor, "localhost", 1234)
    d = point.connect(JMClientProtocolFactory(role))
    d.addCallback(gotProtocol)
    reactor.run()