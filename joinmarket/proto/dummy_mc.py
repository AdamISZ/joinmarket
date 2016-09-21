#!/usr/bin/env python
from __future__ import print_function
import time

class DummyMC(object):
    def __init__(self, role):
        self.role = role

    def register_callbacks(self, on_pubmsg=None,
                           on_privmsg=None,
                           on_connect=None,
                           on_disconnect=None):
        self.on_pubmsg = on_pubmsg
        self.on_privmsg = on_privmsg
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
    
    def send_pubmsg(self, msg):
        print("Sent msg ", msg, " to channel")
    
    def send_privmsg(self, nick, msg):
        print("Sent msg ", msg, " to nick ", nick)
    
    def run(self):
        time.sleep(2)
        self.on_connect()
        for i in range(6):
            time.sleep(2)
            print("Calling self.onpubmsg")
            self.on_pubmsg("dummynick", "!reloffer 0 111 11111111111 2000 0.001")
            time.sleep(2)
            self.on_privmsg("dummynick2", "!reloffer 0 111 11111111111 1000 100")
        self.on_disconnect()
        