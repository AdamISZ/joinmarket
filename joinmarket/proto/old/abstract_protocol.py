#! /usr/bin/env python
from __future__ import absolute_import, print_function
import abc

"""Abstract base class for protocol flow control for joinmarket.
"""

class JMProtocolError(Exception):
    pass

class AbstractNPartyProtocol(object):
    """Controls flow of events in a messaging protocol
    between multiple parties engaged in simultaneous 2-way
    conversations, while also allowing events which
    are not stateful (and not necessarily associated with
    one of the parties). Parties must be identified by "nick"
    variables.
    The instantiating class must define a class variable
    "events" which has format: a dict whose keys are integers
    and whose values take the form:
    [name (string), repeats_allowed (boolean), stateful (boolean)]
    Stateful events must proceed in the sequence defined by the
    keys (integers), allowing for repeats according to repeats_allowed.
    """
    __metaclass__ = abc.ABCMeta
    
    #TO BE IMPLEMENTED BY SUBCLASSES
    #===============================
    @abc.abstractmethod
    def get_sending_events(self):
        pass
    
    @abc.abstractmethod
    def get_initial_event(self):
        pass
    
    @abc.abstractmethod
    def process_error(self, event, nick):
        pass
    
    @abc.abstractmethod
    def msg_send(self, event, msgargs):
        pass
    #==============================

    def next_good_event(self, nick):
        """Returns the next event index after the current event
        which is stateful and not an error.
        """
        e = self.current_event[nick]
        while True:
            e += 1
            if e not in self.events:
                return None
            if e not in self.error_events and self.events[e][2]:
                return e
            
    def receive_event(self, event_received, nick=None, msgargs=[]):
        """Receives an event from either side of the protocol.
        Returns (False, errormsg) if the event was not processed successfully,
        and blocks any further protocol flow for this instance.
        Otherwise returns (True,)
        If nick is None, there is only one protocol flow and this one is followed.
        If nick is not None, follows protocol flow maintained for that specific
        nick (thus allowing one party (e.g. JM Maker) to maintain state for
        multiple counterparties simultaneously).
        For stateless events, nick is not relevant as no protocol flow occurs.
        """
        if nick not in self.current_event:
            self.current_event[nick] = self.get_initial_event()        
        repeats_allowed = self.events[self.current_event[nick]][1]
        stateful = self.events[event_received][2]
        if nick not in self.event_history:
            self.event_history[nick] = []
        self.event_history[nick].append(event_received)
        allowed = False
        if not stateful:
            #No protocol sequence check required, current_event does not change
            allowed = True
        #State machine blocks changes after errors (they are terminal):
        if self.current_event[nick] in self.error_events and stateful:
            return (False, "In error condition: " + str(
                self.current_event[nick]) + ", cannot continue.")
        #Special cases: 
        #Last possible stateful event blocks any more stateful events.
        if self.current_event[nick] == sorted(self.events.keys())[-1] and stateful:
            return (False, "Received event out of order, ignoring")
        #Explicit error conditions
        if event_received in self.error_events:
            #will block any further process flow:
            self.current_event[nick] = event_received
            return (False, self.process_error(event_received, nick))
        #Check sequence flow
        if event_received == self.current_event[nick] and repeats_allowed:
            allowed = True
        #if it's not a repeat, it must be the next non-error event
        if event_received == self.next_good_event(nick):
            allowed = True
        if allowed:
            #Expected process flow; sending events are sent to the
            #message channel, others progress to the next protocol step.
            #OK to overwrite if repeat; stateless events have no effect.
            if stateful:
                self.current_event[nick] = event_received
            return (True,)
        return (False, "Protocol rule violation")
