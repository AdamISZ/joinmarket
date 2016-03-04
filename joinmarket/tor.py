#! /usr/bin/env python
from __future__ import absolute_import, print_function

import txtorcon
import tempfile
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.web import server, resource
import functools

# HS configuration
tconfig = txtorcon.TorConfig()
tconfig.SOCKSPort = 9150
tconfig.ORPort = 9089

def updates(prog, tag, summary):
    print("%d%%: %s" % (prog, summary))

def setup_complete(peer, i, public_port, proto):
    peer.tor_is_ready = True
    onion_address = tconfig.HiddenServices[i].hostname

    print("I have a hidden (web) service running at:")
    print("http://%s (port %d)" % (onion_address, public_port))
    print("The temporary directory for it is at:", tconfig.HiddenServices[i].dir)

def setup_failed(arg):
    print("SETUP FAILED", arg)
    reactor.stop()

def start_tor(peers, hs_public_ports, hs_ports):
    for i, peer in enumerate(peers):
        hs_temp = tempfile.mkdtemp(prefix='torhiddenservice')
        tconfig.HiddenServices.append(
                txtorcon.HiddenService(
                    tconfig,
                    hs_temp,
                    ["%d 127.0.0.1:%d" % (hs_public_ports[i], hs_ports[i])]
                )
            )
        reactor.addSystemEventTrigger(
                'before', 'shutdown',
                functools.partial(
                    txtorcon.util.delete_file_or_tree,
                    hs_temp
                )
        ) 

    tconfig.save()    
    # set up HS server, start Tor
    for i, peer in enumerate(peers):
        site = server.Site(peer)
        hs_endpoint = TCP4ServerEndpoint(reactor, hs_ports[i], interface='127.0.0.1')
        hs_endpoint.listen(site)
    d = txtorcon.launch_tor(tconfig, reactor, progress_updates=updates)
    #add chain of callbacks for actions after Tor is set up correctly.
    for i, peer in enumerate(peers):
        d.addCallback(functools.partial(setup_complete, peer,
                                        i, hs_public_ports[i]))
        d.addErrback(setup_failed)
    return d