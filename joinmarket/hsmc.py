#!/usr/bin/env python

# Here we set up a Twisted Web server and then launch a slave tor
# with a configured hidden service directed at the Web server we set
# up.

import tempfile
import functools
import time
import json
import base64
import subprocess
import os
from hashlib import sha1
import binascii

from StringIO import StringIO
from twisted.internet import reactor, defer
from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint
from twisted.web import server, resource
from twisted.python import log as tlog

import random
import txtorcon
from txsocksx.http import SOCKS5Agent

from pprint import pformat

from twisted.web.client import Agent, readBody, FileBodyProducer
from twisted.web.http_headers import Headers
from twisted.internet import task
from joinmarket.configure import jm_single, get_config_irc_channel
from joinmarket.message_channel import MessageChannel, CJPeerError
from joinmarket import random_nick
from hashlib import sha256
#from enc_wrapper import encrypt_encode, decode_decrypt
from joinmarket.support import get_log, chunks

openssl_path = 'openssl'

#utility functions

def retry(times, func, *args, **kwargs):
    """retry a defer function
    @param times: how many times to retry
    @param func: defer function
    """
    errorList = []
    deferred = defer.Deferred()
    def run():
        #print('Trying: ', func.__name__)
        d = func(*args, **kwargs)
        d.addCallbacks(deferred.callback, error)
    def error(error):
        errorList.append(error)
        print(str(error))
        #print('Failed: ', func.__name__, ':', len(errorList), 'times')
        # Retry
        if len(errorList) < times:
            reactor.callLater(10, run)
        # Fail
        else:
            print('Giving up, failed: ' + str(times) + ' times.')
            deferred.errback(errorList)
    run()
    return deferred
        
class HSPeer(resource.Resource):
    '''A class implementing a HS P2P network of
    nodes which share information (but not large datasets)
    and can request state updates over HTTP.
    All JM-specific application logic is deferred to class
    JMHSPeer.
    '''
    isLeaf = True

    def hs_get_pubkeyDER(self):
        '''Extract the RSA public key for this
        hidden service in the required (DER) binary
        format for verifying with openssl; note that the
        firt 22 bytes of DER encoded ASN-1 are *not* included
        in the onion hostname calculation.
        '''
        return subprocess.check_output([openssl_path,
                                            'rsa', '-RSAPublicKey_out', '-in',
                                            self.hs_private_key_location,
                                            '-outform', 'DER', '-pubout'])
    
    def get_onion_for_pubkey(self, pubkey_DER, fmt='hex'):
        '''Given a DER encoded 1024 bit public key,
        calculate the corresponding hidden service url.
        '''
        if fmt=='hex':
            pubkey_DER = binascii.unhexlify(pubkey_DER)
        
        #for reference, see https://msdn.microsoft.com/en-us/library/windows/desktop/bb648645%28v=vs.85%29.aspx
        pubkey_for_hs_name = pubkey_DER[22:]
        
        hashed_pubkey = sha1(pubkey_for_hs_name).digest()[:10]
        #print("Got hashed pubkey: "+binascii.hexlify(hashed_pubkey))
        onion_prefix = base64.b32encode(hashed_pubkey)
        #print("Got onion prefix: "+onion_prefix)
        return onion_prefix.lower() + '.onion'
            
    def hs_verify_signature(self, sig, pubkey, msg):
        '''Openssl requires the pubkey in a specific 
        file format. Hence all the messing about in this
        function. TODO just junk all this openssl stuff and figure out
        how to do the pubkey parsing and sig verif. myself.
        '''
        #Dump pubkey and sig to file for openssl's convenience.
        sigfile_name = sha256(msg + self.peerid).hexdigest()[:16]
        pubkeyfile_name = sha256(pubkey + self.peerid).hexdigest()[:16]
        with open(sigfile_name, 'wb') as f:
            f.write(binascii.unhexlify(sig))
        with open(pubkeyfile_name, 'wb') as f:
            f.write(binascii.unhexlify(pubkey))            

        extracted = subprocess.check_output([openssl_path,
                                              'rsautl','-verify','-inkey',
                                              pubkeyfile_name,
                                              '-keyform','DER', '-pubin',
                                              '-in', sigfile_name])
        os.remove(pubkeyfile_name)
        os.remove(sigfile_name)
        return extracted==sha256(msg).digest()

    def hspeer_setup(self, port, seedpeers, fixed_name=None):
        '''This setup deferred to a distinct method rather than __init__
        to avoid the complexities of super() calls with 
        multiple inheritance.
        '''
        self.port = port
        self.tor_is_ready = False
        self.host = None #will be set after init
        self.peerid = None
        self.peername = random_nick() if not fixed_name else fixed_name
        self.current_peers = []
        self.heartbeat = 5
        self.updates = {}
        self.add_peers(seedpeers)
        self.torEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9150)
        self.agent = SOCKS5Agent(reactor, proxyEndpoint=self.torEndpoint)        
        #self.agent = Agent(reactor)
       
    def check_received(self, server_response, msgtype, u, peer):
        '''Called when peer responds to request.
        Currently does nothing. TODO deal with rejection.
        '''
        if server_response == 'ACK':
            self.log("We received an ACK")
            #self.log(pformat(self.updates))
            #TODO is there some case where this can fail? It can be dealt with,
            #but more important to know why, if so.
            #Answer: if a request is not answered before another request to same
            #(peer, msgtype) is added, the first will be deleted, we'll then
            #receive 2 acks; the first will delete the key and the second will
            #crash the peer.
            #Solution: depends on what model of error handling you want; here,
            #we'll go with a model of try only once and wait for a response,
            #deal with all failures to respond in general. Hence, don't delete
            #the item from the update queue only after a failed ACK, but delete
            #it immediately once sent. So this is commented out and the deletion
            #occurs immediately on send in hspeer_run.
            #del self.updates[self.get_peer_id(*peer)][msgtype]

    def process_heartbeat_response(self, res):
        '''The response to POST /announce.
        All other requests only get some kind of ACK/NACK; 
        but in this case, we expect a two line response:
        1. The list of peers this peer is connected to, each in format: 
        (peer name, peer host, peer port)
        2. The current orderbook of this peer (TODO: this could get unwieldy)
        Note, there is some redundancy in this information, can be used
        for sanity checks.'''
        #self.log(res)
        firstline = res.split('\n')[0]
        newpeers = [tuple(_) for _ in json.loads(firstline)]

        for line in res.split('\n')[1:]:
            self.add_orders(line)
        filtered_peers = [x for x in newpeers if x not in self.current_peers and \
                          self.get_peer_id(*x) != self.peerid]
        self.add_peers(filtered_peers)
        
        #self.log("Here is my orderbook: ")
        #self.log("*********************")
        #self.log(pformat(self.orderbook))

    def cbRequest(self, response, url):
        '''HTTP request callback; read the
        response and return it to the caller.
        TODO probably dont need the add_peer call here.
        '''
        #print 'Response version:', response.version
        #print 'Response code:', response.code
        #print 'Response phrase:', response.phrase
        #print 'Response headers:'
        #print pformat(list(response.headers.getAllRawHeaders()))
        headers = list(response.headers.getAllRawHeaders())
        peerid, host, peername, port, pubkey = self.parseRequestHeaders(
            headers, server=True)
        if not peerid == self.get_peer_id(peername, host, port):
            raise Exception("Invalid peer ID")
        if not self.get_onion_for_pubkey(pubkey)== host:
            raise Exception("Invalid pubkey or onion host")
        self.add_peers([(peername, host, port, pubkey)])
        d = readBody(response)
        return d

    def hs_sign_message(self, data):
        '''Sign a string using the private key for the hidden
        service (this private key is stored in a file in the 
        hidden service temporary directory).
        The sha256 hash of the string is the message signed.
        '''
        datafile_name = sha256(data + self.peerid).hexdigest()[:16]
        with open(datafile_name, 'wb') as f:
            f.write(sha256(data).digest())
        if not self.hs_private_key_location:
            raise Exception("Cannot authorize message to send, no private key")
        data_sig = subprocess.check_output([openssl_path,
                                            'rsautl', '-sign', '-inkey',
                                            self.hs_private_key_location,
                                            '-keyform', 'PEM', '-in',
                                            datafile_name])
        os.remove(datafile_name)
        return data_sig

    def get_url_for_peer(self, peer):
        return 'http://' + str(peer[1] + ':' + str(peer[2]))

    def make_peer_request(self, peer, data):
        '''Bundle python object to be passed in the
        request POST body into a json string, then
        make an HTTP POST to the given peer with that
        json as the body, and adding custom headers
        for identification and authentication of this peer.
        '''
        #self.log("in get server data, got: ")
        #self.log(pformat(data))
        url = self.get_url_for_peer(peer)
        body_string = json.dumps(data)
        #TODO toconsider: rsa sign is slow(ish). issue - but not so much with 1024!
        auth_sig = self.hs_sign_message(self.peerid + body_string)
        body = FileBodyProducer(StringIO(body_string))
        #duckduckgo HS for testing:
        #url = 'http://3g2upl4pq6kufc4m.onion:80'
        #self.log("Requesting with url: "+ url)
        headers = Headers({'User-Agent': ['Twisted Web Client Example'],
                     'Content-Type': ['application/json'],
                     'Onion-Host': [self.host],
                     'Nickname': [self.peername],
                     'Serving-Port': [str(self.port)],
                     'Peer-Id': [self.peerid],
                     'Pubkey': [binascii.hexlify(self.hs_pubkey)],
                     'Peer-Auth': [binascii.hexlify(auth_sig)]})
        
        d = retry(25, self.agent.request, 'POST', url, headers, body)
        d.addCallback(self.cbRequest, url)
        d.addErrback(self.handle_failed_client_request, url, data)
        return d

    def handle_failed_client_request(self, failure, url, data):
        '''Error handling for failed http requests; this
        is not expected to happen frequently, even
        on initial HS setup - because we use a retry method. 
        At the moment we do nothing, but will need to handle
        the complete failure to access a peer TODO.'''
        self.log("In handle failed request for url: "+url)
        self.log(str(failure))
    
    def hs_init_privkey(self, directory):
        '''Given the (temporary) location of the
        hidden service config directory, store the
        location of the private key file for signing.
        '''
        self.hs_private_key_location = os.path.join(
                            directory, 'private_key')        

    def hspeer_run(self, seedpeers=None, config=None, i=None):
        '''Main loop for the peer.
        Regularly ("heartbeat"), poll all peers for updated
        global state (e.g. orderbook for joinmarket).
        Also, if any updates are in update queue, push
        them out to the relevant peer.
        '''
        #This completion of setup is deferred until run-start
        #since HS setup takes a while
        if self.tor_is_ready:
            if i is not None:
                self.log('seed HS is: '+config.HiddenServices[0].hostname)
                self.log('my HS is: '+config.HiddenServices[i].hostname)
                self.log('my HS privkey is at : ' + os.path.join(
                    config.HiddenServices[i].dir, 'private_key'))
                self.hs_init_privkey(config.HiddenServices[i].dir)
                self.hs_pubkey = self.hs_get_pubkeyDER()
                self.set_host(config.HiddenServices[i].hostname)
                
                if seedpeers:
                    seedpeers = [(seedpeers[0][0], seedpeers[0][1],
                                  seedpeers[0][2], seedpeers[0][3])]
                    self.add_peers(seedpeers)
    
            #TODO investigate better algorithms, this may be too "floody" to scale.
            for sp in self.current_peers:
                #self.log("Looking at peer: "+','.join([str(_) for _ in sp]))
                pid = self.get_peer_id(*sp)
                for msgtype, u in self.updates[pid].iteritems():
                    self.log("making request to : "+str(
                        sp[0]) + " for msgtype: "+str(msgtype))
                    d2 = self.make_peer_request(sp, [msgtype, u])
                    d2.addCallback(self.check_received, msgtype, u, sp)
                
                #see detailed comment in self.check_received; only make req. once.
                msgtypes = self.updates[pid].keys()
                #self.log("Looking to delete uqe for peer: "+str(
                #    sp[0]) + " , msgtypes is: "+str(msgtypes))
                for mt in msgtypes:
                    #self.log("Deleting message type: "+str(mt))
                    del self.updates[pid][mt]
    
                base_request = ['announce', self.peername, self.host, self.port,
                                binascii.hexlify(self.hs_pubkey)]
                d = self.make_peer_request(sp, base_request)
                d.addCallback(self.process_heartbeat_response)
            
            #Trigger on_welcome event (hangover from IRC) once only on first arrival.
            if self.on_welcome and not self.on_welcome_sent:
                self.on_welcome()
                self.on_welcome_sent = True

        task.deferLater(reactor, self.heartbeat, self.hspeer_run)

    def broadcast(self, peers, data):
        '''Send client request with payload "data"
        to all peers in the list "peers".
        '''
        self.log("Working with peers: " + str(peers))
        self.log("Working with current peers: "+str(self.current_peers))
        if not set(peers).issubset(set(self.current_peers)):
            self.log("Failed to broadcast to these peers: "+str(peers))
            return
        for peer in peers:
            #TODO this will change to onion host
            #for non-testing
            self.make_peer_request(peer, data)

    def parseRequestHeaders(self, headers, server=False):
        '''Request headers for all requests are required
        to contain this identifying information in custom
        headers.
        If these requests come from "server" (incoming from HS),
        we dont need to do auth.
        '''
        #This fairly disgusting syntax is a result of the weird way headers
        #are stored 
        peerid = filter(lambda x: x[0]=='Peer-Id', headers)[0][1][0]
        host = filter(lambda x: x[0]=='Onion-Host', headers)[0][1][0]
        peername = filter(lambda x: x[0]=='Nickname', headers)[0][1][0]
        port = int(filter(lambda x: x[0]=='Serving-Port', headers)[0][1][0])
        pubkey = filter(lambda x: x[0]=='Pubkey', headers)[0][1][0]
        if not server:
            auth_sig = filter(lambda x: x[0]=='Peer-Auth', headers)[0][1][0]
            return (peerid, host, peername, port, pubkey, auth_sig)
        
        return (peerid, host, peername, port, pubkey)


    def log(self, msg):
        '''This is a twisted specific logging mechanism.
        '''
        tlog.msg('Peer ' + self.peername + ': ' + msg)

    def update_queue_add(self, peerid, msgtype, msg):
        '''Adds request messages to be sent to other
        peers as scheduled in the peer_run method.
        '''
        if peerid not in self.updates.keys():
            self.updates[peerid] = {}
        self.updates[peerid][msgtype] = msg

    def close(self):
        '''Handling shutdown gracefully in twister
        needs some attention (error handling in deferreds).
        Stopping the reactor may be correct, but causes problems
        for tests of multiple bots.'''
        reactor.stop()

    def authorize_peer(self, peerid, host, peername, port, pubkey, auth_sig,
                       rs):
        ''' For incoming requests from "clients", checks
        the onion address and associated details, and the message
        sent is authenticated against that pubkey.
        1 Verify the peer id (this is really a sanity check)
        2 construct the message signed as peerid + received string (rs)
        3 retrieve the correct hostname from the pubkey and cross check.
        4 use openssl to rsa verify (pubkey, message, auth_sig)
        '''
        if not peerid == self.get_peer_id(peername, host, str(port)):
            self.log("Invalid peerid for peer: " + peername)
            return False
        auth_msg = peerid + rs
        if not self.get_onion_for_pubkey(pubkey) == host:
            self.log("Invalid onion host for peer: " + peername)
            return False
        if not self.hs_verify_signature(auth_sig, pubkey, auth_msg):
            self.log("Invalid peer signature for peer: " + peername)
            return False
        return True

    def render_POST(self, request):
        '''Handles requests from peers.
        Request must have specified custom headers
        containing identifying information, and the
        POST contents must be a json object which will
        be interpreted by application level object.
        The request/instruction/update will be authorized
        by authenticating the payload against the peer pubkey
        using a digital signature.
        '''
        #May be useful for testing.
        #req_string = str(request.path.strip("/"))
        #self.log(pformat(list(request.requestHeaders.getAllRawHeaders())))
        
        received_headers = list(request.requestHeaders.getAllRawHeaders())
        peerid, host, peername, port, pubkey, auth_sig = self.parseRequestHeaders(
            received_headers)
        received_str = request.content.read()
        received = json.loads(received_str)
        #self.log("Received this: "+str(received))
        
        #Auth must verify.
        #If fail to verify, return NACK and do nothing (TODO banscore)
        if not self.authorize_peer(peerid, host, peername, port, pubkey,
                                   auth_sig, received_str):
            retval = 'NACK'
        else:
            #Apply application logic here in subclass:
            retval = self.parse_request_payload(received, peerid,
                                                host, peername, port)            
        
        if retval and retval != 'NACK':
            #"server" side of communication does
            #not need the authenticating header (Peer-Auth)
            #since its hostname provides authentication.
            request.setResponseCode(200)
            request.setHeader('User-Agent', 'Twisted Web Server Example')
            request.setHeader('Onion-Host', self.host)
            request.setHeader('Nickname', self.peername)
            request.setHeader('Serving-Port', str(self.port))
            request.setHeader('Peer-Id', self.peerid)
            request.setHeader('Pubkey', binascii.hexlify(self.hs_pubkey))
        else:
            request.setResponseCode(400)
        return retval
    
    def set_host(self, host):
        '''Set the hostname of this peer.
        '''
        self.host = host
        self.peerid = self.get_peer_id(self.peername, self.host, self.port)
    
    def get_peer_from_name(self, peername):
        '''Retrieve entire tuple for a peer from
        only its readable name, assuming it is already
        known by this peer. If no such peer is found,
        return None.
        '''
        peers = [x for x in self.current_peers if x[0]==peername]
        if len(peers) != 1:
            self.log("Failed to find distinct peer")
            self.log("Peers was: " + str(peers))
            self.log("Current peers was: " + str(self.current_peers))
            self.log("Peername was; " + str(peername))
            return None
        return peers[0]

    def get_peer_id(self, readable_name, host=None, port=None, pubkey=None):
        '''Unique ID of peer is used as key for table of potential
        state updates. ID is formed as sha256(nickname|hostname|port)
        '''
        if not host:
            peer = self.get_peer_from_name(readable_name)
            host = peer[1]
            port = peer[2]
        return sha256(readable_name + host + str(port)).hexdigest()[:20]    
    
    def add_peers(self, peers):
        '''Peers have format tuple: 
        (<peer readable name>, <hostname>, <serving port>, <pubkey>)
        '''
        #self.log("Current peers: "+str(self.current_peers))
        #self.log("Were looking to add: "+ str(peers))
        for p in peers:
            #don't add if already here:
            if p in self.current_peers:
                continue
            #self.log("adding this to current_peers: " + str(p))
            self.current_peers.append(p)
            #set up an entry in the updates table,
            #keyed to the peerid
            peerid = self.get_peer_id(*p)
            self.updates[peerid] = {}    
        
class JMHSPeer(MessageChannel, HSPeer):
    '''A class implementing JoinMarket's
    MessageChannel interface using the HSPeer
    hidden service peer to peer network class.
    '''
    isLeaf = True

    def parse_request_payload(self, received, peerid, host, peername, port):
        '''Takes as argument the decoded json object received
        The received object always takes the form: [request type, [parameters]]
        as the body of the HTTP POST request and applies JM logic.
        '''
        
        if received[0]=='announce':
            self.add_peers([(received[1],received[2], received[3], received[4])])
            retval = '\n'.join([json.dumps(self.current_peers),
                              self.get_orderbook()])

        elif received[0]=='cancel':
            #construct key of to-be-deleted entry
            obkey = ','.join([peername, str(received[1][0])])
            #verify this cancellation before taking action
            if not self.hs_verify_signature(received[2], pubkey,
                                    ','.join(received[0], str(received[1][0]))):
                retval = 'NACK'
            else:
                if obkey in self.orderbook.keys():
                    del self.orderbook[obkey]
                    #Authenticated cancels are propagated aggressively;
                    #note we propagate the same exact message, which contains
                    #a signature. Note also we only re-broadcast if the
                    #cancelled order was still here, otherwise remain silent
                    #to avoid infinite rebroadcast.
                    for peer in self.current_peers:
                        self.make_peer_request(peer, received)
                retval = 'ACK'
        
        elif received[0]=='sig':
            sig_list = received[1]
            if self.on_sig:
                for sig in sig_list:
                    self.on_sig(peername, sig)
            retval = 'ACK'

        elif received[0]=='fill':
            self.log("Got this fill request from peer: "+peername)
            self.log(pformat(received[1]))            
            if self.on_order_fill:
                oid, cjamount, taker_pubkey = received[1]
                self.on_order_fill(peername, oid, cjamount, taker_pubkey)
                retval = 'ACK'
            else:
                #TODO distinguish acknowledgement of receipt from rejection
                retval = 'ACK'

        elif received[0]=='tx':
            b64tx = received[1]
            txhex = base64.b64decode(b64tx).encode('hex')
            if self.on_seen_tx:
                self.on_seen_tx(peername, txhex)
            retval = 'ACK'
        
        elif received[0]=='ioauth':
            utxo_list, cj_pub, change_addr, btc_sig = received[1]
            if self.on_ioauth:
                self.on_ioauth(peername, utxo_list, cj_pub, change_addr,
                                                   btc_sig)
            retval = 'ACK'
        
        elif received[0]=='auth':
            pubkey, sig = received[1]
            if self.on_seen_auth:
                self.on_seen_auth(peername, pubkey, sig)
            retval = 'ACK'
        
        elif received[0]=='pubkey':
            pubkey = received[1]
            if self.on_pubkey:
                self.on_pubkey(peername, pubkey)
            retval = 'ACK'
                
        elif received[0]=='message':
            self.log("Received message: "+received[1])
            retval = 'ACK'
        
        elif received[0]=='push':
            b64tx = received[1]
            txhex = base64.b64decode(b64tx).encode('hex')
            if self.on_push_tx:
                self.on_push_tx(peername, txhex)
            retval = 'ACK'

        return retval

    def __init__(self, port, seedpeers, fixed_name = None):
        self.hspeer_setup(port, seedpeers, fixed_name)
        self.orderbook = {}
        self.oid_ctr = -1
        self.add_orders()
        self.on_welcome_sent = False
        super(JMHSPeer, self).__init__()

    def close(self):
        '''Handling shutdown gracefully in twister
        needs some attention (error handling in deferreds)'''
        #For testing, don't stop the reactor.
        #reactor.stop()
        pass

    def shutdown(self):
        '''Not sure the distinction between shutdown
        and close is needed here.
        '''
        self.close()

    def getoid(self):
        '''Primitive order id number
        assignment. TODO consider if need
        to reuse old orderids, as current
        JM code does.'''
        self.oid_ctr += 1
        return self.oid_ctr

    def get_orderbook(self):
        return json.dumps(self.orderbook)

    def request_orderbook(self):
        '''The p2p network keeps the orderbook updated
        dynamically; Im not sure if there is a case for
        sending requests to all peers, or a specified subset,
        for an updated state, since this will be resource
        heavy. If we dont do it, we will need to consider
        out-of-syncness and make sure its handled correctly.
        '''
        self.log("Orderbook requests not needed for HSmc")

    def add_orders(self, orders=None):
        '''None parameter is for testing, to create
        dummy orders. Note that additions to the
        locally stored orderbook occur here and here only.
        '''
        if not orders:
            #Can be useful for testing:
            #orders = self.create_dummy_order()
            return
        o_json = json.loads(orders)
        for k, v in o_json.iteritems():
            #recognize new orders from other peers
            peer = k.split(',')[0]
            if peer != self.peername:
                p = self.get_peer_from_name(peer)
                if not p:
                    self.log("Unrecognized peer: " + peer)
                    continue
                p_pubkey = p[3]
                order_for_verifying = v.copy()
                order_for_verifying.pop('sig')
                #self.log("Going to validate against this signature: " + v['sig'])
                #self.log("With this pubkey: " + p_pubkey)
                #self.log("And this message: " + json.dumps(order_for_verifying, sort_keys=True))
                if not self.hs_verify_signature(v['sig'], 
                                                p_pubkey, 
                                                json.dumps(order_for_verifying,
                                                sort_keys=True)):
                    self.log("Order update not validated for peer: " + peer)
                    continue
                #We now know the order is from another party, and is authenticated
                #to be that exact party, so we can update our local orderbook.
                
                #TODO replay attacks!
                
                #Local update - note this *does* keep the signature key, because
                #we use the original copy of the dict 'v'.
                self.orderbook[k] = v 
                #Trigger upstream change
                if self.on_order_seen:
                    self.on_order_seen(peer, k.split(',')[1],
                                       v['otype'], v['minsize'], v['maxsize'],
                                       v['txfee'], v['cjfee'])
            else:
                #our own updates dont need authentication,
                #and we already made the signature in convert_to_obformat
                self.orderbook[k] = v

    def cancel_orders(self, oid_list):
        '''Remove locally stored entries.
        and broadcast change to all current peers.
        Note that this is a special case of a message
        that should urgently flood-fill the network, so
        we attach an auth signature and peers propagate.
        '''
        for oid in oid_list:
            k = ','.join([self.peername, str(oid)])
            if k not in self.orderbook.keys():
                continue
            #TODO replay attack
            auth_msg = ','.join(['cancel',str(oid)])
            sig = self.hs_sign_message(auth_msg)
            self.broadcast(self.current_peers, ['cancel',
                                                [oid],binascii.hexlify(sig)])
            del self.orderbook[k]

    def send_pubkey(self, nick, pubkey):
        '''Joinmarket callback
        '''
        self.update_queue_add(self.get_peer_id(nick), 'pubkey', pubkey)

    def send_ioauth(self, nick, utxo_list, cj_pubkey, change_addr, sig):
        '''Joinmarket callback
        '''
        authmsg = [utxo_list, cj_pubkey, change_addr, sig]
        self.update_queue_add(self.get_peer_id(nick), 'ioauth', authmsg)

    def send_sigs(self, nick, sig_list):
        '''Joinmarket callback
        '''
        self.update_queue_add(self.get_peer_id(nick), 'sig', sig_list)

    def send_auth(self, nick, pubkey, sig):
        '''Joinmarket callback
        '''
        message = [pubkey, sig]
        self.update_queue_add(self.get_peer_id(nick), 'auth', message)

    def send_tx(self, nick_list, txhex):
        '''Joinmarket callback
        '''
        txb64 = base64.b64encode(txhex.decode('hex'))
        for nick in nick_list:
            self.update_queue_add(self.get_peer_id(nick), 'tx', txb64)
    
    def send_message(self, nick, msg):
        '''Joinmarket callback
        '''
        self.update_queue_add(self.get_peer_id(nick), 'message', msg)

    def push_tx(self, nick, txhex):
        '''Joinmarket callback
        '''        
        txb64 = base64.b64encode(txhex.decode('hex'))
        self.update_queue_add(self.get_peer_id(nick), 'push', txb64)

    def fill_orders(self, nick_order_dict, cj_amount, taker_pubkey):
        '''Joinmarket callback
        '''
        #self.log("In fill orders, nick order dict is: ")
        #self.log(pformat(nick_order_dict))
        for c, order in nick_order_dict.iteritems():
            msg = [order['oid'], cj_amount, taker_pubkey]
            self.update_queue_add(self.get_peer_id(c), 'fill', msg)

    def convert_to_obformat(self, o):
        '''Take orders in the object format used
        by joinmarket and convert them to json for
        propagation on p2p network, also appends 
        signature to authenticate this entry for 
        non-repudiable and non-forgeable broadcast.
        '''
        
        #Current format: order = {'oid': 0, 'ordertype': 'relorder', 'minsize': 0,
        #		'maxsize': total_value, 'txfee': 10000, 'cjfee': '0.002'}
        #Construct signature on order contents:
        order_contents = {'minsize':o['minsize'], 'maxsize':o['maxsize'],
                          'otype':o['ordertype'], 'cjfee':o['cjfee'],
                          'txfee':o['txfee']}
        #self.log("Going to sign this order: " + json.dumps(order_contents, sort_keys=True))
        #self.log("With this pubkey: " + binascii.hexlify(self.hs_pubkey))
        sig = self.hs_sign_message(json.dumps(order_contents, sort_keys=True))
        order_contents['sig'] = binascii.hexlify(sig)
        return {','.join([self.peername, str(o['oid'])]):order_contents}

    def create_dummy_order(self):
        '''For testing
        TODO update if actually needed.
        '''
        #just for testing; random order objects
        min_amt = random.randint(1, 1000)
        max_amt = min_amt + random.randint(1, 1000)
        oid = self.getoid()
        otype = 'relorder'
        fee = random.random()
        txfee = random.randint(1,1000)
        order = json.dumps({','.join(
            [self.peername,str(oid)]):{'minsize':min_amt, 'maxsize':max_amt,
                                       'otype':otype, 'cjfee':fee, 'txfee':txfee}})
        return order

    def announce_orders(self, orderlist, nick=None):
        '''nick parameter is ignored, just compatibility,
        since we dont distinguish public/private announcment.
        Since we use the heartbeat/run to propagate through
        the network, just update the local orderbook.'''
        orders = {}
        for o in orderlist:
            new_order = self.convert_to_obformat(o)
            orders.update(new_order)
        self.add_orders(json.dumps(orders))






