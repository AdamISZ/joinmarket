#! /usr/bin/env python
from __future__ import absolute_import, print_function

'''Bundled all code to run a test of multiple ygs and one
sendpayment, all messaging done over HS. The message channel
interface is implemented in joinmarket/hsmc.py.
'''

import datetime
import os
import time
import binascii
import tempfile
import functools
import json
import base64

import bitcoin as btc
from joinmarket import Maker
from joinmarket import Taker
from joinmarket import BlockrInterface
from joinmarket import jm_single, get_network, load_program_config
from joinmarket import random_nick, validate_address
from joinmarket import get_log, calc_cj_fee, debug_dump_object, get_p2pk_vbyte
from joinmarket import choose_sweep_orders, choose_orders, pick_order, \
     cheapest_order_choose, weighted_order_choose
from joinmarket import Wallet
from joinmarket.wallet import estimate_tx_fee
from joinmarket.message_channel import MessageChannel, CJPeerError
from joinmarket.support import chunks
from joinmarket.hsmc import JMHSPeer
from joinmarket.tor import tconfig, start_tor

from twisted.internet import reactor
from twisted.python import log as tlog
from twisted.internet import task

import random

from pprint import pformat

log = get_log()
# thread which does the buy-side algorithm
# chooses which coinjoins to initiate and when
class PT(object):

    def __init__(self, taker):
        self.taker = taker
        self.ignored_makers = []

    def create_tx(self):
        crow = self.taker.db.execute(
            'SELECT COUNT(DISTINCT counterparty) FROM orderbook;').fetchone()
        counterparty_count = crow['COUNT(DISTINCT counterparty)']
        counterparty_count -= len(self.ignored_makers)
        if counterparty_count < self.taker.makercount:
            print('not enough counterparties to fill order, ending')
            self.taker.msgchan.shutdown()
            return

        utxos = None
        orders = None
        cjamount = 0
        change_addr = None
        choose_orders_recover = None
        if self.taker.amount == 0:
            utxos = self.taker.wallet.get_utxos_by_mixdepth()[
                self.taker.mixdepth]
            #do our best to estimate the fee based on the number of
            #our own utxos; this estimate may be significantly higher
            #than the default set in option.txfee * makercount, where
            #we have a large number of utxos to spend. If it is smaller,
            #we'll be conservative and retain the original estimate.
            est_ins = len(utxos)+3*self.taker.makercount
            log.debug("Estimated ins: "+str(est_ins))
            est_outs = 2*self.taker.makercount + 1
            log.debug("Estimated outs: "+str(est_outs))
            estimated_fee = estimate_tx_fee(est_ins, est_outs)
            log.debug("We have a fee estimate: "+str(estimated_fee))
            log.debug("And a requested fee of: "+str(
                self.taker.txfee * self.taker.makercount))
            if estimated_fee > self.taker.makercount * self.taker.txfee:
                #both values are integers; we can ignore small rounding errors
                self.taker.txfee = estimated_fee / self.taker.makercount
            total_value = sum([va['value'] for va in utxos.values()])
            orders, cjamount = choose_sweep_orders(
                self.taker.db, total_value, self.taker.txfee,
                self.taker.makercount, self.taker.chooseOrdersFunc,
                self.ignored_makers)
            if not orders:
                raise Exception("Could not find orders to complete transaction.")
            if not self.taker.answeryes:
                total_cj_fee = total_value - cjamount - \
                    self.taker.txfee*self.taker.makercount
                log.debug('total cj fee = ' + str(total_cj_fee))
                total_fee_pc = 1.0 * total_cj_fee / cjamount
                log.debug('total coinjoin fee = ' + str(float('%.3g' % (
                    100.0 * total_fee_pc))) + '%')
                check_high_fee(total_fee_pc)
                if raw_input('send with these orders? (y/n):')[0] != 'y':
                    self.taker.msgchan.shutdown()
                    return
        else:
            orders, total_cj_fee = self.sendpayment_choose_orders(
                self.taker.amount, self.taker.makercount)
            if not orders:
                log.debug(
                    'ERROR not enough liquidity in the orderbook, exiting')
                return
            total_amount = self.taker.amount + total_cj_fee + \
	        self.taker.txfee*self.taker.makercount
            print('total estimated amount spent = ' + str(total_amount))
            #adjust the required amount upwards to anticipate a tripling of 
            #transaction fee after re-estimation; this is sufficiently conservative
            #to make failures unlikely while keeping the occurence of failure to
            #find sufficient utxos extremely rare. Indeed, a tripling of 'normal'
            #txfee indicates undesirable behaviour on maker side anyway.
            utxos = self.taker.wallet.select_utxos(self.taker.mixdepth, 
                total_amount+2*self.taker.txfee*self.taker.makercount)
            cjamount = self.taker.amount
            change_addr = self.taker.wallet.get_internal_addr(self.taker.mixdepth)
            choose_orders_recover = self.sendpayment_choose_orders

        self.taker.start_cj(self.taker.wallet, cjamount, orders, utxos,
			self.taker.destaddr, change_addr, 
                         self.taker.makercount*self.taker.txfee,
                            self.finishcallback, choose_orders_recover)

    def finishcallback(self, coinjointx):
        if coinjointx.all_responded:
            pushed = coinjointx.self_sign_and_push()
            if pushed:
                log.debug('created fully signed tx, ending')
            else:
                #Error should be in log, will not retry.
                log.debug('failed to push tx, ending.')
            self.taker.msgchan.shutdown()
            return
        self.ignored_makers += coinjointx.nonrespondants
        log.debug('recreating the tx, ignored_makers=' + str(
            self.ignored_makers))
        self.create_tx()

    def sendpayment_choose_orders(self,
                                  cj_amount,
                                  makercount,
                                  nonrespondants=None,
                                  active_nicks=None):
        if nonrespondants is None:
            nonrespondants = []
        if active_nicks is None:
            active_nicks = []
        self.ignored_makers += nonrespondants
        orders, total_cj_fee = choose_orders(
            self.taker.db, cj_amount, makercount, self.taker.chooseOrdersFunc,
            self.ignored_makers + active_nicks)
        if not orders:
            return None, 0
        print('chosen orders to fill ' + str(orders) + ' totalcjfee=' + str(
            total_cj_fee))
        if not self.taker.answeryes:
            if len(self.ignored_makers) > 0:
                noun = 'total'
            else:
                noun = 'additional'
            total_fee_pc = 1.0 * total_cj_fee / cj_amount
            log.debug(noun + ' coinjoin fee = ' + str(float('%.3g' % (
                100.0 * total_fee_pc))) + '%')
            check_high_fee(total_fee_pc)
            if raw_input('send with these orders? (y/n):')[0] != 'y':
                log.debug('ending')
                self.taker.msgchan.shutdown()
                return None, -1
        return orders, total_cj_fee

    def run(self):
        print('waiting for all orders to certainly arrive')
        time.sleep(self.taker.waittime)
        self.create_tx()

class SendPayment(Taker):

    def __init__(self, msgchan, wallet, destaddr, amount, makercount, txfee,
                 waittime, mixdepth, answeryes, chooseOrdersFunc):
        Taker.__init__(self, msgchan)
        self.wallet = wallet
        self.destaddr = destaddr
        self.amount = amount
        self.makercount = makercount
        self.txfee = txfee
        self.waittime = waittime
        self.mixdepth = mixdepth
        self.answeryes = answeryes
        self.chooseOrdersFunc = chooseOrdersFunc

    def on_welcome(self):
        Taker.on_welcome(self)


class YieldGenerator(Maker):
    statement_file = os.path.join('logs', 'yigen-statement.csv')

    def __init__(self, msgchan, wallet):
        Maker.__init__(self, msgchan, wallet)
        self.msgchan.register_channel_callbacks(self.on_welcome,
                                                self.on_set_topic, None, None,
                                                self.on_nick_leave, None)
        self.tx_unconfirm_timestamp = {}

    def log_statement(self, data):
        if get_network() == 'testnet':
            return

        data = [str(d) for d in data]
        self.income_statement = open(self.statement_file, 'a')
        self.income_statement.write(','.join(data) + '\n')
        self.income_statement.close()

    def on_welcome(self):
        Maker.on_welcome(self)
        if not os.path.isfile(self.statement_file):
            self.log_statement(
                ['timestamp', 'cj amount/satoshi', 'my input count',
                 'my input value/satoshi', 'cjfee/satoshi', 'earned/satoshi',
                 'confirm time/min', 'notes'])

        timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        self.log_statement([timestamp, '', '', '', '', '', '', 'Connected'])

    def create_my_orders(self):
        print("starting create my orders")
        mix_balance = self.wallet.get_balance_by_mixdepth()
        if len([b for m, b in mix_balance.iteritems() if b > 0]) == 0:
            print('do not have any coins left')
            return []

        # print mix_balance
        max_mix = max(mix_balance, key=mix_balance.get)
        order = {'oid': 0,
                 'ordertype': 'relorder',
                 'minsize': minsize,
                 'maxsize': mix_balance[max_mix] - jm_single().DUST_THRESHOLD,
                 'txfee': txfee,
                 'cjfee': cjfee}
        print("got this order: ")
        print(str(order))

        # sanity check
        assert order['minsize'] >= 0
        assert order['maxsize'] > 0
        assert order['minsize'] <= order['maxsize']

        return [order]

    def oid_to_order(self, cjorder, oid, amount):
        total_amount = amount + cjorder.txfee
        mix_balance = self.wallet.get_balance_by_mixdepth()
        max_mix = max(mix_balance, key=mix_balance.get)

        filtered_mix_balance = [m
                                for m in mix_balance.iteritems()
                                if m[1] >= total_amount]
        log.debug('mix depths that have enough = ' + str(filtered_mix_balance))
        filtered_mix_balance = sorted(filtered_mix_balance, key=lambda x: x[0])
        mixdepth = filtered_mix_balance[0][0]
        log.debug('filling offer, mixdepth=' + str(mixdepth))

        # mixdepth is the chosen depth we'll be spending from
        cj_addr = self.wallet.get_internal_addr((mixdepth + 1) %
                                                self.wallet.max_mix_depth)
        change_addr = self.wallet.get_internal_addr(mixdepth)

        utxos = self.wallet.select_utxos(mixdepth, total_amount)
        my_total_in = sum([va['value'] for va in utxos.values()])
        real_cjfee = calc_cj_fee(cjorder.ordertype, cjorder.cjfee, amount)
        change_value = my_total_in - amount - cjorder.txfee + real_cjfee
        if change_value <= jm_single().DUST_THRESHOLD:
            log.debug(('change value={} below dust threshold, '
                       'finding new utxos').format(change_value))
            try:
                utxos = self.wallet.select_utxos(
                    mixdepth, total_amount + jm_single().DUST_THRESHOLD)
            except Exception:
                log.debug('dont have the required UTXOs to make a '
                          'output above the dust threshold, quitting')
                return None, None, None

        return utxos, cj_addr, change_addr

    def on_tx_unconfirmed(self, cjorder, txid, removed_utxos):
        self.tx_unconfirm_timestamp[cjorder.cj_addr] = int(time.time())
        # if the balance of the highest-balance mixing depth change then
        # reannounce it
        oldorder = self.orderlist[0] if len(self.orderlist) > 0 else None
        neworders = self.create_my_orders()
        if len(neworders) == 0:
            return [0], []  # cancel old order
        # oldorder may not exist when this is called from on_tx_confirmed
        if oldorder:
            if oldorder['maxsize'] == neworders[0]['maxsize']:
                return [], []  # change nothing
        # announce new order, replacing the old order
        return [], [neworders[0]]

    def on_tx_confirmed(self, cjorder, confirmations, txid):
        if cjorder.cj_addr in self.tx_unconfirm_timestamp:
            confirm_time = int(time.time()) - self.tx_unconfirm_timestamp[
                cjorder.cj_addr]
        else:
            confirm_time = 0
        timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        self.log_statement([timestamp, cjorder.cj_amount, len(
            cjorder.utxos), sum([av['value'] for av in cjorder.utxos.values(
            )]), cjorder.real_cjfee, cjorder.real_cjfee - cjorder.txfee, round(
                confirm_time / 60.0, 2), ''])
        return self.on_tx_unconfirmed(cjorder, txid, None)

def make_wallets(n, wallet_structures=None, mean_amt=1, sdev_amt=0, start_index=0):
    '''n: number of wallets to be created
       wallet_structure: array of n arrays , each subarray
       specifying the number of addresses to be populated with coins
       at each depth (for now, this will only populate coins into 'receive' addresses)
       mean_amt: the number of coins (in btc units) in each address as above
       sdev_amt: if randomness in amouts is desired, specify here.
       Returns: a dict of dicts of form {0:{'seed':seed,'wallet':Wallet object},1:..,}'''
    if len(wallet_structures) != n:
        raise Exception("Number of wallets doesn't match wallet structures")
    seeds = chunks(binascii.hexlify(os.urandom(15 * n)), n)
    wallets = {}
    for i in range(n):
        wallets[i+start_index] = {'seed': seeds[i],
                      'wallet': Wallet(seeds[i],
                                              max_mix_depth=5)}
        for j in range(5):
            for k in range(wallet_structures[i][j]):
                deviation = sdev_amt * random.random()
                amt = mean_amt - sdev_amt / 2.0 + deviation
                if amt < 0: amt = 0.001
                print('adding coins to address: '+str(amt))
                jm_single().bc_interface.grab_coins(
                    wallets[i+start_index]['wallet'].get_external_addr(j), amt)
    return wallets

def init_peers(result):
    print("Starting init peers")
    task.deferLater(reactor, 1, peers[0].hspeer_run, [], tconfig, 0)
    peers[0].hs_init_privkey(tconfig.HiddenServices[0].dir)
    seed_pubkey = binascii.hexlify(peers[0].hs_get_pubkeyDER())
    print("Got seed pubkey: " + str(seed_pubkey))
    for i in range(1, Npeers):
        task.deferLater(reactor, 3, peers[i].hspeer_run,
                        [("SEED1", hs_public_ports[0], seed_pubkey)], tconfig, i)

def start_jm(result):

    if isinstance(jm_single().bc_interface, BlockrInterface):
        c = ('\nYou are running a yield generator by polling the blockr.io '
             'website. This is quite bad for privacy. That site is owned by '
             'coinbase.com Also your bot will run faster and more efficently, '
             'you can be immediately notified of new bitcoin network '
             'information so your money will be working for you as hard as '
             'possibleLearn how to setup JoinMarket with Bitcoin Core: '
             'https://github.com/chris-belcher/joinmarket/wiki/Running'
             '-JoinMarket-with-Bitcoin-Core-full-node')
        print(c)
        ret = raw_input('\nContinue? (y/n):')
        if ret[0] != 'y':
            exit(0)
    
    wallet_structures = [[1, 0, 0, 0, 0]] * (Npeers-1)
    wallets = make_wallets(Npeers-1,wallet_structures=wallet_structures,
                                            mean_amt=10)
    
    for k, v in wallets.iteritems():
        log.debug('starting yield generator')
        jm_single().bc_interface.sync_wallet(wallets[k]['wallet'])
        jm_single().bc_interface.sync_wallet(wallets[k]['wallet'])
    
    
    
    for i in range(1, Npeers-1):
        maker = YieldGenerator(peers[i], wallets[i-1]['wallet'])

    dest_address = btc.privkey_to_address(os.urandom(32), get_p2pk_vbyte())
    addr_valid, errormsg = validate_address(dest_address)
    amount = 100000000
    if not addr_valid:
        print('ERROR: Address invalid. ' + errormsg)
        reactor.stop()
    
    chooseOrdersFunc = weighted_order_choose
    
    log.debug('starting sendpayment')
    
    taker = SendPayment(peers[-1], wallets[Npeers-2]['wallet'], dest_address, amount, 3,
                        5000, 1, 0,
                        True, chooseOrdersFunc)
    
    pt = PT(taker)
    task.deferLater(reactor, 85, pt.run)

Npeers = 5
hs_port_start = 9876
hs_ports = []
hs_public_ports = []
hs_temps = []

txfee = 1000
cjfee = '0.002'  # 0.2% fee
jm_single().nickname = random_nick()

# minimum size is such that you always net profit at least 20% of the miner fee
minsize = int(1.2 * txfee / float(cjfee))

mix_levels = 5

load_program_config()

for i in range(Npeers):
    hs_ports.append(hs_port_start+i)
    hs_public_ports.append(8080+i)

peers = []
#Set up a static seed node peer
peers.append(JMHSPeer(hs_public_ports[0], [], fixed_name="SEED1"))

for i in range(1, Npeers):
    peers.append(JMHSPeer(hs_public_ports[i], []))

d = start_tor(peers, hs_public_ports, hs_ports)
d.addCallback(init_peers)
d.addCallback(start_jm)

tlog.startLogging(open('hsexptlog0.txt', 'w'))

reactor.run()
