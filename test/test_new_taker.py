#!/usr/bin/env python
from __future__ import print_function
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from commontest import local_command, make_wallets
import os
import shutil
import pytest
import time
from joinmarket import (Taker, load_program_config,
                        BitcoinCoreWallet, JMClientProtocolFactory)
from joinmarket import validate_address, jm_single, get_irc_mchannels
from joinmarket import get_p2pk_vbyte
from joinmarket import get_log, choose_sweep_orders, choose_orders, \
    pick_order, cheapest_order_choose, weighted_order_choose, debug_dump_object
import json
import bitcoin as btc
log = get_log()

def connect_to_daemon(p):
    p.sendMessage(json.dumps([-100, "mynick", ["TAKER"]]))


class SendPayment(Taker):

    def __init__(self, wallet, destaddr, amount, makercount, txfee,
                 waittime, mixdepth, answeryes, chooseOrdersFunc):
        Taker.__init__(self, wallet)
        self.destaddr = destaddr
        self.amount = amount
        self.makercount = makercount
        self.txfee = txfee
        self.waittime = waittime
        self.mixdepth = mixdepth
        self.answeryes = answeryes
        self.chooseOrdersFunc = chooseOrdersFunc

    def on_welcome(self):
        print('waiting for all orders to certainly arrive')
        time.sleep(self.taker.waittime)
        self.create_tx()
    
    def create_tx(self):
        crow = self.db.execute(
            'SELECT COUNT(DISTINCT counterparty) FROM orderbook;').fetchone()
        counterparty_count = crow['COUNT(DISTINCT counterparty)']
        counterparty_count -= len(self.ignored_makers)
        if counterparty_count < self.makercount:
            print('not enough counterparties to fill order, ending')
            #TODO fire close connection
            return

        utxos = None
        orders = None
        cjamount = 0
        change_addr = None
        choose_orders_recover = None
        if self.taker.amount == 0:
            utxos = self.wallet.get_utxos_by_mixdepth()[self.mixdepth]
            #do our best to estimate the fee based on the number of
            #our own utxos; this estimate may be significantly higher
            #than the default set in option.txfee * makercount, where
            #we have a large number of utxos to spend. If it is smaller,
            #we'll be conservative and retain the original estimate.
            est_ins = len(utxos)+3*self.makercount
            log.debug("Estimated ins: "+str(est_ins))
            est_outs = 2*self.makercount + 1
            log.debug("Estimated outs: "+str(est_outs))
            estimated_fee = estimate_tx_fee(est_ins, est_outs)
            log.debug("We have a fee estimate: "+str(estimated_fee))
            log.debug("And a requested fee of: "+str(
                self.txfee * self.makercount))
            if estimated_fee > self.makercount * self.txfee:
                #both values are integers; we can ignore small rounding errors
                self.txfee = estimated_fee / self.makercount
            total_value = sum([va['value'] for va in utxos.values()])
            orders, cjamount, total_cj_fee = choose_sweep_orders(
                self.db, total_value, self.txfee,
                self.makercount, self.chooseOrdersFunc,
                self.ignored_makers)
            if not orders:
                raise Exception("Could not find orders to complete transaction.")
            if not self.answeryes:
                log.debug('total cj fee = ' + str(total_cj_fee))
                total_fee_pc = 1.0 * total_cj_fee / cjamount
                log.debug('total coinjoin fee = ' + str(float('%.3g' % (
                    100.0 * total_fee_pc))) + '%')
                check_high_fee(total_fee_pc)
                if raw_input('send with these orders? (y/n):')[0] != 'y':
                    print("you chose no")
                    #TODO shut connection
                    return
        else:
            orders, total_cj_fee = self.sendpayment_choose_orders(
                self.amount, self.makercount)
            if not orders:
                log.debug(
                    'ERROR not enough liquidity in the orderbook, exiting')
                return
            total_amount = self.amount + total_cj_fee + \
	        self.txfee*self.makercount
            print('total estimated amount spent = ' + str(total_amount))
            #adjust the required amount upwards to anticipate an increase in 
            #transaction fees after re-estimation; this is sufficiently conservative
            #to make failures unlikely while keeping the occurence of failure to
            #find sufficient utxos extremely rare. Indeed, a doubling of 'normal'
            #txfee indicates undesirable behaviour on maker side anyway.
            utxos = self.wallet.select_utxos(self.mixdepth, 
                total_amount+self.txfee*self.makercount)
            cjamount = self.amount
            change_addr = self.wallet.get_internal_addr(self.mixdepth)
            choose_orders_recover = self.sendpayment_choose_orders

        self.start_cj(self.taker.wallet, cjamount, orders, utxos,
			self.taker.destaddr, change_addr, 
                         self.taker.makercount*self.taker.txfee,
                            self.finishcallback, choose_orders_recover)

@pytest.mark.parametrize(
    "num_ygs, wallet_structures, mean_amt, mixdepth, sending_amt, ygcfs, fails, donate, rpcwallet",
    [
        (4, [[1, 0, 0, 0, 0]] * 5, 10, 0, 100000000, None, None, None, True),
    ])
def test_sendpayment(setup_regtest, num_ygs, wallet_structures, mean_amt,
                     mixdepth, sending_amt, ygcfs, fails, donate, rpcwallet):
    """Test of sendpayment code, with yield generators in background.
    """
    log = get_log()
    makercount = num_ygs
    answeryes = True
    txfee = 5000
    waittime = 5
    amount = sending_amt
    wallets = make_wallets(makercount + 1,
                           wallet_structures=wallet_structures,
                           mean_amt=mean_amt)
    #the sendpayment bot uses the last wallet in the list
    if not rpcwallet:
        wallet = wallets[makercount]['wallet']
    else:
        wallet = BitcoinCoreWallet(fromaccount="")

    time.sleep(2)
    if donate:
        destaddr = None
    else:
        destaddr = btc.privkey_to_address(
            os.urandom(32),
            from_hex=False,
            magicbyte=get_p2pk_vbyte())
        addr_valid, errormsg = validate_address(destaddr)
        assert addr_valid, "Invalid destination address: " + destaddr + \
           ", error message: " + errormsg

    #TODO paramatetrize this as a test variable
    chooseOrdersFunc = weighted_order_choose

    log.debug('starting sendpayment')

    jm_single().bc_interface.sync_wallet(wallet)
    taker = SendPayment(wallet, destaddr, amount, makercount-2, txfee, waittime,
                            mixdepth, answeryes, chooseOrdersFunc)
    point = TCP4ClientEndpoint(reactor, "localhost", 1234)
    #pass the taker's callbacks into the joinmarket protocol client
    d = point.connect(JMClientProtocolFactory("TAKER",
                                                  event_callbacks=taker.callbackdata))


    log.debug('starting message channels')

    d.addCallback(connect_to_daemon)
    
    reactor.run()
    


@pytest.fixture(scope="module")
def setup_regtest():
    load_program_config()

if __name__ == "__main__":
    
    jm_single().bc_interface.sync_wallet(wallet)    
    point = TCP4ClientEndpoint(reactor, "localhost", 1234)
    #pass the taker's callbacks into the joinmarket protocol client
    d = point.connect(JMClientProtocolFactory("TAKER",
                                              event_callbacks=taker.callbackdata))
    #dont really want to start immediately, factor out sendpayment etc
    cj_amount = 10000000
    orders = {"abc":{"oid": 0, "amount": 100000000000}}
    input_utxos = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0"]
    my_cj_addr = "197NZoEKi1QhAGv4A5UsaVC53yFJVQSbTx"
    my_change_addr = "1EKF1HDKSDaMNy45RB8pdv4D2oNXXahkwy"
    total_txfee = 10000
    
    