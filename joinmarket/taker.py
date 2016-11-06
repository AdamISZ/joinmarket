#! /usr/bin/env python
from __future__ import absolute_import, print_function

import base64
import pprint
import random
import sqlite3
import sys
import time
import threading
import json
from decimal import InvalidOperation, Decimal

import bitcoin as btc
from joinmarket.configure import jm_single, get_p2pk_vbyte, donation_address
from joinmarket.support import (get_log, calc_cj_fee, weighted_order_choose,
                                choose_orders)
from joinmarket.wallet import estimate_tx_fee
from joinmarket.irc import B_PER_SEC
log = get_log()


class JMTakerError(Exception):
    pass


class OrderbookWatch(object):

    def __init__(self, msgchan):
        self.msgchan = msgchan
        self.msgchan.register_orderbookwatch_callbacks(self.on_order_seen,
                                                       self.on_order_cancel)
        self.msgchan.register_channel_callbacks(
            self.on_welcome, self.on_set_topic, None, self.on_disconnect,
            self.on_nick_leave, None)

        self.dblock = threading.Lock()
        con = sqlite3.connect(":memory:", check_same_thread=False)
        con.row_factory = sqlite3.Row
        self.db = con.cursor()
        self.db.execute("CREATE TABLE orderbook(counterparty TEXT, "
                        "oid INTEGER, ordertype TEXT, minsize INTEGER, "
                        "maxsize INTEGER, txfee INTEGER, cjfee TEXT);")

    @staticmethod
    def on_set_topic(newtopic):
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

    def on_order_seen(self, counterparty, oid, ordertype, minsize, maxsize,
                      txfee, cjfee):
        try:
            self.dblock.acquire(True)
            if int(oid) < 0 or int(oid) > sys.maxint:
                log.debug("Got invalid order ID: " + oid + " from " +
                          counterparty)
                return (False, [])
            # delete orders eagerly, so in case a buggy maker sends an
            # invalid offer, we won't accidentally !fill based on the ghost
            # of its previous message.
            self.db.execute(
                ("DELETE FROM orderbook WHERE counterparty=? "
                 "AND oid=?;"), (counterparty, oid))
            # now validate the remaining fields
            if int(minsize) < 0 or int(minsize) > 21 * 10**14:
                log.debug("Got invalid minsize: {} from {}".format(
                    minsize, counterparty))
                return (False, [])
            if int(minsize) < jm_single().DUST_THRESHOLD:
                minsize = jm_single().DUST_THRESHOLD
                log.debug("{} has dusty minsize, capping at {}".format(
                    counterparty, minsize))
                # do not pass return, go not drop this otherwise fine offer
            if int(maxsize) < 0 or int(maxsize) > 21 * 10**14:
                log.debug("Got invalid maxsize: " + maxsize + " from " +
                          counterparty)
                return (False, [])
            if int(txfee) < 0:
                log.debug("Got invalid txfee: {} from {}".format(txfee,
                                                                 counterparty))
                return (False, [])
            if int(minsize) > int(maxsize):

                fmt = ("Got minsize bigger than maxsize: {} - {} "
                       "from {}").format
                log.debug(fmt(minsize, maxsize, counterparty))
                return (False, [])
            if ordertype == 'absoffer' and not isinstance(cjfee, int):
                try:
                    cjfee = int(cjfee)
                except ValueError:
                    log.debug("Got non integer coinjoin fee: " + str(cjfee) +
                              " for an absoffer from " + counterparty)
                    return (False, [])
            self.db.execute(
                'INSERT INTO orderbook VALUES(?, ?, ?, ?, ?, ?, ?);',
                (counterparty, oid, ordertype, minsize, maxsize, txfee,
                 str(Decimal(cjfee))))  # any parseable Decimal is a valid cjfee
        except InvalidOperation:
            log.debug("Got invalid cjfee: " + cjfee + " from " + counterparty)
        except Exception as e:
            log.debug("Error parsing order " + oid + " from " + counterparty)
            log.debug("Exception was: " + repr(e))
        finally:
            self.dblock.release()
            return (True, [])

    def on_order_cancel(self, counterparty, oid):
        with self.dblock:
            self.db.execute(
                ("DELETE FROM orderbook WHERE "
                 "counterparty=? AND oid=?;"), (counterparty, oid))

    def on_nick_leave(self, nick):
        with self.dblock:
            self.db.execute('DELETE FROM orderbook WHERE counterparty=?;',
                            (nick,))

    def on_disconnect(self):
        with self.dblock:
            self.db.execute('DELETE FROM orderbook;')


#Taker is now a class to do 1 coinjoin
class Taker(object):

    def __init__(self,
                 wallet,
                 mixdepth,
                 amount,
                 n_counterparties,
                 order_chooser=weighted_order_choose,
                 external_addr=None):
        self.wallet = wallet
        self.mixdepth = mixdepth
        self.cjamount = amount
        self.my_cj_addr = external_addr
        self.order_chooser = order_chooser
        self.n_counterparties = n_counterparties
        self.ignored_makers = None
        self.outputs = []
        self.cjfee_total = 0
        self.maker_txfee_contributions = 0
        self.txfee_default = 5000

    def initialize(self, orderbook):
        """Once the daemon is active and has returned the current orderbook,
        select offers and prepare a commitment, then send it to the protocol
        to fill offers.
        """
        self.filter_orderbook(orderbook)
        #choose coins to spend
        self.prepare_my_bitcoin_data()
        #Prepare a commitment
        commitment, revelation = self.make_commitment()
        return (True, self.cjamount, commitment, revelation, self.orderbook)

    def filter_orderbook(self, orderbook):
        self.orderbook, self.total_cj_fee = choose_orders(
            orderbook, self.cjamount, self.n_counterparties, self.order_chooser,
            self.ignored_makers)

    def prepare_my_bitcoin_data(self):
        """Get a coinjoin address and a change address; prepare inputs
        appropriate for this transaction"""
        if not self.my_cj_addr:
            self.my_cj_addr = self.wallet.get_external_addr(
                self.mixdepth + 1)  #TODO
        self.my_change_addr = None
        if self.cjamount != 0:
            self.my_change_addr = self.wallet.get_internal_addr(self.mixdepth)
        #TODO sweep, doesn't apply here
        self.total_txfee = 2 * self.txfee_default * self.n_counterparties
        total_amount = self.cjamount + self.total_cj_fee + self.total_txfee
        print('total estimated amount spent = ' + str(total_amount))
        #adjust the required amount upwards to anticipate an increase in 
        #transaction fees after re-estimation; this is sufficiently conservative
        #to make failures unlikely while keeping the occurence of failure to
        #find sufficient utxos extremely rare. Indeed, a doubling of 'normal'
        #txfee indicates undesirable behaviour on maker side anyway.
        self.input_utxos = self.wallet.select_utxos(self.mixdepth, total_amount)
        if not self.input_utxos:
            raise JMTakerError("Could not find coins")
        self.utxos = {None: self.input_utxos.keys()}

    def receive_utxos(self, ioauth_data):
        """Triggered when the daemon returns utxo data from
        makers who responded; this is the completion of phase 1
        of the protocol
        """
        rejected_counterparties = []
        #Enough data, but need to authorize against the btc pubkey first.
        for nick, nickdata in ioauth_data.iteritems():
            utxo_list, auth_pub, cj_addr, change_addr, btc_sig, maker_pk = nickdata
            if not self.auth_counterparty(btc_sig, auth_pub, maker_pk):
                print("Counterparty encryption verification failed, aborting")
                #This counterparty must be rejected
                rejected_counterparties.append(nick)

        for rc in rejected_counterparties:
            del ioauth_data[rc]

        self.maker_utxo_data = {}

        for nick, nickdata in ioauth_data.iteritems():
            utxo_list, auth_pub, cj_addr, change_addr, btc_sig, maker_pk = nickdata
            self.utxos[nick] = utxo_list
            utxo_data = jm_single().bc_interface.query_utxo_set(self.utxos[
                nick])
            if None in utxo_data:
                log.debug(('ERROR outputs unconfirmed or already spent. '
                           'utxo_data={}').format(pprint.pformat(utxo_data)))
                # when internal reviewing of makers is created, add it here to
                # immediately quit; currently, the timeout thread suffices.
                continue

            #Complete maker authorization:
            #Extract the address fields from the utxos
            #Construct the Bitcoin address for the auth_pub field
            #Ensure that at least one address from utxos corresponds.
            input_addresses = [d['address'] for d in utxo_data]
            auth_address = btc.pubkey_to_address(auth_pub, get_p2pk_vbyte())
            if not auth_address in input_addresses:
                log.warn("ERROR maker's (" + nick + ")"
                         " authorising pubkey is not included "
                         "in the transaction: " + str(auth_address))
                #this will not be added to the transaction, so we will have
                #to recheck if we have enough
                continue

            total_input = sum([d['value'] for d in utxo_data])
            real_cjfee = calc_cj_fee(self.orderbook[nick]['ordertype'],
                                     self.orderbook[nick]['cjfee'],
                                     self.cjamount)
            change_amount = (total_input - self.cjamount -
                             self.orderbook[nick]['txfee'] + real_cjfee)

            # certain malicious and/or incompetent liquidity providers send
            # inputs totalling less than the coinjoin amount! this leads to
            # a change output of zero satoshis; this counterparty must be removed.
            if change_amount < jm_single().DUST_THRESHOLD:
                fmt = ('ERROR counterparty requires sub-dust change. nick={}'
                       'totalin={:d} cjamount={:d} change={:d}').format
                log.debug(fmt(nick, total_input, self.cjamount, change_amount))
                log.warn("Invalid change, too small, nick= " + nick)
                continue

            self.outputs.append({'address': change_addr,
                                 'value': change_amount})
            fmt = ('fee breakdown for {} totalin={:d} '
                   'cjamount={:d} txfee={:d} realcjfee={:d}').format
            log.debug(fmt(nick, total_input, self.cjamount, self.orderbook[
                nick]['txfee'], real_cjfee))
            self.outputs.append({'address': cj_addr, 'value': self.cjamount})
            self.cjfee_total += real_cjfee
            self.maker_txfee_contributions += self.orderbook[nick]['txfee']
            self.maker_utxo_data[nick] = utxo_data

        #Apply business logic of how many counterparties are enough:
        if len(self.maker_utxo_data.keys()) < jm_single().config.getint(
                "POLICY", "minimum_makers"):
            return (False,
                    "Not enough counterparties responded to fill, giving up")

        log.info('got all parts, enough to build a tx')
        self.nonrespondants = list(self.maker_utxo_data.keys())

        my_total_in = sum([va['value'] for u, va in self.input_utxos.iteritems()
                          ])
        if self.my_change_addr:
            #Estimate fee per choice of next/3/6 blocks targetting.
            estimated_fee = estimate_tx_fee(
                len(sum(self.utxos.values(), [])), len(self.outputs) + 2)
            log.info("Based on initial guess: " + str(self.total_txfee) +
                     ", we estimated a miner fee of: " + str(estimated_fee))
            #reset total
            self.total_txfee = estimated_fee
        my_txfee = max(self.total_txfee - self.maker_txfee_contributions, 0)
        my_change_value = (
            my_total_in - self.cjamount - self.cjfee_total - my_txfee)
        #Since we could not predict the maker's inputs, we may end up needing
        #too much such that the change value is negative or small. Note that
        #we have tried to avoid this based on over-estimating the needed amount
        #in SendPayment.create_tx(), but it is still a possibility if one maker
        #uses a *lot* of inputs.
        if self.my_change_addr and my_change_value <= 0:
            raise ValueError("Calculated transaction fee of: " + str(
                self.total_txfee) +
                             " is too large for our inputs;Please try again.")
        elif self.my_change_addr and my_change_value <= jm_single(
        ).BITCOIN_DUST_THRESHOLD:
            log.info("Dynamically calculated change lower than dust: " + str(
                my_change_value) + "; dropping.")
            self.my_change_addr = None
            my_change_value = 0
        log.info(
            'fee breakdown for me totalin=%d my_txfee=%d makers_txfee=%d cjfee_total=%d => changevalue=%d'
            % (my_total_in, my_txfee, self.maker_txfee_contributions,
               self.cjfee_total, my_change_value))
        if self.my_change_addr is None:
            if my_change_value != 0 and abs(my_change_value) != 1:
                # seems you wont always get exactly zero because of integer
                # rounding so 1 satoshi extra or fewer being spent as miner
                # fees is acceptable
                log.debug(('WARNING CHANGE NOT BEING '
                           'USED\nCHANGEVALUE = {}').format(my_change_value))
        else:
            self.outputs.append({'address': self.my_change_addr,
                                 'value': my_change_value})
        self.utxo_tx = [dict([('output', u)])
                        for u in sum(self.utxos.values(), [])]
        self.outputs.append({'address': self.coinjoin_address(),
                             'value': self.cjamount})
        random.shuffle(self.utxo_tx)
        random.shuffle(self.outputs)
        tx = btc.mktx(self.utxo_tx, self.outputs)
        log.debug('obtained tx\n' + pprint.pformat(btc.deserialize(tx)))

        self.latest_tx = btc.deserialize(tx)
        for index, ins in enumerate(self.latest_tx['ins']):
            utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
            if utxo not in self.input_utxos.keys():
                continue
            # placeholders required
            ins['script'] = 'deadbeef'

        return (True, self.maker_utxo_data.keys(), tx)

    def auth_counterparty(self, btc_sig, auth_pub, maker_pk):
        """Validate the counterpartys claim to own the btc
        address/pubkey that will be used for coinjoining
        with an ecdsa verification.
        """
        if not btc.ecdsa_verify(maker_pk, btc_sig, auth_pub):
            log.debug('signature didnt match pubkey and message')
            return False
        return True

    def on_sig(self, nick, sigb64):
        sig = base64.b64decode(sigb64).encode('hex')
        inserted_sig = False
        txhex = btc.serialize(self.latest_tx)

        # batch retrieval of utxo data
        utxo = {}
        ctr = 0
        for index, ins in enumerate(self.latest_tx['ins']):
            utxo_for_checking = ins['outpoint']['hash'] + ':' + str(ins[
                'outpoint']['index'])
            if (ins['script'] != '' or
                    utxo_for_checking in self.input_utxos.keys()):
                continue
            utxo[ctr] = [index, utxo_for_checking]
            ctr += 1
        utxo_data = jm_single().bc_interface.query_utxo_set([x[
            1] for x in utxo.values()])

        # insert signatures
        for i, u in utxo.iteritems():
            if utxo_data[i] is None:
                continue
            sig_good = btc.verify_tx_input(txhex, u[0], utxo_data[i]['script'],
                                           *btc.deserialize_script(sig))
            if sig_good:
                log.debug('found good sig at index=%d' % (u[0]))
                self.latest_tx['ins'][u[0]]['script'] = sig
                inserted_sig = True
                # check if maker has sent everything possible
                self.utxos[nick].remove(u[1])
                if len(self.utxos[nick]) == 0:
                    log.debug(('nick = {} sent all sigs, removing from '
                               'nonrespondant list').format(nick))
                    self.nonrespondants.remove(nick)
                break
        if not inserted_sig:
            log.debug('signature did not match anything in the tx')
            # TODO what if the signature doesnt match anything
            # nothing really to do except drop it, carry on and wonder why the
            # other guy sent a failed signature

        tx_signed = True
        for ins in self.latest_tx['ins']:
            if ins['script'] == '':
                tx_signed = False
        if not tx_signed:
            return False
        assert not len(self.nonrespondants)
        log.debug('all makers have sent their signatures')
        self.self_sign_and_push()
        return True

    def make_commitment(self):
        """The Taker default commitment function, which uses PoDLE.
        Alternative commitment types should use a different commit type byte.
        This will allow future upgrades to provide different style commitments
        by subclassing Taker and changing the commit_type_byte; existing makers
        will simply not accept this new type of commitment.
        In case of success, return the commitment and its opening.
        In case of failure returns (None, None) and constructs a detailed
        log for the user to read and discern the reason.
        """

        def filter_by_coin_age_amt(utxos, age, amt):
            results = jm_single().bc_interface.query_utxo_set(utxos,
                                                              includeconf=True)
            newresults = []
            too_old = []
            too_small = []
            for i, r in enumerate(results):
                #results return "None" if txo is spent; drop this
                if not r:
                    continue
                valid_age = r['confirms'] >= age
                valid_amt = r['value'] >= amt
                if not valid_age:
                    too_old.append(utxos[i])
                if not valid_amt:
                    too_small.append(utxos[i])
                if valid_age and valid_amt:
                    newresults.append(utxos[i])

            return newresults, too_old, too_small

        def priv_utxo_pairs_from_utxos(utxos, age, amt):
            #returns pairs list of (priv, utxo) for each valid utxo;
            #also returns lists "too_old" and "too_small" for any
            #utxos that did not satisfy the criteria for debugging.
            priv_utxo_pairs = []
            new_utxos, too_old, too_small = filter_by_coin_age_amt(utxos.keys(),
                                                                   age, amt)
            new_utxos_dict = {k: v for k, v in utxos.items() if k in new_utxos}
            for k, v in new_utxos_dict.iteritems():
                addr = v['address']
                priv = self.wallet.get_key_from_addr(addr)
                if priv:  #can be null from create-unsigned
                    priv_utxo_pairs.append((priv, k))
            return priv_utxo_pairs, too_old, too_small

        commit_type_byte = "P"
        podle_data = None
        tries = jm_single().config.getint("POLICY", "taker_utxo_retries")
        age = jm_single().config.getint("POLICY", "taker_utxo_age")
        #Minor rounding errors don't matter here
        amt = int(self.cjamount *
                  jm_single().config.getint("POLICY",
                                            "taker_utxo_amtpercent") / 100.0)
        priv_utxo_pairs, to, ts = priv_utxo_pairs_from_utxos(self.input_utxos,
                                                             age, amt)
        #Note that we ignore the "too old" and "too small" lists in the first
        #pass through, because the same utxos appear in the whole-wallet check.

        #For podle data format see: btc.podle.PoDLE.reveal()
        #In first round try, don't use external commitments
        podle_data = btc.generate_podle(priv_utxo_pairs, tries)
        if not podle_data:
            #We defer to a second round to try *all* utxos in wallet;
            #this is because it's much cleaner to use the utxos involved
            #in the transaction, about to be consumed, rather than use
            #random utxos that will persist after. At this step we also
            #allow use of external utxos in the json file.
            if self.wallet.unspent:
                priv_utxo_pairs, to, ts = priv_utxo_pairs_from_utxos(
                    self.wallet.unspent, age, amt)
            #Pre-filter the set of external commitments that work for this
            #transaction according to its size and age.
            dummy, extdict = btc.get_podle_commitments()
            if len(extdict.keys()) > 0:
                ext_valid, ext_to, ext_ts = filter_by_coin_age_amt(
                    extdict.keys(), age, amt)
            else:
                ext_valid = None
            podle_data = btc.generate_podle(priv_utxo_pairs, tries, ext_valid)
        if podle_data:
            log.debug("Generated PoDLE: " + pprint.pformat(podle_data))
            revelation = btc.PoDLE(u=podle_data['utxo'],
                                   P=podle_data['P'],
                                   P2=podle_data['P2'],
                                   s=podle_data['sig'],
                                   e=podle_data['e']).serialize_revelation()
            return (commit_type_byte + podle_data["commit"], revelation)
        else:
            #we know that priv_utxo_pairs all passed age and size tests, so
            #they must have failed the retries test. Summarize this info
            #and publish to commitments_debug.txt
            with open("commitments_debug.txt", "wb") as f:
                f.write("THIS IS A TEMPORARY FILE FOR DEBUGGING; "
                        "IT CAN BE SAFELY DELETED ANY TIME.\n")
                f.write("***\n")
                f.write("1: Utxos that passed age and size limits, but have "
                        "been used too many times (see taker_utxo_retries "
                        "in the config):\n")
                if len(priv_utxo_pairs) == 0:
                    f.write("None\n")
                else:
                    for p, u in priv_utxo_pairs:
                        f.write(str(u) + "\n")
                f.write("2: Utxos that have less than " + jm_single(
                ).config.get("POLICY", "taker_utxo_age") + " confirmations:\n")
                if len(to) == 0:
                    f.write("None\n")
                else:
                    for t in to:
                        f.write(str(t) + "\n")
                f.write("3: Utxos that were not at least " + \
                        jm_single().config.get(
                            "POLICY", "taker_utxo_amtpercent") + "% of the "
                        "size of the coinjoin amount " + str(
                            self.cjamount) + "\n")
                if len(ts) == 0:
                    f.write("None\n")
                else:
                    for t in ts:
                        f.write(str(t) + "\n")
                f.write('***\n')
                f.write("Utxos that appeared in item 1 cannot be used again.\n")
                f.write(
                    "Utxos only in item 2 can be used by waiting for more "
                    "confirmations, (set by the value of taker_utxo_age).\n")
                f.write("Utxos only in item 3 are not big enough for this "
                        "coinjoin transaction, set by the value "
                        "of taker_utxo_amtpercent.\n")
                f.write(
                    "If you cannot source a utxo from your wallet according "
                    "to these rules, use the tool add-utxo.py to source a "
                    "utxo external to your joinmarket wallet. Read the help "
                    "with 'python add-utxo.py --help'\n\n")
                f.write("You can also reset the rules in the joinmarket.cfg "
                        "file, but this is generally inadvisable.\n")
                f.write(
                    "***\nFor reference, here are the utxos in your wallet:\n")
                f.write("\n" + str(self.wallet.unspent))

            return (None, None)

    def get_commitment(self, utxos, amount):
        """Create commitment to fulfil anti-DOS requirement of makers,
        storing the corresponding reveal/proof data for next step.
        """
        while True:
            self.commitment, self.reveal_commitment = self.make_commitment(
                self.wallet, utxos, amount)
            if (self.commitment) or (jm_single().wait_for_commitments == 0):
                break
            log.debug("Failed to source commitments, waiting 3 minutes")
            time.sleep(3 * 60)
        if not self.commitment:
            log.debug(
                "Cannot construct transaction, failed to generate "
                "commitment, shutting down. Please read commitments_debug.txt "
                "for some information on why this is, and what can be "
                "done to remedy it.")
            #TODO: would like to raw_input here to show the user, but
            #interactivity is undesirable here.
            #Test only:
            if jm_single().config.get("BLOCKCHAIN",
                                      "blockchain_source") == 'regtest':
                raise btc.PoDLEError("For testing raising podle exception")
            #The timeout/recovery code is designed to handle non-responsive
            #counterparties, but this condition means that the current bot
            #is not able to create transactions following its *own* rules,
            #so shutting down is appropriate no matter what style
            #of bot this is.
            #These two settings shut down the timeout thread and avoid recovery.
            self.all_responded = True
            self.end_timeout_thread = True
            self.msgchan.shutdown()

    def coinjoin_address(self):
        if self.my_cj_addr:
            return self.my_cj_addr
        else:
            addr, self.sign_k = donation_address()
            return addr

    def sign_tx(self, tx, i, priv):
        if self.my_cj_addr:
            return btc.sign(tx, i, priv)
        else:
            return btc.sign(tx,
                            i,
                            priv,
                            usenonce=btc.safe_from_hex(self.sign_k))

    def self_sign(self):
        # now sign it ourselves
        tx = btc.serialize(self.latest_tx)
        for index, ins in enumerate(self.latest_tx['ins']):
            utxo = ins['outpoint']['hash'] + ':' + str(ins['outpoint']['index'])
            if utxo not in self.input_utxos.keys():
                continue
            addr = self.input_utxos[utxo]['address']
            tx = self.sign_tx(tx, index, self.wallet.get_key_from_addr(addr))
        self.latest_tx = btc.deserialize(tx)

    def push(self):
        tx = btc.serialize(self.latest_tx)
        log.debug('\n' + tx)
        self.txid = btc.txhash(tx)
        log.debug('txid = ' + self.txid)

        tx_broadcast = jm_single().config.get('POLICY', 'tx_broadcast')
        if tx_broadcast == 'self':
            pushed = jm_single().bc_interface.pushtx(tx)
        elif tx_broadcast in ['random-peer', 'not-self']:
            n = len(self.active_orders)
            if tx_broadcast == 'random-peer':
                i = random.randrange(n + 1)
            else:
                i = random.randrange(n)
            if i == n:
                pushed = jm_single().bc_interface.pushtx(tx)
            else:
                self.msgchan.push_tx(self.active_orders.keys()[i], tx)
                pushed = True
        elif tx_broadcast == 'random-maker':
            crow = self.db.execute(
                'SELECT DISTINCT counterparty FROM orderbook ORDER BY ' +
                'RANDOM() LIMIT 1;').fetchone()
            counterparty = crow['counterparty']
            log.debug('pushing tx to ' + counterparty)
            self.msgchan.push_tx(counterparty, tx)
            pushed = True

        if not pushed:
            log.debug('unable to pushtx')
        return pushed

    def self_sign_and_push(self):
        self.self_sign()
        return self.push()
