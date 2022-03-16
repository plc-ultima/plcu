#!/usr/bin/env python3
# Copyright (c) 2021 The PLC Ultima Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.key import create_key
from test_framework.blocktools import create_coinbase, create_block
from test_framework.certs import send_block

'''
coinbase_subsidy.py
'''

DEFAULT_CB_BEFORE_BLOCK_100  = 5000 * COIN
DEFAULT_CB_AFTER_BLOCK_100   = int(0.005 * COIN)
DEFAULT_CB_AFTER_BLOCK_2000 = int(0.00005 * COIN)


# TestNode: bare-bones "peer".
class TestNode(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.reject_message = None

    def add_connection(self, conn):
        self.connection = conn
        self.peer_disconnected = False

    def on_close(self, conn):
        self.peer_disconnected = True

    def wait_for_disconnect(self):
        def disconnected():
            return self.peer_disconnected
        return wait_until(disconnected, timeout=10)

    def on_reject(self, conn, message):
        self.reject_message = message


class CoinbaseSubsidyTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-debug', '-whitelist=127.0.0.1', '-holyminingblock-regtest=2500']]
        self.outpoints = []


    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()


    def create_tx_with_fee(self, fee):
        outpoint = self.outpoints.pop(0)
        (burn1, burn2, change) = BurnedAndChangeAmount(ToCoins(self.outpoint_amount) - ToCoins(fee))
        tx1 = CTransaction()
        tx1.vin.append(CTxIn(outpoint, self.my_p2pkh_scriptpubkey, 0xffffffff))
        tx1.vout = []
        tx1.vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(hash160(b'some_address'))))
        tx1.vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
        tx1.vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
        (sig_hash, err) = SignatureHash(self.my_p2pkh_scriptpubkey, tx1, 0, SIGHASH_ALL)
        assert (err is None)
        signature = self.my_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx1.vin[0].scriptSig = CScript([signature, self.my_pubkey])
        return tx1


    def compose_and_send_block(self, coinbase, tx_list, accepted, reject_reason = None):
        coinbase.rehash()
        for tx in tx_list:
            tx.rehash()
        tmpl = self.nodes[0].getblocktemplate()
        block = create_block(int(tmpl['previousblockhash'], 16), coinbase, tmpl['curtime'], int(tmpl['bits'], 16), VB_TOP_BITS, tx_list)
        self.log.debug(f'block: {block}')
        send_block(self.nodes[0], self.test_node, block, accepted, reject_reason)


    def generate_outpoints(self):
        amount = self.outpoint_amount
        fee = Decimal('0.0001')
        (burn1, burn2, change) = BurnedAndChangeAmount(amount - fee)
        self.log.debug(f'amount: {amount}, fee: {fee}, burn1: {burn1}, burn2: {burn2}, change: {change}')
        for i in range(40):
            txid = self.nodes[0].sendtoaddress(AddressFromPubkeyHash(self.my_pkh), amount)
            self.outpoints.append(COutPoint(int(txid, 16), find_output(self.nodes[0], txid, amount)))


    def run_test(self):
        self.my_key = create_key(True)
        self.my_pubkey = self.my_key.get_pubkey()
        self.my_pkh = hash160(self.my_pubkey)
        self.my_p2pkh_scriptpubkey = GetP2PKHScript(self.my_pkh)
        self.my_p2pk_scriptpubkey = CScript([self.my_pubkey, OP_CHECKSIG])
        cb_pubkey = self.my_pubkey

        node0 = self.nodes[0]
        height = 50
        node0.generate(height)
        self.test_node.sync_with_ping()
        assert_equal(node0.getblockcount(), height)

        # A-01
        # (0 < height <= 100), normal coinbase: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        assert_equal(cb.vout[0].nValue, DEFAULT_CB_BEFORE_BLOCK_100)
        self.compose_and_send_block(cb, [], True)
        moneybox_vout = cb.vout[-1]

        # A-02
        # (0 < height <= 100), coinbase subsidy is less than allowed: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue -= 1
        self.compose_and_send_block(cb, [], True)

        # A-03
        # (0 < height <= 100), coinbase subsidy is more than allowed: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue += 1
        self.compose_and_send_block(cb, [], False, 'bad-cb-amount')

        # A-04
        # (0 < height <= 100), moneybox refill is less than required: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[1].nValue -= 1
        self.compose_and_send_block(cb, [], False, 'bad-box-amount')

        # A-05
        # (0 < height <= 100), moneybox refill is more than required (and more than granularity): rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[1].nValue += 1
        self.compose_and_send_block(cb, [], False, 'bad-txns-moneybox-value-toolarge')

        # A-06
        # (0 < height <= 100), moneybox refill is more than required in one output (and more than granularity) and less in another, summary OK: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[1].nValue += 1
        cb.vout[2].nValue -= 1
        self.compose_and_send_block(cb, [], False, 'bad-txns-moneybox-value-toolarge')

        # A-07
        # (0 < height <= 100), moneybox refill is more than required (has an extra output, granularity is OK): rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout.append(CTxOut(1 * COIN, cb.vout[-1].scriptPubKey))
        self.compose_and_send_block(cb, [], False, 'bad-box-amount')

        # A-08
        # (0 < height <= 100), moneybox refill is less than required in one output, but has extra output with this amount, summary OK: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        delta = 1 * COIN
        cb.vout[1].nValue -= delta
        cb.vout.append(CTxOut(delta, cb.vout[-1].scriptPubKey))
        self.compose_and_send_block(cb, [], True)

        # A-09
        # (0 < height <= 100), moneybox refill is less than required in 2 outputs, but has 2 extra outputs with this amount, summary OK: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        delta = 1 * COIN
        cb.vout[1].nValue -= delta
        cb.vout[2].nValue -= delta
        cb.vout.append(CTxOut(delta, cb.vout[-1].scriptPubKey))
        cb.vout.append(CTxOut(delta, cb.vout[-1].scriptPubKey))
        self.compose_and_send_block(cb, [], False, 'bad-box-count')

        node0.generate(100)
        self.outpoint_amount = Decimal(10)
        self.generate_outpoints()
        node0.generate(1)

        # A-10
        # (100 < height <= 2000), normal coinbase without other transactions: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        assert_equal(cb.vout[0].nValue, DEFAULT_CB_AFTER_BLOCK_100)
        self.compose_and_send_block(cb, [], True)

        # A-11
        # (100 < height <= 2000), without other transactions
        # coinbase subsidy is less than allowed: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue -= 1
        self.compose_and_send_block(cb, [], True)

        # A-12
        # (100 < height <= 2000), without other transactions
        # coinbase subsidy is more than allowed: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue += 1
        self.compose_and_send_block(cb, [], False, 'bad-cb-amount')

        # A-13
        # (100 < height <= 2000),
        # (sum(tx_fees) / 2 < 0.005): 0.005 is used: accepted
        fee1 = int(0.004 * COIN)
        fee2 = int(0.003 * COIN)
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, DEFAULT_CB_AFTER_BLOCK_100)
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], True)

        # A-14
        # (100 < height <= 2000),
        # (sum(tx_fees) / 2 < 0.005): 0.005 must be used, try 1 satoshi more: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, DEFAULT_CB_AFTER_BLOCK_100)
        cb.vout[0].nValue += 1
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], False, 'bad-cb-amount')

        # A-15
        # (100 < height <= 2000),
        # (sum(tx_fees) / 2 > 0.005): sum(tx_fees) / 2 is used: accepted
        fee1 = int(0.006 * COIN)
        fee2 = int(0.007 * COIN)
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, (fee1 + fee2) // 2)
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], True)

        # A-16
        # (100 < height <= 2000),
        # (sum(tx_fees) / 2 > 0.005): sum(tx_fees) / 2 must be used, try 1 satoshi more: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, (fee1 + fee2) // 2)
        cb.vout[0].nValue += 1
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], False, 'bad-cb-amount')

        # A-17
        # (100 < height <= 2000), without other transactions
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        moneybox_vout.nValue = DEFAULT_CB_AFTER_BLOCK_100
        cb.vout.append(moneybox_vout)
        self.compose_and_send_block(cb, [], False, 'bad-box-amount')

        # A-18
        # (100 < height <= 2000), with normal transactions not spending moneybox
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        cb.vout.append(moneybox_vout)
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], False, 'bad-box-amount')

        generate_many_blocks(node0, 2001 - node0.getblockcount())

        # A-20
        # (height > 2000), normal coinbase without other transactions: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        assert_equal(cb.vout[0].nValue, DEFAULT_CB_AFTER_BLOCK_2000)
        self.compose_and_send_block(cb, [], True)

        # A-21
        # (height > 2000), without other transactions
        # coinbase subsidy is less than allowed: accepted
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue -= 1
        self.compose_and_send_block(cb, [], True)

        # A-22
        # (height > 2000), without other transactions
        # coinbase subsidy is more than allowed: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        cb.vout[0].nValue += 1
        self.compose_and_send_block(cb, [], False, 'bad-cb-amount')

        # A-23
        # (height > 2000),
        # (sum(tx_fees) / 2 < 0.00005): 0.00005 is used: accepted
        fee1 = int(0.00004 * COIN)
        fee2 = int(0.00003 * COIN)
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, DEFAULT_CB_AFTER_BLOCK_2000)
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], True)

        # A-24
        # (height > 2000),
        # (sum(tx_fees) / 2 < 0.00005): 0.00005 must be used, try 1 satoshi more: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, DEFAULT_CB_AFTER_BLOCK_2000)
        cb.vout[0].nValue += 1
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], False, 'bad-cb-amount')

        # A-25
        # (height > 2000),
        # (sum(tx_fees) / 2 > 0.00005): sum(tx_fees) / 2 is used: accepted
        fee1 = int(0.00006 * COIN)
        fee2 = int(0.00007 * COIN)
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, (fee1 + fee2) // 2)
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], True)

        # A-26
        # (height > 2000),
        # (sum(tx_fees) / 2 > 0.005): sum(tx_fees) / 2 must be used, try 1 satoshi more: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        assert_equal(cb.vout[0].nValue, (fee1 + fee2) // 2)
        cb.vout[0].nValue += 1
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], False, 'bad-cb-amount')

        # A-27
        # (height > 2000), without other transactions
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey)
        moneybox_vout.nValue = DEFAULT_CB_AFTER_BLOCK_2000
        cb.vout.append(moneybox_vout)
        self.compose_and_send_block(cb, [], False, 'bad-box-amount')

        # A-28
        # (height > 2000), with normal transactions not spending moneybox
        # try to fill up moneybox: rejected
        cb = create_coinbase(node0.getblockcount() + 1, cb_pubkey, fee1 + fee2)
        cb.vout.append(moneybox_vout)
        tx1 = self.create_tx_with_fee(fee1)
        tx2 = self.create_tx_with_fee(fee2)
        self.compose_and_send_block(cb, [tx1, tx2], False, 'bad-box-amount')


if __name__ == '__main__':
    CoinbaseSubsidyTest().main()
