#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet accounts properly when there are cloned transactions with malleated scriptsigs."""

import struct
from test_framework.test_framework import BitcoinTestFramework
from test_framework.mininode import *
from test_framework.util import *

class TxnMallTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4

    def add_options(self, parser):
        parser.add_option("--mineblock", dest="mine_block", default=False, action="store_true",
                          help="Test double-spend of 1-confirmed transaction")

    def setup_network(self):
        # Start with split network:
        super(TxnMallTest, self).setup_network()
        disconnect_nodes(self.nodes[1], 2)
        disconnect_nodes(self.nodes[2], 1)

    def run_test(self):
        miner_reward = CB_AMOUNT_AFTER_BLOCK_100
        # All nodes should start with starting_balance:
        starting_balance = BASE_CB_AMOUNT * 25
        for i in range(self.num_nodes):
            assert_equal(self.nodes[i].getbalance(), starting_balance)
            self.nodes[i].getnewaddress("")  # bug workaround, coins generated assigned to first getnewaddress!

        # Assign coins to foo and bar accounts:
        self.nodes[0].settxfee(.001)

        node0_address_foo = self.nodes[0].getnewaddress("foo")
        fund_foo_txid = self.nodes[0].sendfrom("", node0_address_foo, 1219)
        fund_foo_tx = self.nodes[0].gettransaction(fund_foo_txid)
        burn_foo = -find_burned_amount_in_tx(fund_foo_tx)

        node0_address_bar = self.nodes[0].getnewaddress("bar")
        fund_bar_txid = self.nodes[0].sendfrom("", node0_address_bar, 29)
        fund_bar_tx = self.nodes[0].gettransaction(fund_bar_txid)
        burn_bar = -find_burned_amount_in_tx(fund_bar_tx)

        assert_equal(self.nodes[0].getbalance(""),
                     starting_balance - 1219 - 29 + fund_foo_tx["fee"] + fund_bar_tx["fee"] - burn_foo - burn_bar)

        # Coins are sent to node1_address
        node1_address = self.nodes[1].getnewaddress("from0")

        # Send tx1, and another transaction tx2 that won't be cloned 
        txid1 = self.nodes[0].sendfrom("foo", node1_address, 40, 0)
        txid2 = self.nodes[0].sendfrom("bar", node1_address, 20, 0)

        # Construct a clone of tx1, to be malleated 
        rawtx1 = self.nodes[0].getrawtransaction(txid1,1)
        outputs_count = 4  # dest, change, burn1, burn2
        assert_equal(len(rawtx1['vout']), outputs_count)

        tx1_cl = CTransaction()
        tx1_cl.nVersion = 2
        tx1_cl.vin = [CTxIn(COutPoint(int(rawtx1['vin'][0]['txid'], 16), rawtx1['vin'][0]['vout']), b'', 0xFFFFFFFE)]
        for out in rawtx1['vout']:
            tx1_cl.vout.append(CTxOut(ToSatoshi(out['value']), hex_str_to_bytes(out['scriptPubKey']['hex'])))
        tx1_cl.nLockTime = rawtx1['locktime']
        clone_raw = bytes_to_hex_str(tx1_cl.serialize())

        # Use a different signature hash type to sign.  This creates an equivalent but malleated clone.
        # Don't send the clone anywhere yet
        tx1_clone = self.nodes[0].signrawtransaction(clone_raw, None, None, "ALL|ANYONECANPAY")
        assert_equal(tx1_clone["complete"], True)

        # Have node0 mine a block, if requested:
        if (self.options.mine_block):
            self.nodes[0].generate(1)
            sync_blocks(self.nodes[0:2])

        tx1 = self.nodes[0].gettransaction(txid1)
        tx2 = self.nodes[0].gettransaction(txid2)

        # Node0's balance should be starting balance, plus 50 PLCU for another
        # matured block, minus tx1 and tx2 amounts, and minus transaction fees:
        expected = starting_balance + fund_foo_tx["fee"] + fund_bar_tx["fee"] - burn_foo - burn_bar
        if self.options.mine_block: expected += miner_reward
        expected += tx1["amount"] + tx1["fee"]
        expected += tx2["amount"] + tx2["fee"]
        assert_equal(self.nodes[0].getbalance(), expected)

        # foo and bar accounts should be debited:
        # getbalance() for account doesn't work since version 2.10
        # assert_equal(self.nodes[0].getbalance("foo", 0), 1219 + tx1["amount"] + tx1["fee"])
        # assert_equal(self.nodes[0].getbalance("bar", 0), 29 + tx2["amount"] + tx2["fee"])

        if self.options.mine_block:
            assert_equal(tx1["confirmations"], 1)
            assert_equal(tx2["confirmations"], 1)
            # Node1's "from0" balance should be both transaction amounts:
            burned1 = -find_burned_amount_in_tx(tx1)
            burned2 = -find_burned_amount_in_tx(tx2)
            assert_equal(self.nodes[1].getbalance("from0"), -(tx1["amount"] + tx2["amount"]) - burned1 - burned2)
        else:
            assert_equal(tx1["confirmations"], 0)
            assert_equal(tx2["confirmations"], 0)

        # Send clone and its parent to miner
        self.nodes[2].sendrawtransaction(fund_foo_tx["hex"])
        txid1_clone = self.nodes[2].sendrawtransaction(tx1_clone["hex"])
        # ... mine a block...
        self.nodes[2].generate(1)

        # Reconnect the split network, and sync chain:
        connect_nodes(self.nodes[1], 2)
        self.nodes[2].sendrawtransaction(fund_bar_tx["hex"])
        self.nodes[2].sendrawtransaction(tx2["hex"])
        self.nodes[2].generate(1)  # Mine another block to make sure we sync
        sync_blocks(self.nodes)

        # Re-fetch transaction info:
        tx1 = self.nodes[0].gettransaction(txid1)
        tx1_clone = self.nodes[0].gettransaction(txid1_clone)
        tx2 = self.nodes[0].gettransaction(txid2)
        
        # Verify expected confirmations
        assert_equal(tx1["confirmations"], -2)
        assert_equal(tx1_clone["confirmations"], 2)
        assert_equal(tx2["confirmations"], 1)

        # Check node0's total balance; should be same as before the clone, + miner_reward * 2 PLCU for 2 matured,
        # less possible orphaned matured subsidy
        expected += miner_reward * 2
        if (self.options.mine_block): 
            expected -= miner_reward
        assert_equal(self.nodes[0].getbalance(), expected)
        assert_equal(self.nodes[0].getbalance("*", 0), expected)

        # Check node0's individual account balances.
        # "foo" should have been debited by the equivalent clone of tx1
        # getbalance() for account doesn't work since version 2.10
        # assert_equal(self.nodes[0].getbalance("foo"), 1219 + tx1["amount"] + tx1["fee"])
        # "bar" should have been debited by (possibly unconfirmed) tx2
        # assert_equal(self.nodes[0].getbalance("bar", 0), 29 + tx2["amount"] + tx2["fee"])
        # "" should have starting balance, less funding txes, plus subsidies
        # assert_equal(self.nodes[0].getbalance("", 0), starting_balance
        #                                                         - 1219
        #                                                         + fund_foo_tx["fee"] - burn_foo
        #                                                         -   29
        #                                                         + fund_bar_tx["fee"] - burn_bar
        #                                                         + miner_reward * 2)

        # Node1's "from0" account balance
        burned1 = -find_burned_amount_in_tx(tx1)
        burned2 = -find_burned_amount_in_tx(tx2)
        assert_equal(self.nodes[1].getbalance("from0", 0), -(tx1["amount"] + tx2["amount"]) - burned1 - burned2)

if __name__ == '__main__':
    TxnMallTest().main()

