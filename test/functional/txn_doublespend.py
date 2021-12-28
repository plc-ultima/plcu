#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet accounts properly when there is a double-spend conflict."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class TxnMallTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True

    def add_options(self, parser):
        parser.add_option("--mineblock", dest="mine_block", default=False, action="store_true",
                          help="Test double-spend of 1-confirmed transaction")

    def run_test(self):
        # Generate starting blocks by all nodes equally and disconnect nodes:
        blocks_per_each_after_100 = 2
        # TODO: for (1 <= blocks_per_each_after_100 <= 2) works OK,
        #  for (blocks_per_each_after_100 >= 3) fails in the case with negative confirmations. WHY ???
        for i in range(25 + blocks_per_each_after_100):
            for j in range(self.num_nodes):
                self.nodes[j].generate(1)
                self.sync_all()
        disconnect_nodes(self.nodes[1], 2)
        disconnect_nodes(self.nodes[2], 1)

        # All nodes should start with starting_balance:
        base_balance = BASE_CB_AMOUNT
        starting_balance = base_balance * blocks_per_each_after_100
        for i in range(self.num_nodes):
            assert_equal(self.nodes[i].getbalance(), starting_balance)
            self.nodes[i].getnewaddress("")  # bug workaround, coins generated assigned to first getnewaddress!

        # Assign coins to foo and bar accounts:
        node0_address_foo = self.nodes[0].getnewaddress("foo")
        fund_foo_txid = self.nodes[0].sendfrom("", node0_address_foo, 29)
        fund_foo_tx = self.nodes[0].gettransaction(fund_foo_txid)
        burn_foo = -find_burned_amount_in_tx(fund_foo_tx)

        node0_address_bar = self.nodes[0].getnewaddress("bar")
        fund_bar_txid = self.nodes[0].sendfrom("", node0_address_bar, 1219)
        fund_bar_tx = self.nodes[0].gettransaction(fund_bar_txid)
        burn_bar = -find_burned_amount_in_tx(fund_bar_tx)

        assert_equal(self.nodes[0].getbalance(""),
                     starting_balance - 29 - 1219 + fund_foo_tx["fee"] + fund_bar_tx["fee"] - burn_foo - burn_bar)

        # Coins are sent to node1_address
        node1_address = self.nodes[1].getnewaddress("from0")

        # First: use raw transaction API to send 1240 PLCU to node1_address,
        # but don't broadcast:
        doublespend_fee = Decimal('-.02')
        rawtx_input_0 = {}
        rawtx_input_0["txid"] = fund_foo_txid
        rawtx_input_0["vout"] = find_output(self.nodes[0], fund_foo_txid, 29)
        rawtx_input_1 = {}
        rawtx_input_1["txid"] = fund_bar_txid
        rawtx_input_1["vout"] = find_output(self.nodes[0], fund_bar_txid, 1219)
        inputs = [rawtx_input_0, rawtx_input_1]
        change_address = self.nodes[0].getnewaddress()
        outputs = {}
        (doublespend_burn1, doublespend_burn2, change) = BurnedAndChangeAmount(Decimal(1248) + doublespend_fee, Decimal(1200))
        doublespend_burn = doublespend_burn1 + doublespend_burn2
        outputs[node1_address] = 1200
        outputs[GRAVE_ADDRESS_1] = doublespend_burn1
        outputs[GRAVE_ADDRESS_2] = doublespend_burn2
        outputs[change_address] = change
        rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
        doublespend = self.nodes[0].signrawtransaction(rawtx)
        assert_equal(doublespend["complete"], True)
        generated_balance = 0

        # Create two spends to node1_address:
        txid1 = self.nodes[0].sendfrom("foo", node1_address, 20, 0)
        txid2 = self.nodes[0].sendfrom("bar", node1_address, 40, 0)

        # Have node0 mine a block:
        if (self.options.mine_block):
            self.nodes[0].generate(1)
            sync_blocks(self.nodes[0:2])
            generated_balance += base_balance

        tx1 = self.nodes[0].gettransaction(txid1)
        tx2 = self.nodes[0].gettransaction(txid2)

        # Node0's balance should be starting balance,
        # minus 20, minus 40, and minus transaction fees:
        expected = starting_balance + fund_foo_tx["fee"] + fund_bar_tx["fee"] + generated_balance - burn_foo - burn_bar
        expected += tx1["amount"] + tx1["fee"]
        expected += tx2["amount"] + tx2["fee"]
        assert_equal(self.nodes[0].getbalance(), expected)

        # foo and bar accounts should be debited:
        assert_equal(self.nodes[0].getbalance("foo", 0), 29 + tx1["amount"] + tx1["fee"])
        assert_equal(self.nodes[0].getbalance("bar", 0), 1219 + tx2["amount"] + tx2["fee"])

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

        # Now give doublespend and its parents to miner:
        self.nodes[2].sendrawtransaction(fund_foo_tx["hex"])
        self.nodes[2].sendrawtransaction(fund_bar_tx["hex"])
        doublespend_txid = self.nodes[2].sendrawtransaction(doublespend["hex"])
        assert_in(doublespend_txid, self.nodes[2].getrawmempool())
        # ... mine a block...
        self.nodes[2].generate(1)

        # Reconnect the split network, and sync chain:
        connect_nodes(self.nodes[1], 2)
        self.nodes[2].generate(1)  # Mine another block to make sure we sync
        sync_blocks(self.nodes)
        assert_equal(self.nodes[0].gettransaction(doublespend_txid)["confirmations"], 2)

        # Re-fetch transaction info:
        tx1 = self.nodes[0].gettransaction(txid1)
        tx2 = self.nodes[0].gettransaction(txid2)

        # Both transactions should be conflicted
        assert_equal(tx1["confirmations"], -2)
        assert_equal(tx2["confirmations"], -2)

        # Node0's total balance should be starting balance,
        # minus 1240 for the double-spend, plus fees (which are negative):
        expected = starting_balance - 1200 + \
                   fund_foo_tx["fee"] + fund_bar_tx["fee"] - burn_foo - burn_bar + \
                   doublespend_fee - doublespend_burn + base_balance
        assert_equal(self.nodes[0].getbalance(), expected)
        assert_equal(self.nodes[0].getbalance("*"), expected)

        # Final "" balance is starting_balance - amount moved to accounts - doublespend + subsidies +
        # fees (which are negative)
        assert_equal(self.nodes[0].getbalance("foo"), 29)
        assert_equal(self.nodes[0].getbalance("bar"), 1219)
        assert_equal(self.nodes[0].getbalance(""), starting_balance
                                                              -29
                                                              -1219
                                                              -1200
                                                              + fund_foo_tx["fee"] - burn_foo
                                                              + fund_bar_tx["fee"] - burn_bar
                                                              + doublespend_fee - doublespend_burn
                                                              + base_balance)

        # Node1's "from0" account balance should be just the doublespend:
        assert_equal(self.nodes[1].getbalance("from0"), 1200)

if __name__ == '__main__':
    TxnMallTest().main()

