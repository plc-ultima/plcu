#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the abandontransaction RPC.

 The abandontransaction RPC marks a transaction and all its in-wallet
 descendants as abandoned which allows their inputs to be respent. It can be
 used to replace "stuck" or evicted transactions. It only works on transactions
 which are not included in a block and are not currently in the mempool. It has
 no effect on transactions which are already conflicted or abandoned.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
# from test_framework.script import GraveAddress


class AbandonConflictTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-minrelaytxfee=0.00000100"], []]

    def run_test(self):
        self.nodes[1].generate(100)
        sync_blocks(self.nodes)
        balance = self.nodes[0].getbalance()
        amount10 = Decimal("10")
        fee = Decimal("0.00002000")
        txA = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), amount10)
        verify_tx_sent(self.nodes[0], txA)
        txB = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), amount10)
        verify_tx_sent(self.nodes[0], txB)
        txC = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), amount10)
        verify_tx_sent(self.nodes[0], txC)
        sync_mempools(self.nodes)
        self.nodes[1].generate(1)

        sync_blocks(self.nodes)
        newbalance = self.nodes[0].getbalance()
        (_, _, rest) = BurnedAndChangeAmount(BASE_CB_AMOUNT * 3, 0)
        assert_greater_than_or_equal(Decimal("0.1") + rest, balance - newbalance) #no more than fees and burned lost
        balance = newbalance

        # Disconnect nodes so node0's transactions don't get into node1's mempool
        disconnect_nodes(self.nodes[0], 1)

        # Identify the 10 PLCU outputs
        nA = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txA, 1)["vout"]) if vout["value"] == amount10)
        nB = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txB, 1)["vout"]) if vout["value"] == amount10)
        nC = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txC, 1)["vout"]) if vout["value"] == amount10)

        inputs =[]
        # spend 10 PLCU outputs from txA and txB
        inputs.append({"txid":txA, "vout":nA})
        inputs.append({"txid":txB, "vout":nB})
        outputs = {}
        amount15 = Decimal(15)
        (burn1, burn2, change) = BurnedAndChangeAmount(amount10 * 2 - fee, amount15 - fee)
        outputs[self.nodes[0].getnewaddress()] = amount15 - fee
        outputs[self.nodes[1].getnewaddress()] = change
        outputs[GRAVE_ADDRESS_1] = burn1
        outputs[GRAVE_ADDRESS_2] = burn2
        signed = self.nodes[0].signrawtransaction(self.nodes[0].createrawtransaction(inputs, outputs))
        txAB1 = self.nodes[0].sendrawtransaction(signed["hex"])

        # Identify the 14.998 PLCU output
        nAB = next(i for i, vout in enumerate(self.nodes[0].getrawtransaction(txAB1, 1)["vout"]) if vout["value"] == amount15 - fee)

        #Create a child tx spending AB1 and C
        inputs = []
        inputs.append({"txid":txAB1, "vout":nAB})
        inputs.append({"txid":txC, "vout":nC})
        outputs = {}
        feeA = Decimal('0.00039800')
        (burnA1, burnA2, changeA) = BurnedAndChangeAmount(amount10 + amount15 - fee - feeA)
        outputs[self.nodes[0].getnewaddress()] = changeA
        outputs[GRAVE_ADDRESS_1] = burnA1
        outputs[GRAVE_ADDRESS_2] = burnA2
        signed2 = self.nodes[0].signrawtransaction(self.nodes[0].createrawtransaction(inputs, outputs))
        txABC2 = self.nodes[0].sendrawtransaction(signed2["hex"])

        # In mempool txs from self should increase balance from change
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - Decimal("30") + changeA)
        balance = newbalance

        # Restart the node with a higher min relay fee so the parent tx is no longer in mempool
        # TODO: redo with eviction
        self.stop_node(0)
        self.start_node(0, extra_args=["-minrelaytxfee=0.00010000"])

        # Verify txs no longer in either node's mempool
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        assert_equal(len(self.nodes[1].getrawmempool()), 0)

        # Not in mempool txs from self should only reduce balance
        # inputs are still spent, but change not received
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - changeA)
        # Unconfirmed received funds that are not in mempool, also shouldn't show
        # up in unconfirmed balance
        unconfbalance = self.nodes[0].getunconfirmedbalance() + self.nodes[0].getbalance()
        assert_equal(unconfbalance, newbalance)
        # Also shouldn't show up in listunspent
        assert(not txABC2 in [utxo["txid"] for utxo in self.nodes[0].listunspent(0)])
        balance = newbalance

        # Abandon original transaction and verify inputs are available again
        # including that the child tx was also abandoned
        self.nodes[0].abandontransaction(txAB1)
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance + amount10 * 3)
        balance = newbalance

        # Verify that even with a low min relay fee, the tx is not reaccepted from wallet on startup once abandoned
        self.stop_node(0)
        self.start_node(0, extra_args=["-minrelaytxfee=0.00001000"])
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        assert_equal(self.nodes[0].getbalance(), balance)

        # But if its received again then it is unabandoned
        # And since now in mempool, the change is available
        # But its child tx remains abandoned
        self.nodes[0].sendrawtransaction(signed["hex"])
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - Decimal("20") + amount15 - fee)
        balance = newbalance

        # Send child tx again so its unabandoned
        self.nodes[0].sendrawtransaction(signed2["hex"])
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - Decimal("10") - (amount15 - fee) + changeA)
        balance = newbalance

        # Remove using high relay fee again
        self.stop_node(0)
        self.start_node(0, extra_args=["-minrelaytxfee=0.01"])
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance - changeA)
        balance = newbalance

        # Create a double spend of AB1 by spending again from only A's 10 output
        # Mine double spend from node 1
        inputs =[]
        inputs.append({"txid":txA, "vout":nA})
        outputs = {}
        feeB = Decimal('0.00010000')
        (burnB1, burnB2, changeB) = BurnedAndChangeAmount(amount10 - feeB)
        outputs[self.nodes[1].getnewaddress()] = Decimal(changeB)
        outputs[GRAVE_ADDRESS_1] = burnB1
        outputs[GRAVE_ADDRESS_2] = burnB2
        tx = self.nodes[0].createrawtransaction(inputs, outputs)
        signed = self.nodes[0].signrawtransaction(tx)
        self.nodes[1].sendrawtransaction(signed["hex"])
        self.nodes[1].generate(1)

        connect_nodes(self.nodes[0], 1)
        sync_blocks(self.nodes)

        # Verify that B and C's 10 PLCU outputs are available for spending again because AB1 is now conflicted
        newbalance = self.nodes[0].getbalance()
        assert_equal(newbalance, balance + amount10 * 2)
        balance = newbalance

        # There is currently a minor bug around this and so this test doesn't work.  See Issue #7315
        # Invalidate the block with the double spend and B's 10 PLCU output should no longer be available
        # Don't think C's should either
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())
        newbalance = self.nodes[0].getbalance()
        #assert_equal(newbalance, balance - Decimal("10"))
        self.log.info("If balance has not declined after invalidateblock then out of mempool wallet tx which is no longer")
        self.log.info("conflicted has not resumed causing its inputs to be seen as spent.  See Issue #7315")
        self.log.info(str(balance) + " -> " + str(newbalance) + " ?")

if __name__ == '__main__':
    AbandonConflictTest().main()
