#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test gettxoutproof and verifytxoutproof RPCs."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.key import *
from test_framework.mininode import *
from test_framework.script import *

class MerkleBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        # Nodes 0/1 are "wallet" nodes, Nodes 2/3 are used for testing
        self.extra_args = [[], [], [], ["-txindex"]]

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[0], 2)
        connect_nodes(self.nodes[0], 3)

        self.sync_all()

    def run_test(self):
        self.log.info("Mining blocks...")
        self.nodes[0].generate(105)
        self.sync_all()

        chain_height = self.nodes[1].getblockcount()
        assert_equal(chain_height, 105)
        assert_equal(self.nodes[1].getbalance(), 0)
        assert_equal(self.nodes[2].getbalance(), 0)

        node0utxos = self.nodes[0].listunspent(1)
        fee = Decimal('0.00001000')
        (burn1, burn2, restA) = BurnedAndChangeAmount(BASE_CB_AMOUNT - fee)
        tx1 = self.nodes[0].createrawtransaction([node0utxos[0]], {self.nodes[1].getnewaddress(): restA, GRAVE_ADDRESS_1: burn1, GRAVE_ADDRESS_2: burn2})
        txid1 = self.nodes[0].sendrawtransaction(self.nodes[0].signrawtransaction(tx1)["hex"])
        tx2 = self.nodes[0].createrawtransaction([node0utxos[1]], {self.nodes[1].getnewaddress(): restA, GRAVE_ADDRESS_1: burn1, GRAVE_ADDRESS_2: burn2})
        txid2 = self.nodes[0].sendrawtransaction(self.nodes[0].signrawtransaction(tx2)["hex"])
        # This will raise an exception because the transaction is not yet in a block
        assert_raises_rpc_error(-5, "Transaction not yet in block", self.nodes[0].gettxoutproof, [txid1])

        self.nodes[0].generate(1)
        blockhash = self.nodes[0].getblockhash(chain_height + 1)
        self.sync_all()

        txlist = []
        blocktxn = self.nodes[0].getblock(blockhash, True)["tx"]
        txlist.append(blocktxn[1])
        txlist.append(blocktxn[2])

        assert_equal(self.nodes[2].verifytxoutproof(self.nodes[2].gettxoutproof([txid1])), [txid1])
        assert_equal(self.nodes[2].verifytxoutproof(self.nodes[2].gettxoutproof([txid1, txid2])), txlist)
        assert_equal(self.nodes[2].verifytxoutproof(self.nodes[2].gettxoutproof([txid1, txid2], blockhash)), txlist)

        # We cannot spend tx with grave outputs - so this part of test is skipped


if __name__ == '__main__':
    MerkleBlockTest().main()
