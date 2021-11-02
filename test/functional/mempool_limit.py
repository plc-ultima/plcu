#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool limiting together/eviction with the wallet."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# Does the same as create_lots_of_big_transactions() function from util.py,
# but also sorts the transactions by size (and fee per KB respectively, so as they all have the same absolute fee).
# It is necessary, because transaction with the smallest fee per KB sent at the end will evict from pool itself
# and we'll get 'mempool full' RPC exception (in some rare cases - not always!)
def create_lots_of_big_transactions2(node, txouts, utxos, num, fee):
    addr = node.getnewaddress()
    txids = []
    signedhextxs = []

    for i in range(num):
        t = utxos.pop()
        inputs=[{ "txid" : t["txid"], "vout" : t["vout"]}]
        outputs = {}
        change = t['amount'] - fee
        outputs[addr] = satoshi_round(change)
        rawtx = node.createrawtransaction(inputs, outputs)
        newtx = rawtx[0:92]
        newtx = newtx + txouts
        newtx = newtx + rawtx[94:]
        signresult = node.signrawtransaction(newtx, None, None, "NONE")
        signedhextxs.append(signresult["hex"])
    signedhextxs.sort(key=len, reverse=True)
    for signedtx in signedhextxs:
        txid = node.sendrawtransaction(signedtx, True)
        txids.append(txid)
    return txids


class MempoolLimitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-maxmempool=5", "-mintxfee=0.00001", "-spendzeroconfchange=0"]]

    def run_test(self):
        txouts = gen_return_txouts()
        relayfee = self.nodes[0].getnetworkinfo()['relayfee']

        txids = []
        utxos = create_confirmed_utxos(relayfee, self.nodes[0], 91)

        #create a mempool tx that will be evicted
        us0 = utxos.pop()
        inputs = [{ "txid" : us0["txid"], "vout" : us0["vout"]}]
        outputs = {self.nodes[0].getnewaddress() : 0.01}
        tx = self.nodes[0].createrawtransaction(inputs, outputs)
        self.nodes[0].settxfee(relayfee) # specifically fund this tx with low fee
        txF = self.nodes[0].fundrawtransaction(tx)
        self.nodes[0].settxfee(0) # return to automatic fee selection
        txFS = self.nodes[0].signrawtransaction(txF['hex'])
        txid = self.nodes[0].sendrawtransaction(txFS['hex'])

        relayfee = self.nodes[0].getnetworkinfo()['relayfee']
        base_fee = relayfee*100
        for i in range (3):
            txids.append([])
            txids[i] = create_lots_of_big_transactions2(self.nodes[0], txouts, utxos[30*i:30*i+30], 30, (i+1)*base_fee)

        # by now, the tx should be evicted, check confirmation state
        assert(txid not in self.nodes[0].getrawmempool())
        txdata = self.nodes[0].gettransaction(txid)
        assert(txdata['confirmations'] ==  0) #confirmation should still be 0

if __name__ == '__main__':
    MempoolLimitTest().main()
