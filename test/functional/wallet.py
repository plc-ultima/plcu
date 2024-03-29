#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


FEE = Decimal('0.00002000')

class WalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.extra_args = [['-usehd={:d}'.format(i%2==0)] for i in range(4)]

    def setup_network(self):
        self.add_nodes(4, self.extra_args)
        self.start_node(0)
        self.start_node(1)
        self.start_node(2)
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        self.sync_all([self.nodes[0:3]])

    def check_fee_amount(self, curr_balance, balance_with_fee, fee_per_byte, tx_size):
        """Return curr_balance after asserting the fee was in range"""
        fee = balance_with_fee - curr_balance
        assert_fee_amount(fee, tx_size, fee_per_byte * 1000)
        return curr_balance

    def run_test(self):
        NEXT_CB_AMOUNT = Decimal('0.005')

        # Check that there's no UTXO on none of the nodes
        assert_equal(len(self.nodes[0].listunspent()), 0)
        assert_equal(len(self.nodes[1].listunspent()), 0)
        assert_equal(len(self.nodes[2].listunspent()), 0)

        self.log.info("Mining blocks...")

        self.nodes[0].generate(1)

        walletinfo = self.nodes[0].getwalletinfo()
        assert_equal(walletinfo['immature_balance'], BASE_CB_AMOUNT)
        assert_equal(walletinfo['balance'], 0)

        self.sync_all([self.nodes[0:3]])
        self.nodes[1].generate(101)
        self.sync_all([self.nodes[0:3]])

        assert_equal(self.nodes[0].getbalance(), BASE_CB_AMOUNT)
        assert_equal(self.nodes[1].getbalance(), BASE_CB_AMOUNT)
        assert_equal(self.nodes[2].getbalance(), 0)

        # Check that only first and second nodes have UTXOs
        utxos = self.nodes[0].listunspent()
        assert_equal(len(utxos), 1)
        assert_equal(len(self.nodes[1].listunspent()), 1)
        assert_equal(len(self.nodes[2].listunspent()), 0)

        self.log.info("test gettxout")
        confirmed_txid, confirmed_index = utxos[0]["txid"], utxos[0]["vout"]
        # First, outputs that are unspent both in the chain and in the
        # mempool should appear with or without include_mempool
        txout = self.nodes[0].gettxout(txid=confirmed_txid, n=confirmed_index, include_mempool=False)
        assert_equal(txout['value'], BASE_CB_AMOUNT)
        txout = self.nodes[0].gettxout(txid=confirmed_txid, n=confirmed_index, include_mempool=True)
        assert_equal(txout['value'], BASE_CB_AMOUNT)
        
        # Send 21 PLCU from 0 to 2 using sendtoaddress call.
        # Locked memory should use at least 32 bytes to sign each transaction
        self.log.info("test getmemoryinfo")
        memory_before = self.nodes[0].getmemoryinfo()
        txid1 = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 11)
        verify_tx_sent(self.nodes[0], txid1)
        mempool_txid = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 10)
        verify_tx_sent(self.nodes[0], mempool_txid)
        memory_after = self.nodes[0].getmemoryinfo()
        # assert(memory_before['locked']['used'] + 64 <= memory_after['locked']['used'])  # hz

        self.log.info("test gettxout (second part)")
        # utxo spent in mempool should be visible if you exclude mempool
        # but invisible if you include mempool
        txout = self.nodes[0].gettxout(confirmed_txid, confirmed_index, False)
        assert_equal(txout['value'], BASE_CB_AMOUNT)
        txout = self.nodes[0].gettxout(confirmed_txid, confirmed_index, True)
        assert txout is None
        # new utxo from mempool should be invisible if you exclude mempool
        # but visible if you include mempool
        output_indexes = [0, 1, 2, 3]
        burn1_index = find_output_by_address(self.nodes[0], GRAVE_ADDRESS_1, mempool_txid)
        burn2_index = find_output_by_address(self.nodes[0], GRAVE_ADDRESS_2, mempool_txid)
        output_indexes.remove(burn1_index)
        output_indexes.remove(burn2_index)
        txout = self.nodes[0].gettxout(mempool_txid, output_indexes[0], False)
        assert txout is None
        txout1 = self.nodes[0].gettxout(mempool_txid, output_indexes[0], True)
        txout2 = self.nodes[0].gettxout(mempool_txid, output_indexes[1], True)
        # note the mempool tx will have randomly assigned indices
        # but 10 will go to node2 and the rest will go to node0
        balance = self.nodes[0].getbalance()
        assert_equal(set([txout1['value'], txout2['value']]), set([10, balance]))
        walletinfo = self.nodes[0].getwalletinfo()
        assert_equal(walletinfo['immature_balance'], 0)

        # Have node0 mine a block (it will NOT collect its own fee)
        self.nodes[0].generate(1)
        self.sync_all([self.nodes[0:3]])

        # Exercise locking of unspent outputs
        unspent_0 = self.nodes[2].listunspent()[0]
        unspent_0 = {"txid": unspent_0["txid"], "vout": unspent_0["vout"]}
        self.nodes[2].lockunspent(False, [unspent_0])
        assert_raises_rpc_error(None, "Insufficient funds", self.nodes[2].sendtoaddress, self.nodes[2].getnewaddress(), 20)
        assert_equal([unspent_0], self.nodes[2].listlockunspent())
        self.nodes[2].lockunspent(True, [unspent_0])
        assert_equal(len(self.nodes[2].listlockunspent()), 0)

        # Have node1 generate 100 blocks
        self.nodes[1].generate(100)
        self.sync_all([self.nodes[0:3]])

        # node0 should end up with (BASE_CB_AMOUNT + NEXT_CB_AMOUNT) plc in block rewards, but
        # minus the 21 plus fees sent to node2
        fees1 = -(self.nodes[0].gettransaction(txid1)['fee'] + self.nodes[0].gettransaction(mempool_txid)['fee'])
        node0_balance = BASE_CB_AMOUNT + NEXT_CB_AMOUNT - 21 - fees1
        # assert_equal(self.nodes[0].getbalance(), node0_balance)
        assert_equal(self.nodes[2].getbalance(), 21)

        # Node0 should have two unspent outputs.
        # Create a couple of transactions to send them to node2, submit them through
        # node1, and make sure both node0 and node2 pick them up properly:
        node0utxos = self.nodes[0].listunspent(1)
        assert_equal(len(node0utxos), 2)

        # create both transactions
        HIGH_FEE = Decimal('0.00002000')
        txns_to_send = []
        for utxo in node0utxos:
            inputs = []
            outputs = {}
            inputs.append({ "txid" : utxo["txid"], "vout" : utxo["vout"]})
            (burn1, burn2, rest) = BurnedAndChangeAmount(utxo["amount"] - HIGH_FEE)
            outputs[self.nodes[2].getnewaddress("from1")] = rest
            outputs[GRAVE_ADDRESS_1] = burn1
            outputs[GRAVE_ADDRESS_2] = burn2
            raw_tx = self.nodes[0].createrawtransaction(inputs, outputs)
            txns_to_send.append(self.nodes[0].signrawtransaction(raw_tx))

        # Have node 1 (miner) send the transactions
        self.nodes[1].sendrawtransaction(txns_to_send[0]["hex"], True)
        self.nodes[1].sendrawtransaction(txns_to_send[1]["hex"], True)

        # Have node1 mine a block to confirm transactions:
        self.nodes[1].generate(1)
        self.sync_all([self.nodes[0:3]])

        assert_equal(self.nodes[0].getbalance(), 0)
        # assert_equal(self.nodes[2].getbalance(), node0_balance + 21 - HIGH_FEE*2)
        # assert_equal(self.nodes[2].getbalance("from1"), node0_balance - HIGH_FEE*2)

        # Send 10 PLCU normal
        address = self.nodes[0].getnewaddress("test")
        fee_per_byte = Decimal('0.001') / 1000
        self.nodes[2].settxfee(fee_per_byte * 1000)
        txid = self.nodes[2].sendtoaddress(address, 10, "", "", False)
        verify_tx_sent(self.nodes[2], txid)
        self.nodes[2].generate(1)
        self.sync_all([self.nodes[0:3]])
        fee = -(self.nodes[2].gettransaction(txid)['fee'])
        node_2_bal = self.check_fee_amount(self.nodes[2].getbalance(), self.nodes[2].getbalance() + fee, fee_per_byte, count_bytes(self.nodes[2].getrawtransaction(txid)))
        assert_equal(self.nodes[0].getbalance(), Decimal('10'))

        # Send 10 PLCU with subtract fee from amount
        self.log.info(f'self.nodes[2].getbalance: {self.nodes[2].getbalance()}')
        txid = self.nodes[2].sendtoaddress(address, 10, "", "", True)
        verify_tx_sent(self.nodes[2], txid)
        txraw = self.nodes[2].getrawtransaction(txid, 1)
        burn1_out_ind = find_output_by_address(None, GRAVE_ADDRESS_1, tx_raw=txraw)
        burn2_out_ind = find_output_by_address(None, GRAVE_ADDRESS_2, tx_raw=txraw)
        burn1 = txraw['vout'][burn1_out_ind]['value']
        burn2 = txraw['vout'][burn2_out_ind]['value']
        self.nodes[2].generate(1)
        self.sync_all([self.nodes[0:3]])
        node_2_bal -= Decimal('10')
        assert_equal(self.nodes[2].getbalance(), node_2_bal)
        fee = -(self.nodes[2].gettransaction(txid)['fee'])
        node_0_bal = self.check_fee_amount(self.nodes[0].getbalance(), self.nodes[0].getbalance() + fee, fee_per_byte, count_bytes(self.nodes[2].getrawtransaction(txid)))

        # Sendmany 10 PLCU
        txid = self.nodes[2].sendmany('from1', {address: 10}, 0, "", [])
        verify_tx_sent(self.nodes[2], txid)
        self.nodes[2].generate(1)
        self.sync_all([self.nodes[0:3]])
        node_0_bal += Decimal('10')
        fee = -(self.nodes[2].gettransaction(txid)['fee'])
        node_2_bal = self.check_fee_amount(self.nodes[2].getbalance(), self.nodes[2].getbalance() + fee, fee_per_byte, count_bytes(self.nodes[2].getrawtransaction(txid)))
        assert_equal(self.nodes[0].getbalance(), node_0_bal)

        # Sendmany 10 PLCU with subtract fee from amount
        txid = self.nodes[2].sendmany('from1', {address: 10}, 0, "", [address])
        verify_tx_sent(self.nodes[2], txid)
        self.nodes[2].generate(1)
        self.sync_all([self.nodes[0:3]])
        node_2_bal -= Decimal('10')
        assert_equal(self.nodes[2].getbalance(), node_2_bal)
        fee = -(self.nodes[2].gettransaction(txid)['fee'])
        node_0_bal = self.check_fee_amount(self.nodes[0].getbalance(), self.nodes[0].getbalance() + fee, fee_per_byte, count_bytes(self.nodes[2].getrawtransaction(txid)))

        # Test ResendWalletTransactions:
        # Create a couple of transactions, then start up a fourth
        # node (nodes[3]) and ask nodes[0] to rebroadcast.
        # EXPECT: nodes[3] should have those transactions in its mempool.
        txid1 = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1)
        verify_tx_sent(self.nodes[0], txid1)
        txid2 = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        verify_tx_sent(self.nodes[1], txid2)
        sync_mempools(self.nodes[0:2])

        self.start_node(3)
        connect_nodes_bi(self.nodes, 0, 3)
        sync_blocks(self.nodes)

        relayed = self.nodes[0].resendwallettransactions()
        assert_equal(set(relayed), {txid1, txid2})
        sync_mempools(self.nodes)

        assert(txid1 in self.nodes[3].getrawmempool())

        # Exercise balance rpcs
        assert_equal(self.nodes[0].getwalletinfo()["unconfirmed_balance"], 1)
        assert_equal(self.nodes[0].getunconfirmedbalance(), 1)

        #check if we can list zero value tx as available coins
        #1. create rawtx
        #2. hex-changed one output to 0.0
        #3. sign and send
        #4. check if recipient (node0) can list the zero value tx
        usp = node_listunspent(self.nodes[1], minimumAmount=BASE_CB_AMOUNT)
        inputs = [{"txid":usp[0]['txid'], "vout":usp[0]['vout']}]
        (burn1, burn2, rest) = BurnedAndChangeAmount(BASE_CB_AMOUNT - FEE)
        outputs = {self.nodes[1].getnewaddress(): rest, self.nodes[0].getnewaddress(): 11.11, GRAVE_ADDRESS_1: burn1, GRAVE_ADDRESS_2: burn2}

        rawTx = self.nodes[1].createrawtransaction(inputs, outputs).replace("c0833842", "00000000") #replace 11.11 with 0.0 (int32)
        decRawTx = self.nodes[1].decoderawtransaction(rawTx)
        signedRawTx = self.nodes[1].signrawtransaction(rawTx)
        decRawTx = self.nodes[1].decoderawtransaction(signedRawTx['hex'])
        zeroValueTxid= decRawTx['txid']
        sendResp = self.nodes[1].sendrawtransaction(signedRawTx['hex'])

        self.sync_all()
        self.nodes[1].generate(1) #mine a block
        self.sync_all()

        unspentTxs = self.nodes[0].listunspent() #zero value tx must be in listunspents output
        found = False
        for uTx in unspentTxs:
            if uTx['txid'] == zeroValueTxid:
                found = True
                assert_equal(uTx['amount'], Decimal('0'))
        assert(found)

        #do some -walletbroadcast tests
        self.stop_nodes()
        self.start_node(0, ["-walletbroadcast=0"])
        self.start_node(1, ["-walletbroadcast=0"])
        self.start_node(2, ["-walletbroadcast=0"])
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        self.sync_all([self.nodes[0:3]])

        txIdNotBroadcasted  = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 2)
        txObjNotBroadcasted = self.nodes[0].gettransaction(txIdNotBroadcasted)
        self.nodes[1].generate(1) #mine a block, tx should not be in there
        self.sync_all([self.nodes[0:3]])
        assert_equal(self.nodes[2].getbalance(), node_2_bal) #should not be changed because tx was not broadcasted

        #now broadcast from another node, mine a block, sync, and check the balance
        self.nodes[1].sendrawtransaction(txObjNotBroadcasted['hex'])
        self.nodes[1].generate(1)
        self.sync_all([self.nodes[0:3]])
        node_2_bal += 2
        txObjNotBroadcasted = self.nodes[0].gettransaction(txIdNotBroadcasted)
        assert_equal(self.nodes[2].getbalance(), node_2_bal)

        #create another tx
        txIdNotBroadcasted  = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 2)

        #restart the nodes with -walletbroadcast=1
        self.stop_nodes()
        self.start_node(0)
        self.start_node(1)
        self.start_node(2)
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,0,2)
        sync_blocks(self.nodes[0:3])

        self.nodes[0].generate(1)
        sync_blocks(self.nodes[0:3])
        node_2_bal += 2

        #tx should be added to balance because after restarting the nodes tx should be broadcastet
        assert_equal(self.nodes[2].getbalance(), node_2_bal)

        #send a tx with value in a string (PR#6380 +)
        amount_str = '2'
        amount = Decimal(amount_str)
        txId  = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), amount_str)
        verify_tx_sent(self.nodes[0], txId)
        txObj = self.nodes[0].gettransaction(txId)
        assert_equal(-txObj['amount'], amount + sum(GetBurnedValue(amount))) # node returns here (amount + burned), not pure amount

        amount_str = '0.001'
        amount = Decimal(amount_str)
        txId  = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), amount_str)
        verify_tx_sent(self.nodes[0], txId)
        txObj = self.nodes[0].gettransaction(txId)
        assert_equal(-txObj['amount'], amount + sum(GetBurnedValue(amount))) # node returns here (amount + burned), not pure amount

        #check if JSON parser can handle scientific notation in strings
        txId  = self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), "1e-3")
        verify_tx_sent(self.nodes[0], txId)
        txObj = self.nodes[0].gettransaction(txId)
        assert_equal(-txObj['amount'], amount + sum(GetBurnedValue(amount))) # node returns here (amount + burned), not pure amount

        # This will raise an exception because the amount type is wrong
        assert_raises_rpc_error(-3, "Invalid amount", self.nodes[0].sendtoaddress, self.nodes[2].getnewaddress(), "1f-4")

        # This will raise an exception since generate does not accept a string
        assert_raises_rpc_error(-1, "not an integer", self.nodes[0].generate, "2")

        # Import address and private key to check correct behavior of spendable unspents
        # 1. Send some coins to generate new UTXO
        address_to_import = self.nodes[2].getnewaddress()
        txid = self.nodes[0].sendtoaddress(address_to_import, 1)
        verify_tx_sent(self.nodes[0], txid)
        self.nodes[0].generate(1)
        self.sync_all([self.nodes[0:3]])

        # 2. Import address from node2 to node1
        self.nodes[1].importaddress(address_to_import)

        # 3. Validate that the imported address is watch-only on node1
        assert(self.nodes[1].validateaddress(address_to_import)["iswatchonly"])

        # 4. Check that the unspents after import are not spendable
        assert_array_result(self.nodes[1].listunspent(),
                           {"address": address_to_import},
                           {"spendable": False})

        # 5. Import private key of the previously imported address on node1
        priv_key = self.nodes[2].dumpprivkey(address_to_import)
        self.nodes[1].importprivkey(priv_key)

        # 6. Check that the unspents are now spendable on node1
        assert_array_result(self.nodes[1].listunspent(),
                           {"address": address_to_import},
                           {"spendable": True})

        # Mine a block from node0 to an address from node1
        cbAddr = self.nodes[1].getnewaddress()
        blkHash = self.nodes[0].generatetoaddress(1, cbAddr)[0]
        cbTxId = self.nodes[0].getblock(blkHash)['tx'][0]
        self.sync_all([self.nodes[0:3]])

        # Check that the txid and balance is found by node1
        self.nodes[1].gettransaction(cbTxId)

        # check if wallet or blockchain maintenance changes the balance
        self.sync_all([self.nodes[0:3]])
        blocks = self.nodes[0].generate(2)
        self.sync_all([self.nodes[0:3]])
        balance_nodes = [self.nodes[i].getbalance() for i in range(3)]
        block_count = self.nodes[0].getblockcount()

        # Check modes:
        #   - True: unicode escaped as \u....
        #   - False: unicode directly as UTF-8
        for mode in [True, False]:
            self.nodes[0].ensure_ascii = mode
            # unicode check: Basic Multilingual Plane, Supplementary Plane respectively
            for s in [u'рыба', u'𝅘𝅥𝅯']:
                addr = self.nodes[0].getaccountaddress(s)
                label = self.nodes[0].getaccount(addr)
                assert_equal(label, s)
                assert(s in self.nodes[0].listaccounts().keys())
        self.nodes[0].ensure_ascii = True # restore to default

        # maintenance tests
        maintenance = [
            '-rescan',
            '-reindex',
            '-zapwallettxes=1',
            '-zapwallettxes=2',
            # disabled until issue is fixed: https://github.com/bitcoin/bitcoin/issues/7463
            # '-salvagewallet',
        ]
        chainlimit = 6
        for m in maintenance:
            self.log.info("check " + m)
            self.stop_nodes()
            # set lower ancestor limit for later
            self.start_node(0, [m, "-limitancestorcount="+str(chainlimit)])
            self.start_node(1, [m, "-limitancestorcount="+str(chainlimit)])
            self.start_node(2, [m, "-limitancestorcount="+str(chainlimit)])
            while m == '-reindex' and [block_count] * 3 != [self.nodes[i].getblockcount() for i in range(3)]:
                # reindex will leave rpc warm up "early"; Wait for it to finish
                time.sleep(0.1)
            assert_equal(balance_nodes, [self.nodes[i].getbalance() for i in range(3)])

        # Exercise listsinceblock with the last two blocks
        coinbase_tx_1 = self.nodes[0].listsinceblock(blocks[0])
        assert_equal(coinbase_tx_1["lastblock"], blocks[1])
        assert_equal(len(coinbase_tx_1["transactions"]), 1)
        assert_equal(coinbase_tx_1["transactions"][0]["blockhash"], blocks[1])
        assert_equal(len(self.nodes[0].listsinceblock(blocks[1])["transactions"]), 0)

        # ==Check that wallet prefers to use coins that don't exceed mempool limits =====

        # Get all non-zero utxos together
        chain_addrs = [self.nodes[0].getnewaddress(), self.nodes[0].getnewaddress()]
        singletxid = self.nodes[0].sendtoaddress(chain_addrs[0], self.nodes[0].getbalance(), "", "", True)
        verify_tx_sent(self.nodes[0], singletxid)
        self.nodes[0].generate(1)
        node0_balance = self.nodes[0].getbalance()
        # Split into two chains
        (burn1, burn2, rest) = BurnedAndChangeAmount(node0_balance)
        rawtx = self.nodes[0].createrawtransaction([{"txid": singletxid, "vout": 0}], {
            chain_addrs[0]: rest / 2 - FEE / 2,
            chain_addrs[1]: rest / 2 - FEE / 2,
            GRAVE_ADDRESS_1: burn1,
            GRAVE_ADDRESS_2: burn2,
        })
        signedtx = self.nodes[0].signrawtransaction(rawtx)
        singletxid = self.nodes[0].sendrawtransaction(signedtx["hex"])
        self.nodes[0].generate(1)

        # Make a long chain of unconfirmed payments without hitting mempool limit
        # Each tx we make leaves only one output of change on a chain 1 longer
        # Since the amount to send is always much less than the outputs, we only ever need one output
        # So we should be able to generate exactly chainlimit txs for each original output
        sending_addr = self.nodes[1].getnewaddress()
        txid_list = []
        for i in range(chainlimit*2):
            txid_list.append(self.nodes[0].sendtoaddress(sending_addr, Decimal('0.01')))
        [verify_tx_sent(self.nodes[0], txid) for txid in txid_list]
        assert_equal(self.nodes[0].getmempoolinfo()['size'], chainlimit*2)
        assert_equal(len(txid_list), chainlimit*2)

        # Without walletrejectlongchains, we will still generate a txid
        # The tx will be stored in the wallet but not accepted to the mempool
        # since version 2.10, transactions not accepted to mempool don't get into wallet too
        # extra_txid = self.nodes[0].sendtoaddress(sending_addr, Decimal('0.01'))
        # assert(extra_txid not in self.nodes[0].getrawmempool())
        # assert(extra_txid in [tx["txid"] for tx in self.nodes[0].listtransactions()])
        # self.nodes[0].abandontransaction(extra_txid)
        total_txs = len(self.nodes[0].listtransactions("*",99999))

        # Try with walletrejectlongchains
        # Double chain limit but require combining inputs, so we pass SelectCoinsMinConf
        self.stop_node(0)
        self.start_node(0, extra_args=["-walletrejectlongchains", "-limitancestorcount="+str(2*chainlimit)])

        # wait for loadmempool
        timeout = 10
        while (timeout > 0 and len(self.nodes[0].getrawmempool()) < chainlimit*2):
            time.sleep(0.5)
            timeout -= 0.5
        assert_equal(len(self.nodes[0].getrawmempool()), chainlimit*2)

        node0_balance = self.nodes[0].getbalance()
        # With walletrejectlongchains we will not create the tx and store it in our wallet.
        assert_raises_rpc_error(-4, "Transaction has too long of a mempool chain", self.nodes[0].sendtoaddress, sending_addr, node0_balance, '', '', True)

        # Verify nothing new in wallet
        assert_equal(total_txs, len(self.nodes[0].listtransactions("*",99999)))

if __name__ == '__main__':
    WalletTest().main()
