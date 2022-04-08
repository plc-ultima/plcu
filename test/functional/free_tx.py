#!/usr/bin/env python3
# Copyright (c) 2020-2022 The PLC Ultima Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.certs import *

'''
free_tx.py
'''

NORMAL_FEE = Decimal('0.00001000')


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

class FreeTxTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = False
        self.extra_args = [['-debug', '-whitelist=127.0.0.1'], ['-debug', '-whitelist=127.0.0.1', '-limitfreetx=0']]
        self.outpoints = []


    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node0 = TestNode()
        self.test_node1 = TestNode()
        connection0 = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node0)
        connection1 = NodeConn('127.0.0.1', p2p_port(1), self.nodes[1], self.test_node1)
        self.test_node0.add_connection(connection0)
        self.test_node1.add_connection(connection1)
        NetworkThread().start()
        self.test_node0.wait_for_verack()
        self.test_node1.wait_for_verack()
        self.test_node0.sync_with_ping()
        self.test_node1.sync_with_ping()


    def run_scenario(self, name, node, test_node, amount, fee, accepted=True, reject_reason_rpc=None, reject_reason_p2p=None):
        self.log.info(f'Start scenario {name} ...')

        amount = amount if amount is not None else Decimal(75)
        user_key = create_key()
        dest_pkh = hash160(b'xepppp-001')
        dest_script = GetP2PKHScript(dest_pkh)
        (self.outpoints, _) = generate_outpoints(node, 2, amount, AddressFromPubkey(user_key.get_pubkey()))
        node.generate(1)
        self.sync_all()

        transactions = []
        (burn1, burn2, rest) = BurnedAndChangeAmount(amount - fee)
        destinations = {GraveScript1(): burn1, GraveScript2(): burn2, dest_script: rest}
        for _ in range(2):
            tx = compose_tx([self.outpoints.pop()], user_key, destinations)
            transactions.append(tx)

        # Check p2p, normal tx:
        tx3 = transactions.pop()
        txid3 = send_tx(node, test_node, tx3, accepted, reject_reason_p2p, verbose=True, try_mine_in_block=False)

        # RPC, normal tx:
        tx4 = transactions.pop()
        tx4hex = bytes_to_hex_str(tx4.serialize())
        if accepted:
            txid4 = node.sendrawtransaction(tx4hex)
            assert_in(txid3, node.getrawmempool())
            assert_in(txid4, node.getrawmempool())
            template = node.getblocktemplate()
            template_txids = [tx['txid'] for tx in template['transactions']]
            assert_in(txid3, template_txids)
            assert_in(txid4, template_txids)
            last_block_hash = node.generate(1)[0]
            last_block = node.getblock(last_block_hash)
            assert_in(txid3, last_block['tx'])
            assert_in(txid4, last_block['tx'])
        else:
            assert_raises_rpc_error(None, reject_reason_rpc, node.sendrawtransaction, tx4hex)

        test_node.sync_with_ping()
        self.sync_all()
        self.log.debug(f'Finish scenario {name}')


    def run_test(self):
        amount = Decimal(80)

        self.run_scenario('with_fee_node0', self.nodes[0], self.test_node0, amount, NORMAL_FEE)
        self.run_scenario('with_fee_node1', self.nodes[1], self.test_node1, amount, NORMAL_FEE)
        self.run_scenario('without_fee_node0', self.nodes[0], self.test_node0, amount, 0,
                          accepted=False,
                          reject_reason_p2p='min relay fee not met',
                          reject_reason_rpc='min relay fee not met')
        self.run_scenario('without_fee_node1', self.nodes[1], self.test_node1, amount, 0)


if __name__ == '__main__':
    FreeTxTest().main()
