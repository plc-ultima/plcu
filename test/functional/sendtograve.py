#!/usr/bin/env python3
# Copyright (c) 2021 The PLC Ultima Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.certs import *

'''
sendtograve.py
'''

fee = Decimal('0.00001')


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

class SendToGraveTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = False
        self.extra_args = [['-debug', '-whitelist=127.0.0.1']] * 2
        self.outpoints = []
        self.taxfree_cert_filename = None


    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(1), self.nodes[1], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()


    def check_scen_001(self, amount, super_key, certs, dest_addr, mine_block=True, accepted=True, reject_reason=None):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        null_input = {'txid': '0000000000000000000000000000000000000000000000000000000000000000', 'vout': 0}
        addr1 = node0.getnewaddress()
        txid = node1.sendtoaddress(addr1, amount)
        verify_tx_sent(node1, txid)
        self.sync_all()
        if mine_block:
            node1.generate(1)
            self.sync_all()
        balance_before = node0.getbalance('', 0)
        n = find_output(node0, txid, amount)
        raw_super = node0.createrawtransaction([{'txid': txid, 'vout': n}, null_input], {dest_addr: amount - fee})
        if super_key:
            sig_res = node0.signrawtransaction(raw_super, [],
                                               [SecretBytesToBase58(super_key.get_secret()), node0.dumpprivkey(addr1)],
                                               'ALL', certs, [bytes_to_hex_str(super_key.get_pubkey())])
        else:
            sig_res = node0.signrawtransaction(raw_super)
        self.log.debug(f'check_scen_001, amount: {amount}, super_key: {super_key}, dest_addr: {dest_addr}, mine_block: {mine_block}, sig_res: {sig_res}')
        assert_equal(sig_res['complete'], accepted)
        if accepted:
            assert('errors' not in sig_res or len(sig_res['errors']) == 0)
            txid_super = node0.sendrawtransaction(sig_res['hex'])
            assert_in(txid_super, node0.getrawmempool())
            balance_after = node0.getbalance('', 0)
            assert_equal(balance_before, balance_after + amount)
            if mine_block:
                self.sync_all()
                node1.generate(1)
        else:
            assert_greater_than(len(sig_res['errors']), 0)
            assert_raises_rpc_error(None, reject_reason, node0.sendrawtransaction, sig_res['hex'])
            balance_after = node0.getbalance('', 0)
            assert_equal(balance_before, balance_after)
        self.sync_all()


    def check_sendtoaddress(self, address, amount, subtractfeefromamount, valid_cert):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        balance_before = node0.getbalance('', 0)
        self.log.debug(f'check sendtoaddress: node: 0, balance: {balance_before}, address: {address}, amount: {amount}, subtractfeefromamount: {subtractfeefromamount}, valid_cert: {valid_cert}, height: {node0.getblockcount()}')
        txid = node0.sendtoaddress(address, amount, '', '', subtractfeefromamount)
        verify_tx_sent(node0, txid)
        txraw = node0.getrawtransaction(txid, 1)
        balance_after = node0.getbalance('', 0)
        self.log.debug(f'txraw: {txraw}, balance_after: {balance_after}')
        outputs_cnt = len(txraw['vout'])
        assert_greater_than_or_equal(outputs_cnt, 1)  # dest (if no change)
        assert_greater_than_or_equal(2, outputs_cnt)  # dest + change
        amount_sent_index = find_output_by_address(node0, address, tx_raw=txraw)
        assert_greater_than(amount_sent_index, -1)
        return txid

    def check_sendmany(self, addresses_and_amounts, subtractfeefrom=[], valid_cert=True):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        amount_sum = 0
        for addr in addresses_and_amounts:
            amount_sum += addresses_and_amounts[addr]
        balance_before = node0.getbalance('', 0)
        self.log.debug(f'check sendmany: node: 0, balance: {balance_before}, amount_sum: {amount_sum}, addresses_and_amounts: {addresses_and_amounts}, subtractfeefrom: {subtractfeefrom}, valid_cert: {valid_cert}, height: {node0.getblockcount()}')
        txid = node0.sendmany('', addresses_and_amounts, 1, '', subtractfeefrom)
        verify_tx_sent(node0, txid)
        txraw = node0.getrawtransaction(txid, 1)

        self.log.debug(f'txraw: {txraw}')
        outputs_cnt = len(txraw['vout'])
        assert_greater_than_or_equal(outputs_cnt, len(addresses_and_amounts))  # dests (if no change)
        assert_greater_than_or_equal(len(addresses_and_amounts) + 1, outputs_cnt)  # dests + change
        for addr in addresses_and_amounts:
            amount_sent_index = find_output_by_address(node0, addr, tx_raw=txraw)
            assert_greater_than(amount_sent_index, -1)
        return txid


    def run_scenario(self, amount, with_cert, accepted=True, reject_reason_rpc=None, reject_reason_p2p=None):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        root_cert_hash = None
        pass_cert_hash = None

        if with_cert:
            # Root cert:
            root_cert_key = create_key(True, GENESIS_PRIV_KEY0_BIN)
            root_cert_name = 'root_cert'
            root_cert_flags = 0
            print_key_verbose(root_cert_key, f'root_cert_key in {root_cert_name}')
            (self.outpoints, _) = generate_outpoints(node1, 1, Decimal('1.03') + fee, AddressFromPubkey(root_cert_key.get_pubkey()))
            (tx2, pass_cert_key1) = compose_cert_tx(self.outpoints.pop(0), Decimal(1), root_cert_key, root_cert_name, root_cert_flags)
            root_cert_hash = send_tx(node1, self.test_node, tx2, True)
            node1.generate(1)
            self.sync_all()

            # CA3 cert:
            pass_cert_key = pass_cert_key1
            pass_cert_name = 'pass_cert'
            pass_cert_flags = SUPER_TX
            (self.outpoints, _) = generate_outpoints(node1, 1, Decimal('1.03') + fee, AddressFromPubkey(pass_cert_key.get_pubkey()))
            (tx2, super_key) = compose_cert_tx(self.outpoints.pop(0), Decimal(1), pass_cert_key, pass_cert_name, pass_cert_flags)
            pass_cert_hash = send_tx(node1, self.test_node, tx2, True)
            node1.generate(1)
            self.sync_all()

        restart_node_with_cert(self, with_cert, super_key.get_pubkey() if with_cert else None, root_cert_hash, pass_cert_hash)

        if with_cert:
            node0.importprivkey(SecretBytesToBase58(super_key.get_secret()))

            # createrawtransaction --> signrawtransaction(empty_keys_array) --> sendrawtransaction
            # with and without mining transactions into blocks
            for address in [GRAVE_ADDRESS_1, GRAVE_ADDRESS_2]:
                self.check_scen_001(amount, None, [], address, False, accepted, reject_reason_rpc)

        self.sync_all()
        node1.generate(1)
        self.sync_all()
        assert_equal(len(node0.getrawmempool()), 0)
        assert_equal(len(node1.getrawmempool()), 0)

        for address in [GRAVE_ADDRESS_1, GRAVE_ADDRESS_2]:
            for subtractfeefromamount in [False, True]:
                self.check_sendtoaddress(address, amount, subtractfeefromamount, with_cert)

        self.sync_all()
        node1.generate(1)
        self.sync_all()

        for addresses in [[GRAVE_ADDRESS_1], [GRAVE_ADDRESS_2], [GRAVE_ADDRESS_1, GRAVE_ADDRESS_2]]:
            for subtractfeefrom in [[], [GRAVE_ADDRESS_1], [GRAVE_ADDRESS_2], [GRAVE_ADDRESS_1, GRAVE_ADDRESS_2]]:
                skip_this_combination = False
                for addr in subtractfeefrom:
                    if addr not in addresses:
                        skip_this_combination = True
                        break
                if skip_this_combination:
                    continue
                addresses_and_amounts = {}
                for i in range(len(addresses)):
                    addresses_and_amounts[addresses[i]] = amount * (i+1)
                self.check_sendmany(addresses_and_amounts, subtractfeefrom, with_cert)
        self.sync_all()
        node1.generate(1)
        self.sync_all()
        self.test_node.sync_with_ping()


    def run_test(self):
        # Test cert with node0
        # self.test_node uses node1
        self.taxfree_cert_filename = os.path.join(self.options.tmpdir + '/node0/regtest', 'taxfree.cert')

        self.sync_all()
        self.test_node.sync_with_ping()

        for with_cert in [False, True]:
            self.run_scenario(Decimal(80), with_cert)
            self.run_scenario(Decimal('1.12345678'), with_cert)


if __name__ == '__main__':
    SendToGraveTest().main()
