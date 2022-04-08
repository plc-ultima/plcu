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
from test_framework.blocktools import create_coinbase, create_block

'''
mining_cert.py
'''

fee = Decimal('0.00001')
BAD_CERT_P2P = 'bad-cb-cert'
TAXFREE_CERT_NOT_LOADED = 'TaxFree cert not loaded - '
INV_CERT_CHAIN = 'Invalid cert chain'
MINING_NOT_ALLOWED = 'Mining not allowed'
ERRORS_RPC = [TAXFREE_CERT_NOT_LOADED, INV_CERT_CHAIN, MINING_NOT_ALLOWED]
CERTS_AFTER_HEIGHT = 550

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


class MiningCertTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = False
        self.extra_args = [['-debug', '-whitelist=127.0.0.1']] * 2
        self.outpoints = []
        self.taxfree_cert_filename = None
        self.certs = {}

    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(1), self.nodes[1], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()

    def check_generate(self, cert_used, accepted=True, reject_reason=None):
        node0 = self.nodes[0]
        self.log.debug(f'check_generate, cert_used: {cert_used}, accepted: {accepted}')
        if accepted:
            block_hashes = node0.generate(1)
            block = node0.getblock(block_hashes[0], 2)
            cb_tx = block['tx'][0]
            inputs = cb_tx['vin']
            assert_equal(not cert_used, len(inputs) == 1)
            assert_equal(cert_used, len(inputs) == 2)
            if cert_used:
                assert_in('coinbase', inputs[1])
        else:
            assert_raises_rpc_error(None, reject_reason, node0.generate, 1)
        self.sync_all()


    def restart_node_0(self, use_cert, super_key_pubkey=None, root_cert_hash=None, pass_cert_hash=None, accepted=True):
        node0 = self.nodes[0]
        if use_cert:
            write_taxfree_cert_to_file(self.taxfree_cert_filename, super_key_pubkey, root_cert_hash, pass_cert_hash)
        self.stop_node(0)
        more_args = [f'-taxfreecert={self.taxfree_cert_filename}'] if use_cert else []
        self.start_node(0, extra_args=self.extra_args[0] + more_args)
        connect_nodes(self.nodes[0], 1)
        if use_cert and accepted:
            assert_equal(node0.getwalletinfo()['taxfree_certificate'], self.taxfree_cert_filename)
        elif not use_cert:
            assert_not_in('taxfree_certificate', node0.getwalletinfo())


    def generate_cert(self, name, root_cert_key=None, root_cert_flags=None, root_cert_hash=None,
                     root_cert_sig_hash=None, root_cert_sig_key=None, root_cert_signature=None, root_cert_revoked=False,
                     pass_cert_key=None, pass_cert_flags=None, pass_cert_hash=None,
                     pass_cert_sig_hash=None, pass_cert_sig_key=None, pass_cert_signature=None, pass_cert_revoked=False,
                     super_key=None):
        node1 = self.nodes[1]
        cert = generate_certs_pair(node1, self.test_node, root_cert_key=root_cert_key, root_cert_flags=root_cert_flags,
                                   root_cert_hash=root_cert_hash, root_cert_sig_hash=root_cert_sig_hash,
                                   root_cert_sig_key=root_cert_sig_key, root_cert_signature=root_cert_signature,
                                   root_cert_revoked=root_cert_revoked, pass_cert_key=pass_cert_key,
                                   pass_cert_flags=pass_cert_flags, pass_cert_hash=pass_cert_hash,
                                   pass_cert_sig_hash=pass_cert_sig_hash, pass_cert_sig_key=pass_cert_sig_key,
                                   pass_cert_signature=pass_cert_signature, pass_cert_revoked=pass_cert_revoked,
                                   super_key=super_key, fee=fee, pass_cert_flag_default=ALLOW_MINING)
        node1.generate(1)
        self.sync_all()
        assert_not_in(name, self.certs)
        self.certs[name] = cert


    def run_scenario(self, name, use_cert, cert_needed=None, accepted=True, reject_reason_rpc=None,
                     reject_reason_p2p=None, unload_cert_on_finish=False):
        self.log.info(f'Start scenario {name} ...')
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        assert_not_in('taxfree_certificate', node1.getwalletinfo())
        cert_needed = cert_needed if cert_needed is not None else use_cert
        reject_reason_p2p = reject_reason_p2p if reject_reason_p2p is not None else BAD_CERT_P2P
        reject_reason_rpc = reject_reason_rpc if reject_reason_rpc is not None else ERRORS_RPC

        if use_cert:
            assert_in(name, self.certs)
            cert = self.certs[name]
            root_cert_hash = cert[0]
            pass_cert_hash = cert[1]
            super_key = cert[2]
            del self.certs[name]
        else:
            assert_not_in('taxfree_certificate', node0.getwalletinfo())

        # Check p2p first:
        # tmpl = node0.getblocktemplate() # it doesn't work without certificate
        parent_hash = node0.getbestblockhash()
        parent_block = node0.getblock(parent_hash)
        coinbase = create_coinbase(parent_block['height'] + 1)
        if use_cert:
            coinbase = add_cert_to_coinbase(coinbase, COutPoint(int(root_cert_hash, 16), 0),
                                            COutPoint(int(pass_cert_hash, 16), 0), super_key)
        block = create_block(int(parent_hash, 16), coinbase, parent_block['time'] + 1, int(parent_block['bits'], 16), VB_TOP_BITS)
        send_block(self.nodes[1], self.test_node, block, accepted, reject_reason_p2p)

        # And now RPC:
        if use_cert:
            node0.importprivkey(SecretBytesToBase58(super_key.get_secret()))
            self.restart_node_0(True, super_key.get_pubkey(), root_cert_hash, pass_cert_hash, accepted)
        self.check_generate(cert_needed, accepted, reject_reason_rpc)
        if use_cert and unload_cert_on_finish:
            self.restart_node_0(False)
        self.test_node.sync_with_ping()
        self.log.debug(f'Finish scenario {name}')


    def run_test(self):
        # Test cert with node0
        # self.test_node uses node1
        self.taxfree_cert_filename = os.path.join(self.options.tmpdir + '/node0/regtest', 'taxfree.cert')
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        txid = node0.sendtoaddress(node1.getnewaddress(), 1)
        verify_tx_sent(node0, txid)
        node0.generate(1)
        self.sync_all()
        self.test_node.sync_with_ping()

        # generate all certs before start running testcases, because we need generate() call when generating certs:
        self.generate_cert('positive_with_cert_before_cert_needed')
        self.generate_cert('positive_with_cert_after_cert_needed')
        self.generate_cert('positive_both_flags', pass_cert_flags=SUPER_TX | ALLOW_MINING)
        self.generate_cert('positive_required_flag_in_root_cert_v1', pass_cert_flags=0, root_cert_flags=ALLOW_MINING)
        self.generate_cert('positive_required_flag_in_root_cert_v2', pass_cert_flags=SUPER_TX | SILVER_HOOF, root_cert_flags=ALLOW_MINING)
        self.generate_cert('missing_root_cert', root_cert_hash=bytes_to_hex_str(hash256(b'xyu')))
        self.generate_cert('missing_pass_cert', pass_cert_hash=bytes_to_hex_str(hash256(b'xyu-again')))
        self.generate_cert('tx_instead_of_root_cert', root_cert_hash=txid)
        self.generate_cert('tx_instead_of_pass_cert', pass_cert_hash=txid)
        fake_root_key = create_key()
        self.generate_cert('root_cert_is_not_root', root_cert_key=fake_root_key)
        fake_pass_key = create_key()
        self.generate_cert('pass_cert_is_not_child_of_root', pass_cert_key=fake_pass_key)
        fake_super_key = create_key()
        self.generate_cert('super_key_not_mentioned_in_cert', super_key=fake_super_key)
        self.generate_cert('no_required_flag_in_cert_v1', pass_cert_flags=0)
        self.generate_cert('no_required_flag_in_cert_v2', pass_cert_flags=SUPER_TX | SILVER_HOOF)
        self.generate_cert('root_cert_revoked', root_cert_revoked=True)
        self.generate_cert('pass_cert_revoked', pass_cert_revoked=True)
        self.generate_cert('root_cert_empty_signature', root_cert_signature=b'', )
        self.generate_cert('pass_cert_empty_signature', pass_cert_signature=b'')
        self.generate_cert('root_cert_invalid_sig_hash', root_cert_sig_hash=hash256(b'no!'))
        self.generate_cert('pass_cert_invalid_sig_hash', pass_cert_sig_hash=hash256(b'no-no-no dont even think'))
        self.generate_cert('root_cert_block_signed_with_another_key', root_cert_sig_key=fake_root_key)
        self.generate_cert('pass_cert_block_signed_with_another_key', pass_cert_sig_key=fake_pass_key)
        fake_signature = sign_compact(hash256(b'no_chance_either'), fake_root_key.get_secret())
        self.generate_cert('root_cert_invalid_signature', root_cert_signature=fake_signature)
        fake_signature = sign_compact(hash256(b'aaaaaaaaaaaa'), fake_pass_key.get_secret())
        self.generate_cert('pass_cert_invalid_signature', pass_cert_signature=fake_signature)

        # Run testcases:
        self.run_scenario('positive_with_cert_before_cert_needed', use_cert=True, cert_needed=False, unload_cert_on_finish=True)
        self.run_scenario('positive_without_cert_before_cert_needed', use_cert=False, cert_needed=False)

        generate_many_blocks(node0, CERTS_AFTER_HEIGHT - node0.getblockcount() - 1)
        self.sync_all()

        self.run_scenario('positive_with_cert_after_cert_needed', use_cert=True, unload_cert_on_finish=True)
        self.run_scenario('without_cert', use_cert=False, cert_needed=True, accepted=False)
        self.run_scenario('positive_required_flag_in_root_cert_v1', use_cert=True)
        self.run_scenario('positive_required_flag_in_root_cert_v2', use_cert=True)
        self.run_scenario('missing_root_cert', use_cert=True, accepted=False)
        self.run_scenario('missing_pass_cert', use_cert=True, accepted=False)
        self.run_scenario('tx_instead_of_root_cert', use_cert=True, accepted=False)
        self.run_scenario('tx_instead_of_pass_cert', use_cert=True, accepted=False)
        self.run_scenario('root_cert_is_not_root', use_cert=True, accepted=False)
        self.run_scenario('pass_cert_is_not_child_of_root', use_cert=True, accepted=False)
        self.run_scenario('super_key_not_mentioned_in_cert', use_cert=True, accepted=False)
        self.run_scenario('no_required_flag_in_cert_v1', use_cert=True, accepted=False)
        self.run_scenario('no_required_flag_in_cert_v2', use_cert=True, accepted=False)
        self.run_scenario('root_cert_revoked', use_cert=True, accepted=False)
        self.run_scenario('pass_cert_revoked', use_cert=True, accepted=False)
        self.run_scenario('root_cert_empty_signature', use_cert=True, accepted=False)
        self.run_scenario('pass_cert_empty_signature', use_cert=True, accepted=False)
        self.run_scenario('root_cert_invalid_sig_hash', use_cert=True, accepted=False)
        self.run_scenario('pass_cert_invalid_sig_hash', use_cert=True, accepted=False)
        self.run_scenario('root_cert_block_signed_with_another_key', use_cert=True, accepted=False)
        self.run_scenario('pass_cert_block_signed_with_another_key', use_cert=True, accepted=False)
        self.run_scenario('root_cert_invalid_signature', use_cert=True, accepted=False)
        self.run_scenario('pass_cert_invalid_signature', use_cert=True, accepted=False)
        self.run_scenario('positive_both_flags', use_cert=True)

        assert_equal(len(self.certs), 0)

        # And now ensure super-tx will work correctly with the same cert containing both flags:
        txid = node0.sendtoaddress(node1.getnewaddress(), 100)
        verify_tx_sent(node0, txid)
        tx = node0.getrawtransaction(txid, 1)
        assert_equal(len(tx['vout']), 2)
        assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_1, None, tx)
        assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_2, None, tx)


if __name__ == '__main__':
    MiningCertTest().main()
