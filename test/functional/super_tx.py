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
super_tx.py
'''

fee = Decimal('0.00001')
maxfee = Decimal('0.002')
BAD_CERTIFICATE = 'mandatory-script-verify-flag-failed (Bad plc certificate)'
BAD_BURNED = 'bad-burned'


def compose_super_tx(input_utxos, input_key, utxo_cert_root, utxo_cert_ca3, user_super_key, dest_pkhs_and_amounts):
    tx3 = CTransaction()

    for input_utxo in input_utxos:
        tx3.vin.append(CTxIn(input_utxo, GetP2PKHScript(hash160(input_key.get_pubkey())), 0xffffffff))
    tx3.vin.append(CTxIn(COutPoint(0,0), GetP2SHMoneyboxScript(OP_CHECKSUPER), 0xffffffff))

    # append dest_outputs to tx:
    for dest_pkh in dest_pkhs_and_amounts:
        amount = dest_pkhs_and_amounts[dest_pkh]
        tx3.vout.append(CTxOut(ToSatoshi(amount), GetP2PKHScript(dest_pkh)))

    for i in range(len(input_utxos)):
        (sig_hash, err) = SignatureHash(CScript(tx3.vin[i].scriptSig), tx3, i, SIGHASH_ALL)
        assert (err is None)
        signature = input_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx3.vin[i].scriptSig = CScript([signature, input_key.get_pubkey()])

    for i in range(len(input_utxos), len(tx3.vin)):
        # There are no common rules of composing signature for p2sh transaction inputs,
        # we made agreement to replace scriptSig with inner script (CScript(OP_CHECKREWARD)), not
        # with the public key script of the referenced transaction output
        # (excluding all occurences of OP CODESEPARATOR in it), as for p2pkh transactions:
        scriptSig = CScript([OP_CHECKSUPER])
        (sig_hash, err) = SignatureHash(scriptSig, tx3, i, SIGHASH_ALL)
        assert (err is None)
        signatures_and_keys = []
        signature = user_super_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        signatures_and_keys.append(signature)
        signatures_and_keys.append(user_super_key.get_pubkey())
        tx3.vin[i].scriptSig = CScript(signatures_and_keys +
                                       [ ser_uint256(utxo_cert_root.hash), utxo_cert_root.n,
                                         ser_uint256(utxo_cert_ca3.hash), utxo_cert_ca3.n,
                                         CScript([OP_CHECKSUPER])])
    tx3.rehash()
    return tx3


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

class SuperTxTest(BitcoinTestFramework):

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


    def check_scen_001(self, amount, super_key=None, certs=[], mine_block=True, accepted=True, reject_reason=None):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        dest_key = create_key()
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
        raw_super = node0.createrawtransaction([{'txid': txid, 'vout': n}, null_input], {AddressFromPubkey(dest_key.get_pubkey()): amount - fee})
        sig_res = None
        try:
            if super_key:
                sig_res = node0.signrawtransaction(raw_super, [],
                                                   [SecretBytesToBase58(super_key.get_secret()), node0.dumpprivkey(addr1)],
                                                   'ALL', certs, [bytes_to_hex_str(super_key.get_pubkey())])
            else:
                sig_res = node0.signrawtransaction(raw_super)
        except JSONRPCException as e:
            self.log.debug(f'signrawtransaction JSONRPCException: {e}')
        self.log.debug(f'check_scen_001, amount: {amount}, super_key: {super_key}, mine_block: {mine_block}, sig_res: {sig_res}')
        assert_equal(sig_res is not None and sig_res['complete'], accepted)
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
            if sig_res:
                assert_greater_than(len(sig_res['errors']), 0)
                assert_raises_rpc_error(None, reject_reason, node0.sendrawtransaction, sig_res['hex'])
            balance_after = node0.getbalance('', 0)
            assert_equal(balance_before, balance_after)
        self.sync_all()


    def check_sendtoaddress(self, address, amount, subtractfeefromamount=False, mine_block=True, valid_cert=True):
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
        burn_outputs = 0 if valid_cert else 2
        assert_greater_than_or_equal(outputs_cnt, 1 + burn_outputs)  # dest (if no change)
        assert_greater_than_or_equal(2 + burn_outputs, outputs_cnt)  # dest + change
        amount_sent_index = find_output_by_address(node0, address, tx_raw=txraw)
        amount_sent = txraw['vout'][amount_sent_index]['value']
        if valid_cert:
            assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_1, tx_raw=txraw)
            assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_2, tx_raw=txraw)
            burn_got_sum = 0
            burn_indexes = []
        else:
            burn1_index = find_output_by_address(node0, GRAVE_ADDRESS_1, tx_raw=txraw)
            burn2_index = find_output_by_address(node0, GRAVE_ADDRESS_2, tx_raw=txraw)
            burn_got1 = txraw['vout'][burn1_index]['value']
            burn_got2 = txraw['vout'][burn2_index]['value']
            burn_got_sum = burn_got1 + burn_got2
            burn_indexes = [burn1_index, burn2_index]
        change_indexes = [e for e in list(range(outputs_cnt)) if e not in [amount_sent_index] + burn_indexes]
        assert_greater_than_or_equal(1, len(change_indexes))
        change_index = change_indexes[0] if len(change_indexes) else -1
        change = txraw['vout'][change_index]['value'] if change_index != -1 else 0
        fee = -node0.gettransaction(txid)['fee']
        assert_greater_than_or_equal(maxfee, fee)

        if subtractfeefromamount:
            assert_equal(amount, amount_sent + burn_got_sum + fee)
            assert_equal(balance_before, balance_after + amount)
        else:
            assert_equal(amount, amount_sent)
            assert_equal(balance_before, balance_after + amount + burn_got_sum + fee)
        if mine_block:
            self.sync_all()
            node1.generate(1)
            self.sync_all()
        return (txid, fee + burn_got_sum)


    def check_sendmany(self, addresses_and_amounts, subtractfeefrom=[], mine_block=True, valid_cert=True):
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
        balance_after = node0.getbalance('', 0)
        self.log.debug(f'txraw: {txraw}')
        outputs_cnt = len(txraw['vout'])
        burn_outputs = 0 if valid_cert else 2
        assert_greater_than_or_equal(outputs_cnt, len(addresses_and_amounts) + burn_outputs)  # dests (if no change)
        assert_greater_than_or_equal(len(addresses_and_amounts) + 1 + burn_outputs, outputs_cnt)  # dests + change
        amount_sent_indexes_map = {}
        amount_sent_indexes_arr = []
        amount_sent_sum = 0
        for addr in addresses_and_amounts:
            amount_sent_index = find_output_by_address(node0, addr, tx_raw=txraw)
            amount_sent_indexes_map[addr] = amount_sent_index
            amount_sent_indexes_arr.append(amount_sent_index)
            amount_sent_sum += txraw['vout'][amount_sent_index]['value']
        if valid_cert:
            assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_1, tx_raw=txraw)
            assert_raises(RuntimeError, find_output_by_address, node0, GRAVE_ADDRESS_2, tx_raw=txraw)
            burn_got_sum = 0
            burn_indexes = []
        else:
            burn1_index = find_output_by_address(node0, GRAVE_ADDRESS_1, tx_raw=txraw)
            burn2_index = find_output_by_address(node0, GRAVE_ADDRESS_2, tx_raw=txraw)
            burn_got1 = txraw['vout'][burn1_index]['value']
            burn_got2 = txraw['vout'][burn2_index]['value']
            burn_got_sum = burn_got1 + burn_got2
            burn_indexes = [burn1_index, burn2_index]
        change_indexes = [e for e in list(range(outputs_cnt)) if e not in amount_sent_indexes_arr + burn_indexes]
        assert_greater_than_or_equal(1, len(change_indexes))
        change_index = change_indexes[0] if len(change_indexes) else -1
        change = txraw['vout'][change_index]['value'] if change_index != -1 else 0
        fee = -node0.gettransaction(txid)['fee']

        if len(subtractfeefrom) > 0:
            assert_equal(amount_sum, amount_sent_sum + burn_got_sum + fee)
            taxes = []
            for addr in addresses_and_amounts:
                amount_sent_index = amount_sent_indexes_map[addr]
                if addr in subtractfeefrom:
                    assert_greater_than(addresses_and_amounts[addr], txraw['vout'][amount_sent_index]['value'])
                    tax = addresses_and_amounts[addr] - txraw['vout'][amount_sent_index]['value']
                    taxes.append(tax)
                else:
                    assert_equal(addresses_and_amounts[addr], txraw['vout'][amount_sent_index]['value'])
            # Node calculates taxes with accuracy 2 satoshi, let it be so
            assert_greater_than_or_equal(2, ToSatoshi(max(taxes) - min(taxes)))
            assert_equal(balance_before, balance_after + amount_sum)
        else:
            for addr in addresses_and_amounts:
                amount_sent_index = amount_sent_indexes_map[addr]
                assert_equal(addresses_and_amounts[addr], txraw['vout'][amount_sent_index]['value'])
            assert_equal(amount_sum, amount_sent_sum)
            assert_equal(balance_before, balance_after + amount_sum + burn_got_sum + fee)
        if mine_block:
            self.sync_all()
            node1.generate(1)
            self.sync_all()
        return (txid, fee + burn_got_sum)


    def run_scenario(self, name, root_cert_key=None, root_cert_flags=None, root_cert_hash=None,
                     root_cert_sig_hash=None, root_cert_sig_key=None, root_cert_signature=None, root_cert_revoked=False,
                     pass_cert_key=None, pass_cert_flags=None, pass_cert_hash=None,
                     pass_cert_sig_hash=None, pass_cert_sig_key=None, pass_cert_signature=None, pass_cert_revoked=False,
                     super_key=None, amount=None, accepted=True, reject_reason_rpc=None, reject_reason_p2p=None):
        self.log.info(f'Start scenario {name} ...')
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        assert_not_in('taxfree_certificate', node0.getwalletinfo())
        assert_not_in('taxfree_certificate', node1.getwalletinfo())

        (root_cert_hash, pass_cert_hash, super_key) = generate_certs_pair(node1, self.test_node,
                                                                          root_cert_key=root_cert_key,
                                                                          root_cert_flags=root_cert_flags,
                                                                          root_cert_hash=root_cert_hash,
                                                                          root_cert_sig_hash=root_cert_sig_hash,
                                                                          root_cert_sig_key=root_cert_sig_key,
                                                                          root_cert_signature=root_cert_signature,
                                                                          root_cert_revoked=root_cert_revoked,
                                                                          pass_cert_key=pass_cert_key,
                                                                          pass_cert_flags=pass_cert_flags,
                                                                          pass_cert_hash=pass_cert_hash,
                                                                          pass_cert_sig_hash=pass_cert_sig_hash,
                                                                          pass_cert_sig_key=pass_cert_sig_key,
                                                                          pass_cert_signature=pass_cert_signature,
                                                                          pass_cert_revoked=pass_cert_revoked,
                                                                          super_key=super_key, fee=fee,
                                                                          pass_cert_flag_default=SUPER_TX)
        node1.generate(1)
        self.sync_all()

        # Check p2p first:
        amount = amount if amount is not None else Decimal(75)
        user_key = create_key()
        dest_pkh = hash160(b'xepppp-001')
        (self.outpoints, _) = generate_outpoints(node0, 20, amount, AddressFromPubkey(user_key.get_pubkey()))
        self.sync_all()
        node1.generate(1)
        self.sync_all()

        tx3 = compose_super_tx([self.outpoints.pop()], user_key, COutPoint(int(root_cert_hash, 16), 0),
                               COutPoint(int(pass_cert_hash, 16), 0), super_key, {dest_pkh: amount - fee})
        send_tx(node1, self.test_node, tx3, accepted, reject_reason_p2p)

        restart_node_with_cert(self, True, super_key.get_pubkey(), root_cert_hash, pass_cert_hash, accepted)

        # createrawtransaction --> signrawtransaction(super_key) --> sendrawtransaction
        # with and without mining transactions into blocks
        certs = [
            {'txid': root_cert_hash, 'vout': 0},
            {'txid': pass_cert_hash, 'vout': 0},
        ]
        for mine_block in [True, False, False]:
            self.check_scen_001(amount, super_key, certs, mine_block, accepted, reject_reason_rpc)

        node0.importprivkey(SecretBytesToBase58(super_key.get_secret()))

        # createrawtransaction --> signrawtransaction(empty_keys_array) --> sendrawtransaction
        # with and without mining transactions into blocks
        for mine_block in [True, False, False]:
            self.check_scen_001(amount, None, [], mine_block, accepted, reject_reason_rpc)

        self.sync_all()
        node1.generate(1)
        self.sync_all()
        assert_equal(len(node0.getrawmempool()), 0)
        assert_equal(len(node1.getrawmempool()), 0)
        pkh1 = hash160(b'antonio-1')
        pkh2 = hash160(b'antonio-2')
        addr1 = AddressFromPubkeyHash(pkh1)
        addr2 = AddressFromPubkeyHash(pkh2)
        balance_before = node0.getbalance()
        spent_sum = 0
        txids = []

        for mine_block in [True, False, False]:
            for subtractfeefromamount in [False, True]:
                (txid, fee_this) = self.check_sendtoaddress(addr1, amount, subtractfeefromamount, mine_block, accepted)
                txids.append(txid)
                spent_this = amount if subtractfeefromamount else (amount + fee_this)
                spent_sum += spent_this
        self.sync_all()
        node1.generate(1)
        self.sync_all()
        balance_after = node0.getbalance()
        self.log.debug(f'balance_before: {balance_before}, balance_after: {balance_after}, spent_sum: {spent_sum}')
        for txid in txids:
            assert_greater_than(node0.getrawtransaction(txid, 1)['confirmations'], 0)
        assert_equal(balance_before, balance_after + spent_sum)
        self.sync_all()

        balance_before = node0.getbalance()
        spent_sum = 0
        txids = []

        for mine_block in [True, False, False]:
            for subtractfeefrom in [[], [addr1], [addr1, addr2]]:
                (txid, fee_this) = self.check_sendmany({addr1: amount, addr2: amount * 3}, subtractfeefrom, mine_block, accepted)
                txids.append(txid)
                spent_this = (amount * 4) if len(subtractfeefrom) else (amount * 4 + fee_this)
                spent_sum += spent_this
        self.sync_all()
        node1.generate(1)
        self.sync_all()
        balance_after = node0.getbalance()
        self.log.debug(f'balance_before: {balance_before}, balance_after: {balance_after}, spent_sum: {spent_sum}')
        for txid in txids:
            assert_greater_than(node0.getrawtransaction(txid, 1)['confirmations'], 0)
        assert_equal(balance_before, balance_after + spent_sum)
        restart_node_with_cert(self, False)
        self.test_node.sync_with_ping()
        self.log.debug(f'Finish scenario {name}')


    def run_test(self):
        # Test cert with node0
        # Check balance before/after with node0
        # Generate blocks with node1
        # self.test_node uses node1
        self.taxfree_cert_filename = os.path.join(self.options.tmpdir + '/node0/regtest', 'taxfree.cert')
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        node1.generate(100) # is needed to remove influence of generate() calls to node0 balance
        self.sync_all()
        self.test_node.sync_with_ping()

        # Transfer some amount node1 --> node0 and don't mine it into a block:
        for _ in range(20):
            txid = node1.sendtoaddress(node0.getnewaddress(), 1000)
            verify_tx_sent(node1, txid)
        self.sync_all()

        # ... and now mine it into a block:
        node1.generate(1)
        self.sync_all()

        self.run_scenario('base_positive_1', amount=Decimal(800))
        self.run_scenario('base_positive_2', amount=Decimal(8))
        self.run_scenario('base_positive_3', amount=Decimal('1.12345678'))

        self.run_scenario('positive_supertx_flag_in_root_cert_v1',
                          root_cert_flags=SUPER_TX,
                          pass_cert_flags=0)

        self.run_scenario('positive_supertx_flag_in_root_cert_v2',
                          root_cert_flags=SUPER_TX,
                          pass_cert_flags=SILVER_HOOF | ALLOW_MINING)

        self.run_scenario('missing_root_cert',
                          root_cert_hash=bytes_to_hex_str(hash256(b'xyu')),
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('missing_pass_cert',
                          pass_cert_hash=bytes_to_hex_str(hash256(b'xyu-again')),
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('tx_instead_of_root_cert',
                          root_cert_hash=txid,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('tx_instead_of_pass_cert',
                          pass_cert_hash=txid,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        fake_root_key = create_key()
        self.run_scenario('root_cert_is_not_root',
                          root_cert_key=fake_root_key,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        fake_pass_key = create_key()
        self.run_scenario('pass_cert_is_not_child_of_root',
                          pass_cert_key=fake_pass_key,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        fake_super_key = create_key()
        self.run_scenario('super_key_not_mentioned_in_cert',
                          super_key=fake_super_key,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('no_supertx_flag_in_cert_v1',
                          pass_cert_flags=0,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=[BAD_BURNED, BAD_CERTIFICATE])

        self.run_scenario('no_supertx_flag_in_cert_v2',
                          pass_cert_flags=SILVER_HOOF | ALLOW_MINING,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=[BAD_BURNED, BAD_CERTIFICATE])

        self.run_scenario('root_cert_revoked',
                          root_cert_revoked=True,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('pass_cert_revoked',
                          pass_cert_revoked=True,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('root_cert_empty_signature',
                          root_cert_signature=b'',
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('pass_cert_empty_signature',
                          pass_cert_signature=b'',
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('root_cert_invalid_sig_hash',
                          root_cert_sig_hash=hash256(b'no!'),
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('pass_cert_invalid_sig_hash',
                          pass_cert_sig_hash=hash256(b'no-no-no dont even think'),
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('root_cert_block_signed_with_another_key',
                          root_cert_sig_key=fake_root_key,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        self.run_scenario('pass_cert_block_signed_with_another_key',
                          pass_cert_sig_key=fake_pass_key,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        fake_signature = sign_compact(hash256(b'no_chance_either'), fake_root_key.get_secret())
        self.run_scenario('root_cert_invalid_signature',
                          root_cert_signature=fake_signature,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)

        fake_signature = sign_compact(hash256(b'aaaaaaaaaaaa'), fake_pass_key.get_secret())
        self.run_scenario('pass_cert_invalid_signature',
                          pass_cert_signature=fake_signature,
                          accepted=False,
                          reject_reason_p2p=BAD_CERTIFICATE,
                          reject_reason_rpc=BAD_BURNED)


if __name__ == '__main__':
    SuperTxTest().main()
