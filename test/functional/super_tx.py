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
maxfee = Decimal('0.001')


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


    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()


    def check_scen_001(self, amount, super_key=None, mine_block=True):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        dest_key = create_key()
        null_input = {'txid': '0000000000000000000000000000000000000000000000000000000000000000', 'vout': 0}
        addr1 = node0.getnewaddress()
        txid = node1.sendtoaddress(addr1, amount)
        assert_in(txid, node1.getrawmempool())
        self.sync_all()
        if mine_block:
            node0.generate(1)
        n = find_output(node0, txid, amount)
        raw_super = node0.createrawtransaction([{'txid': txid, 'vout': n}, null_input], {AddressFromPubkey(dest_key.get_pubkey()): amount - fee})
        if super_key:
            sig_res = node0.signrawtransaction(raw_super, [], [SecretBytesToBase58(super_key.get_secret()), node0.dumpprivkey(addr1)])
        else:
            sig_res = node0.signrawtransaction(raw_super)
        assert_equal(sig_res['complete'], True)
        assert('errors' not in sig_res or len(sig_res['errors']) == 0)
        txid_super = node0.sendrawtransaction(sig_res['hex'])
        assert_in(txid_super, node0.getrawmempool())
        if mine_block:
            node0.generate(1)


    def check_sendtoaddress(self, node, address, amount, subtractfeefromamount=False, mine_block=True):
        balance_before = node.getbalance('', 0)
        self.log.debug(f'check sendtoaddress: node: {self.nodes.index(node)}, balance: {balance_before}, address: {address}, amount: {amount}, subtractfeefromamount: {subtractfeefromamount}')
        txid = node.sendtoaddress(address, amount, '', '', subtractfeefromamount)
        assert_in(txid, node.getrawmempool())
        txraw = node.getrawtransaction(txid, 1)
        balance_after = node.getbalance('', 0)
        self.log.debug(f'txraw: {txraw}, balance_after: {balance_after}')
        outputs_cnt = len(txraw['vout'])
        assert_greater_than_or_equal(outputs_cnt, 1)  # dest (if no change)
        assert_greater_than_or_equal(2, outputs_cnt)  # dest + change
        amount_sent_index = find_output_by_address(node, address, tx_raw=txraw)
        amount_sent = txraw['vout'][amount_sent_index]['value']
        assert_raises(RuntimeError, find_output_by_address, node, GRAVE_ADDRESS_1, tx_raw=txraw)
        assert_raises(RuntimeError, find_output_by_address, node, GRAVE_ADDRESS_2, tx_raw=txraw)
        change_indexes = [e for e in list(range(outputs_cnt)) if e not in [amount_sent_index]]
        assert_greater_than_or_equal(1, len(change_indexes))
        change_index = change_indexes[0] if len(change_indexes) else -1
        change = txraw['vout'][change_index]['value'] if change_index != -1 else 0
        fee = -node.gettransaction(txid)['fee']
        assert_greater_than_or_equal(maxfee, fee)

        if subtractfeefromamount:
            assert_equal(amount, amount_sent + fee)
            assert_equal(balance_before, balance_after + amount)
        else:
            assert_equal(amount, amount_sent)
            assert_equal(balance_before, balance_after + amount + fee)
        if mine_block:
            node.generate(1)
        return fee


    def check_sendmany(self, node, addresses_and_amounts, subtractfeefrom=[], mine_block=True):
        amount_sum = 0
        for addr in addresses_and_amounts:
            amount_sum += addresses_and_amounts[addr]
        balance_before = node.getbalance('', 0)
        self.log.debug(f'check sendmany: node: {self.nodes.index(node)}, balance: {balance_before}, amount_sum: {amount_sum}, addresses_and_amounts: {addresses_and_amounts}, subtractfeefrom: {subtractfeefrom}')
        txid = node.sendmany('', addresses_and_amounts, 1, '', subtractfeefrom)
        assert_in(txid, node.getrawmempool())
        txraw = node.getrawtransaction(txid, 1)
        balance_after = node.getbalance('', 0)
        self.log.debug(f'txraw: {txraw}')
        outputs_cnt = len(txraw['vout'])
        assert_greater_than_or_equal(outputs_cnt, len(addresses_and_amounts))  # dests (if no change)
        assert_greater_than_or_equal(len(addresses_and_amounts) + 1, outputs_cnt)  # dests + change
        amount_sent_indexes_map = {}
        amount_sent_indexes_arr = []
        amount_sent_sum = 0
        for addr in addresses_and_amounts:
            amount_sent_index = find_output_by_address(node, addr, tx_raw=txraw)
            amount_sent_indexes_map[addr] = amount_sent_index
            amount_sent_indexes_arr.append(amount_sent_index)
            amount_sent_sum += txraw['vout'][amount_sent_index]['value']
        assert_raises(RuntimeError, find_output_by_address, node, GRAVE_ADDRESS_1, tx_raw=txraw)
        assert_raises(RuntimeError, find_output_by_address, node, GRAVE_ADDRESS_2, tx_raw=txraw)
        change_indexes = [e for e in list(range(outputs_cnt)) if e not in amount_sent_indexes_arr]
        assert_greater_than_or_equal(1, len(change_indexes))
        change_index = change_indexes[0] if len(change_indexes) else -1
        change = txraw['vout'][change_index]['value'] if change_index != -1 else 0
        fee = -node.gettransaction(txid)['fee']

        if len(subtractfeefrom) > 0:
            assert_equal(amount_sum, amount_sent_sum + fee)
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
            assert_equal(balance_before, balance_after + amount_sum + fee)
        if mine_block:
            node.generate(1)
        return fee


    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        self.sync_all()
        self.test_node.sync_with_ping()
        assert_not_in('taxfree_certificate', node0.getwalletinfo())
        assert_not_in('taxfree_certificate', node1.getwalletinfo())

        # Transfer some amount node1 --> node0 and mine it into a block:
        for _ in range(10):
            node1.sendtoaddress(node0.getnewaddress(), 1000)
        node1.generate(1)
        self.sync_all()

        # Transfer some amount node1 --> node0 and don't mine it into a block:
        for _ in range(10):
            txid = node1.sendtoaddress(node0.getnewaddress(), 1000)
            assert_in(txid, node1.getrawmempool())
        self.sync_all()

        # ... and now mine it into a block:
        node1.generate(1)
        self.sync_all()

        # Root cert:
        genesis_key0 = create_key(True, GENESIS_PRIV_KEY0_BIN)
        print_key_verbose(genesis_key0, 'genesis_key0')
        (self.outpoints, _) = generate_outpoints(node0, 1, Decimal('1.03') + fee, AddressFromPubkey(genesis_key0.get_pubkey()))
        (tx2, ca3_cert_key) = compose_cert_tx(self.outpoints.pop(0), Decimal(1), genesis_key0, 'root_cert', 0)
        root_cert_hash = send_tx(node0, self.test_node, tx2, True)
        node0.generate(1)

        # CA3 cert:
        (self.outpoints, _) = generate_outpoints(node0, 1, Decimal('1.03') + fee, AddressFromPubkey(ca3_cert_key.get_pubkey()))
        (tx2, super_key) = compose_cert_tx(self.outpoints.pop(0), Decimal(1), ca3_cert_key, 'user_cert', SUPER_TX)
        pass_cert_hash = send_tx(node0, self.test_node, tx2, True)
        node0.generate(1)

        # Check p2p first:
        amount = Decimal(4500)
        user_key = create_key()
        dest_pkh = hash160(b'xepppp-001')
        (self.outpoints, _) = generate_outpoints(node0, 20, amount, AddressFromPubkey(user_key.get_pubkey()))
        node0.generate(1)

        tx3 = compose_super_tx([self.outpoints.pop()], user_key, COutPoint(int(root_cert_hash, 16), 0),
                               COutPoint(int(pass_cert_hash, 16), 0), super_key, {dest_pkh: amount - fee})
        send_tx(node0, self.test_node, tx3, True)


        taxfree_cert_filename = os.path.join(self.options.tmpdir + '/node0/regtest', 'taxfree.cert')
        self.log.debug(f'taxfree_cert_filename: {taxfree_cert_filename}')
        with open(taxfree_cert_filename, 'w', encoding='utf8') as f:
            body = \
                '{\n' \
                '    "pubkeys":\n' \
                '    [\n' \
                '        "%s"\n' \
                '    ],\n' \
                '    "certs":\n' \
                '    [\n' \
                '        {\n' \
                '            "txid": "%s",\n' \
                '            "vout": 0\n' \
                '        },\n' \
                '        {\n' \
                '            "txid": "%s",\n' \
                '            "vout": 0\n' \
                '        }\n' \
                '    ]\n' \
                '}\n' % (bytes_to_hex_str(super_key.get_pubkey()), root_cert_hash, pass_cert_hash)
            f.write(body)

        self.stop_node(0)
        self.start_node(0, extra_args=self.extra_args[0] + [f'-taxfreecert={taxfree_cert_filename}'])
        connect_nodes(self.nodes[0], 1)
        assert_equal(node0.getwalletinfo()['taxfree_certificate'], taxfree_cert_filename)

        amount = Decimal(4500)

        # A-001: base positive
        # createrawtransaction --> signrawtransaction(super_key) --> sendrawtransaction
        # with and without mining transactions into blocks
        for mine_block in [True, False, False]:
            self.check_scen_001(amount, super_key, mine_block)

        node0.importprivkey(SecretBytesToBase58(super_key.get_secret()))

        # A-002: base positive after importprivkey
        # createrawtransaction --> signrawtransaction(empty_keys_array) --> sendrawtransaction
        # with and without mining transactions into blocks
        for mine_block in [True, False, False]:
            self.check_scen_001(amount, None, mine_block)

        node0.generate(1)
        pkh1 = hash160(b'antonio-1')
        pkh2 = hash160(b'antonio-2')
        addr1 = AddressFromPubkeyHash(pkh1)
        addr2 = AddressFromPubkeyHash(pkh2)
        amount = Decimal(800)
        balance_before = node0.getbalance()
        fee_sum = 0
        spent = 0
        mined = Decimal('0.005')

        for mine_block in [True, False, False]:
            for subtractfeefromamount in [False, True]:
                fee_this = self.check_sendtoaddress(node0, addr1, amount, subtractfeefromamount, mine_block)
                fee_sum += fee_this
                spent += amount if subtractfeefromamount else (amount + fee_this)
                mined += Decimal('0.005') if mine_block else 0

        node0.generate(1)
        balance_after = node0.getbalance()
        assert_equal(balance_before + mined, balance_after + spent)
        self.sync_all()

        fee_sum = 0
        spent = 0
        mined = Decimal('0.005')
        balance_before = node0.getbalance()

        for mine_block in [True, False, False]:
            for subtractfeefrom in [[], [addr1], [addr1, addr2]]:
                fee_this = self.check_sendmany(node0, {addr1: amount, addr2: amount * 3}, subtractfeefrom, mine_block)
                fee_sum += fee_this
                spent += (amount * 4) if len(subtractfeefrom) else (amount * 4 + fee_this)
                mined += Decimal('0.005') if mine_block else 0

        self.sync_all()
        node0.generate(1)
        balance_after = node0.getbalance()
        assert_equal(balance_before + mined, balance_after + spent)


if __name__ == '__main__':
    SuperTxTest().main()
