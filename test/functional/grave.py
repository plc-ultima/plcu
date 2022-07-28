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
grave.py
'''

ADDRESS_PROHIBITED = 'Address prohibited'
BURN_AMOUNT_TOO_SMALL = 'Burn amount too small'
TOO_SMALL_TO_PAY_FEE = 'The transaction amount is too small to pay the fee'

def create_my_key():
    my_key = create_key(True)
    my_pubkey = my_key.get_pubkey()
    my_pkh = hash160(my_pubkey)
    my_p2pkh_scriptpubkey = GetP2PKHScript(my_pkh)
    my_p2pk_scriptpubkey = CScript([my_pubkey, OP_CHECKSIG])
    return (my_key, my_pubkey, my_pkh, my_p2pkh_scriptpubkey, my_p2pk_scriptpubkey)


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


class GraveTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.extra_args = [['-debug', '-whitelist=127.0.0.1']]
        self.outpoints_p2pk = []
        self.outpoints_p2pkh = []
        self.outpoints_fund1 = []  # (my_addr OR (addr1 + addr2))
        self.outpoints_fund2 = []  # (addr1 OR (my_addr + addr2))
        (self.main_key, self.main_pubkey, self.main_pkh, self.main_scriptpubkey_p2pkh, self.main_scriptpubkey_p2pk) = create_my_key()
        (self.key1, self.pubkey1, self.pkh1, _, _) = create_my_key()
        (self.key2, self.pubkey2, self.pkh2, _, _) = create_my_key()
        (self.key3, self.pubkey3, self.pkh3, _, _) = create_my_key()
        self.main_scriptpubkey_fund1 = GetAbMintingMultisigScript(self.main_key, self.key1, self.key2)
        self.main_scriptpubkey_fund2 = GetAbMintingMultisigScript(self.key1, self.main_key, self.key3)


    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()

    def compose_and_send_tx_from_p2pk_input(self, outputs, accepted, reject_reason=None):
        outpoint = self.outpoints_p2pk.pop(0)
        tx1 = CTransaction()
        tx1.vin.append(CTxIn(outpoint, b'', 0xffffffff))
        tx1.vout = outputs
        (sig_hash, err) = SignatureHash(self.main_scriptpubkey_p2pk, tx1, 0, SIGHASH_ALL)
        assert (err is None)
        signature = self.main_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx1.vin[0].scriptSig = CScript([signature])
        tx1.rehash()
        return send_tx(self.nodes[0], self.test_node, tx1, accepted, reject_reason, False)

    def compose_and_send_tx_from_p2pkh_input(self, outputs, accepted, reject_reason=None):
        outpoint = self.outpoints_p2pkh.pop(0)
        tx1 = CTransaction()
        tx1.vin.append(CTxIn(outpoint, b'', 0xffffffff))
        tx1.vout = outputs
        (sig_hash, err) = SignatureHash(self.main_scriptpubkey_p2pkh, tx1, 0, SIGHASH_ALL)
        assert (err is None)
        signature = self.main_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx1.vin[0].scriptSig = CScript([signature, self.main_pubkey])
        tx1.rehash()
        return send_tx(self.nodes[0], self.test_node, tx1, accepted, reject_reason, False)

    def compose_and_send_tx_from_fund1_input(self, outputs, accepted, reject_reason=None):
        outpoint = self.outpoints_fund1.pop(0)
        tx1 = CTransaction()
        tx1.vin.append(CTxIn(outpoint, b'', 0xffffffff))
        tx1.vout = outputs
        (sig_hash, err) = SignatureHash(self.main_scriptpubkey_fund1, tx1, 0, SIGHASH_ALL)
        assert (err is None)
        signature = self.main_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx1.vin[0].scriptSig = CScript([signature, self.main_pubkey])
        tx1.rehash()
        return send_tx(self.nodes[0], self.test_node, tx1, accepted, reject_reason, False)

    def compose_and_send_tx_from_fund2_input(self, outputs, accepted, reject_reason=None):
        outpoint = self.outpoints_fund2.pop(0)
        tx1 = CTransaction()
        tx1.vin.append(CTxIn(outpoint, b'', 0xffffffff))
        tx1.vout = outputs
        (sig_hash, err) = SignatureHash(self.main_scriptpubkey_fund2, tx1, 0, SIGHASH_ALL)
        assert (err is None)
        keyA = self.main_key
        keyB = self.key3
        signature0 = keyA.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        signature1 = keyB.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx1.vin[0].scriptSig = CScript([OP_0, signature0, signature1, OP_2, keyA.get_pubkey(), keyB.get_pubkey()])
        tx1.rehash()
        return send_tx(self.nodes[0], self.test_node, tx1, accepted, reject_reason, False)

    def compose_and_send_tx(self, outputs, accepted, reject_reason=None):
        self.compose_and_send_tx_from_p2pk_input(outputs, accepted, reject_reason)
        self.compose_and_send_tx_from_p2pkh_input(outputs, accepted, reject_reason)
        self.compose_and_send_tx_from_fund1_input(outputs, accepted, reject_reason)
        self.compose_and_send_tx_from_fund2_input(outputs, accepted, reject_reason)


    def check_sendtoaddress(self, node, address, amount, subtractfeefromamount=False, changeToNewAddress=False, changeExists=None):
        self.log.debug(f'check sendtoaddress: node: {self.nodes.index(node)}, balance: {node.getbalance()}, address: {address}, amount: {amount}, subtractfeefromamount: {subtractfeefromamount}, changeToNewAddress: {changeToNewAddress}')
        txid = node.sendtoaddress(address, amount, '', '', subtractfeefromamount, False, DEFAULT_TX_CONFIRM_TARGET, 'UNSET', changeToNewAddress)
        verify_tx_sent(node, txid)
        txraw = node.getrawtransaction(txid, 1)
        self.log.debug(f'txraw: {txraw}')
        outputs_cnt = len(txraw['vout'])
        assert_greater_than_or_equal(outputs_cnt, 3)  # dest + burn1 + burn2 (if no change)
        assert_greater_than_or_equal(4, outputs_cnt)  # dest + change + burn1 + burn2
        amount_sent_index = find_output_by_address(node, address, tx_raw=txraw)
        amount_sent = txraw['vout'][amount_sent_index]['value']
        burn1_index = find_output_by_address(node, GRAVE_ADDRESS_1, tx_raw=txraw)
        burn2_index = find_output_by_address(node, GRAVE_ADDRESS_2, tx_raw=txraw)
        burn_got1 = txraw['vout'][burn1_index]['value']
        burn_got2 = txraw['vout'][burn2_index]['value']
        change_indexes = [e for e in list(range(outputs_cnt)) if e not in [amount_sent_index, burn1_index, burn2_index]]
        assert_greater_than_or_equal(1, len(change_indexes))
        change_index = change_indexes[0] if len(change_indexes) else -1
        change = txraw['vout'][change_index]['value'] if change_index != -1 else 0
        fee = -node.gettransaction(txid)['fee']

        if changeExists is not None:
            assert_equal(changeExists, change_index != -1)

        if subtractfeefromamount and changeToNewAddress:
            (burn_expected1, burn_expected2) = GetBurnedValue(amount_sent + change)
            assert_equal(burn_got1, burn_expected1)
            assert_equal(burn_got2, burn_expected2)
            assert_equal(amount, amount_sent + burn_got1 + burn_got2 + fee)
        elif subtractfeefromamount:
            (burn_expected1, burn_expected2) = GetBurnedValue(amount_sent)
            assert_equal(burn_got1, burn_expected1)
            assert_equal(burn_got2, burn_expected2)
            assert_equal(amount, amount_sent + burn_got1 + burn_got2 + fee)
        elif changeToNewAddress:
            (burn_expected1, burn_expected2) = GetBurnedValue(amount + change)
            assert_equal(burn_got1, burn_expected1)
            assert_equal(burn_got2, burn_expected2)
            assert_equal(amount, amount_sent)
        else:
            (burn_expected1, burn_expected2) = GetBurnedValue(amount)
            assert_equal(burn_got1, burn_expected1)
            assert_equal(burn_got2, burn_expected2)
            assert_equal(amount, amount_sent)

        if change_index != -1:
            self.verify_change_output_addr_equals_first_input(txraw, not changeToNewAddress)


    def check_sendmany(self, node, addresses_and_amounts, changeToNewAddress, subtractfeefrom, changeExists=None):
        amount_sum = 0
        for addr in addresses_and_amounts:
            amount_sum += addresses_and_amounts[addr]
        self.log.debug(f'check sendmany: node: {self.nodes.index(node)}, balance: {node.getbalance()}, amount_sum: {amount_sum}, addresses_and_amounts: {addresses_and_amounts}, changeToNewAddress: {changeToNewAddress}, subtractfeefrom: {subtractfeefrom}')
        txid = node.sendmany('', addresses_and_amounts, 1, '', subtractfeefrom, False, DEFAULT_TX_CONFIRM_TARGET, 'UNSET', changeToNewAddress)
        verify_tx_sent(node, txid)
        txraw = node.getrawtransaction(txid, 1)
        self.log.debug(f'txraw: {txraw}')
        # print_tx_verbose(node, tx_json=txraw)
        outputs_cnt = len(txraw['vout'])
        assert_greater_than_or_equal(outputs_cnt, len(addresses_and_amounts) + 2)  # dests + burn1 + burn2 (if no change)
        assert_greater_than_or_equal(len(addresses_and_amounts) + 3, outputs_cnt)  # dests + change + burn1 + burn2
        amount_sent_indexes_map = {}
        amount_sent_indexes_arr = []
        amount_sent_sum = 0
        for addr in addresses_and_amounts:
            amount_sent_index = find_output_by_address(node, addr, tx_raw=txraw)
            amount_sent_indexes_map[addr] = amount_sent_index
            amount_sent_indexes_arr.append(amount_sent_index)
            amount_sent_sum += txraw['vout'][amount_sent_index]['value']
        burn1_index = find_output_by_address(node, GRAVE_ADDRESS_1, tx_raw=txraw)
        burn2_index = find_output_by_address(node, GRAVE_ADDRESS_2, tx_raw=txraw)
        burn_got1 = txraw['vout'][burn1_index]['value']
        burn_got2 = txraw['vout'][burn2_index]['value']
        change_indexes = [e for e in list(range(outputs_cnt)) if e not in amount_sent_indexes_arr + [burn1_index, burn2_index]]
        assert_greater_than_or_equal(1, len(change_indexes))
        change_index = change_indexes[0] if len(change_indexes) else -1
        change = txraw['vout'][change_index]['value'] if change_index != -1 else 0
        fee = -node.gettransaction(txid)['fee']

        if changeExists is not None:
            assert_equal(changeExists, change_index != -1)

        if len(subtractfeefrom) > 0:
            if changeToNewAddress:
                (burn_expected1, burn_expected2) = GetBurnedValue(amount_sent_sum + change)
            else:
                (burn_expected1, burn_expected2) = GetBurnedValue(amount_sent_sum)
            assert_equal(burn_got1, burn_expected1)
            assert_equal(burn_got2, burn_expected2)
            assert_equal(amount_sum, amount_sent_sum + burn_got1 + burn_got2 + fee)
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
        else:
            if changeToNewAddress:
                (burn_expected1, burn_expected2) = GetBurnedValue(amount_sum + change)
            else:
                (burn_expected1, burn_expected2) = GetBurnedValue(amount_sum)
            assert_equal(burn_got1, burn_expected1)
            assert_equal(burn_got2, burn_expected2)
            for addr in addresses_and_amounts:
                amount_sent_index = amount_sent_indexes_map[addr]
                assert_equal(addresses_and_amounts[addr], txraw['vout'][amount_sent_index]['value'])
            assert_equal(amount_sum, amount_sent_sum)

        if change_index != -1:
            self.verify_change_output_addr_equals_first_input(txraw, not changeToNewAddress)


    def verify_change_output_addr_equals_first_input(self, txraw, expected):
        node0 = self.nodes[0]
        parent_txid = txraw['vin'][0]['txid']
        parent_txraw = node0.getrawtransaction(parent_txid, 1)
        parent_vout = txraw['vin'][0]['vout']
        parent_out_address = parent_txraw['vout'][parent_vout]['scriptPubKey']['addresses'][0]
        if expected:
            change_output_num = find_output_by_address(node0, parent_out_address, tx_raw=txraw)
            assert_greater_than_or_equal(change_output_num, 0)
        else:
            assert_raises(RuntimeError, find_output_by_address, node0, parent_out_address, tx_raw=txraw)


    def generate_outpoint(self, node, amount, script, outpoints):
        tx = CTransaction()
        tx.vout.append(CTxOut(ToSatoshi(amount), script))
        rawtx = bytes_to_hex_str(tx.serialize())
        rawtxfund = node.fundrawtransaction(rawtx)['hex']
        tx_signed = node.signrawtransaction(rawtxfund)['hex']
        txid = node.sendrawtransaction(tx_signed)
        outpoints.append(COutPoint(int(txid, 16), find_output(node, txid, amount)))


    def run_test(self):
        node0 = self.nodes[0]
        self.test_node.sync_with_ping()

        amount = Decimal(10)
        small_amount_bad = Decimal('0.00015000')
        small_amount_good = Decimal('0.00020000')
        fee = Decimal('0.00001')
        pkh1 = hash160(b'xep1')
        pkh2 = hash160(b'xep2')
        pkh3 = hash160(b'xep3')
        addr1 = AddressFromPubkeyHash(pkh1)
        addr2 = AddressFromPubkeyHash(pkh2)
        addr3 = AddressFromPubkeyHash(pkh3)
        self.log.info(f'addr1: {addr1}, addr2: {addr2}, addr3: {addr3}, grave1: {GRAVE_ADDRESS_1}, grave2: {GRAVE_ADDRESS_2}')

        (burn1, burn2) = GetBurnedValue(Decimal(6))

        # Node has only utxos with amount=5000, no chance to pay fee and burn for full 5000 (changeToNewAddress=True and subtractfeefromamount=True) from small dest amount:
        assert_raises_rpc_error(None, TOO_SMALL_TO_PAY_FEE, self.check_sendtoaddress, node0, addr1, amount,
                                subtractfeefromamount=True, changeToNewAddress=True)

        # Node has only utxos with amount=5000, no chance to pay fee and burn for full 5000 (changeToNewAddress=True and subtractfeefromamount=[any]) from small dest amount(s):
        for subtractfeefrom in [[addr1], [addr1, addr3], [addr1, addr2, addr3]]:
            assert_raises_rpc_error(None, TOO_SMALL_TO_PAY_FEE, self.check_sendmany, node0,
                                    {addr1: amount, addr2: amount * 2, addr3: amount * 3}, True, subtractfeefrom)

        # Here we still have only utxos with amount 5000
        # check calls without change:
        for changeToNewAddress in [False, True]:
            self.check_sendtoaddress(node0, addr1, Decimal(5000), subtractfeefromamount=True, changeToNewAddress=changeToNewAddress, changeExists=False)
            self.check_sendmany(node0, {addr1: Decimal(5000)}, changeToNewAddress=changeToNewAddress, subtractfeefrom=[addr1], changeExists=False)
            self.check_sendmany(node0, {addr1: Decimal(5000), addr2: Decimal(5000)}, changeToNewAddress=changeToNewAddress, subtractfeefrom=[addr2], changeExists=False)
            self.check_sendmany(node0, {addr1: Decimal(5000), addr2: Decimal(5000)}, changeToNewAddress=changeToNewAddress, subtractfeefrom=[addr2, addr1], changeExists=False)

        changeToNewAddress = False
        for subtractfeefromamount in [False, True]:
            self.check_sendtoaddress(node0, addr1, amount, subtractfeefromamount, changeToNewAddress)
            self.check_sendtoaddress(node0, addr1, Decimal(400), subtractfeefromamount, changeToNewAddress)
            self.check_sendtoaddress(node0, addr1, Decimal(5000), subtractfeefromamount, changeToNewAddress)
        for subtractfeefrom in [[], [addr1], [addr1, addr3], [addr1, addr2, addr3]]:
            self.check_sendmany(node0, {addr1: amount, addr2: amount * 2, addr3: amount * 3}, changeToNewAddress, subtractfeefrom)
            self.check_sendmany(node0, {addr1: Decimal(800), addr2: Decimal(1200), addr3: Decimal(1400)}, changeToNewAddress, subtractfeefrom)
            self.check_sendmany(node0, {addr1: Decimal(200), addr2: Decimal(200), addr3: Decimal(5000)}, changeToNewAddress, subtractfeefrom)
        node0.generate(1)
        self.sync_all()

        changeToNewAddress = True
        for subtractfeefromamount in [False, True]:
            self.check_sendtoaddress(node0, addr1, Decimal(400), subtractfeefromamount, changeToNewAddress=True)
            self.check_sendtoaddress(node0, addr1, Decimal(5000), subtractfeefromamount, changeToNewAddress=True)
        self.check_sendtoaddress(node0, addr1, amount, subtractfeefromamount=False, changeToNewAddress=True)

        # No chance to pay 3% burn from addr1 amount - too little:
        assert_raises_rpc_error(None, TOO_SMALL_TO_PAY_FEE, self.check_sendmany, node0,
                                {addr1: amount * 2, addr2: amount * 100}, changeToNewAddress=False,
                                subtractfeefrom=[addr1])

        # From both no chance too:
        assert_raises_rpc_error(None, TOO_SMALL_TO_PAY_FEE, self.check_sendmany, node0,
                                {addr1: amount, addr2: amount * 100}, changeToNewAddress=False,
                                subtractfeefrom=[addr1, addr2])

        # But if to pay it from addr2 - OK:
        self.check_sendmany(node0, {addr1: amount * 2, addr2: amount * 100}, changeToNewAddress=False,
                            subtractfeefrom=[addr2])

        for changeToNewAddress in [False, True]:
            self.check_sendtoaddress(node0, addr1, small_amount_good, changeToNewAddress=changeToNewAddress)
            self.check_sendmany(node0, {addr1: small_amount_good}, changeToNewAddress=changeToNewAddress,
                                subtractfeefrom=[])
            self.check_sendmany(node0, {addr1: small_amount_good / 2, addr2: small_amount_good / 2},
                                changeToNewAddress=changeToNewAddress, subtractfeefrom=[])

        # Ensure node allows to send coins to grave addresses:
        txid = node0.sendmany('', {GRAVE_ADDRESS_1: burn1})
        verify_tx_sent(node0, txid)
        txid = node0.sendmany('', {GRAVE_ADDRESS_2: burn2})
        verify_tx_sent(node0, txid)
        txid = node0.sendmany('', {GRAVE_ADDRESS_1: burn1, GRAVE_ADDRESS_2: burn2})
        verify_tx_sent(node0, txid)
        txid = node0.sendtoaddress(GRAVE_ADDRESS_1, burn1)
        verify_tx_sent(node0, txid)
        txid = node0.sendtoaddress(GRAVE_ADDRESS_2, burn2)
        verify_tx_sent(node0, txid)

        # Generate utxos:
        (burn1, burn2, change) = BurnedAndChangeAmount(amount - fee, keep_sum=False)
        self.log.debug(f'amount: {amount}, fee: {fee}, burn1: {burn1}, burn2: {burn2}, change: {change}')
        for i in range(30):
            self.generate_outpoint(node0, amount, self.main_scriptpubkey_p2pk, self.outpoints_p2pk)
            self.generate_outpoint(node0, amount, self.main_scriptpubkey_p2pkh, self.outpoints_p2pkh)
            self.generate_outpoint(node0, amount, self.main_scriptpubkey_fund1, self.outpoints_fund1)
            self.generate_outpoint(node0, amount, self.main_scriptpubkey_fund2, self.outpoints_fund2)
            if len(node0.getrawmempool()) >= 20:
                node0.generate(1)
        node0.generate(1)
        self.test_node.sync_with_ping()

        # A001: Regular workflow - tx with burn: accepted
        vout = []
        vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(pkh1)))
        vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
        vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
        self.compose_and_send_tx(vout, True)

        # A002: Missing burn2 output: rejected
        vout = []
        vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(pkh1)))
        vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
        self.compose_and_send_tx(vout, False, 'bad-burned')

        # A003: Missing burn1 output: rejected
        vout = []
        vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(pkh1)))
        vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
        self.compose_and_send_tx(vout, False, 'bad-burned')

        # A004: Send coins only to burn1+burn2 addresses, without target address: accepted
        vout = []
        vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
        vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
        self.compose_and_send_tx(vout, True)

        # A005: Send coins only to burn1 address, without target address: accepted
        vout = []
        vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
        self.compose_and_send_tx(vout, True)

        # A006: Send coins only to burn2 address, without target address: accepted
        vout = []
        vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
        self.compose_and_send_tx(vout, True)

        # A007: Tx to addr1 without burn: rejected
        vout = []
        vout.append(CTxOut(ToSatoshi(amount - fee), GetP2PKHScript(pkh1)))
        self.compose_and_send_tx(vout, False, 'bad-burned')

        # A008: burn1 is too small: rejected
        vout = []
        vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(pkh1)))
        vout.append(CTxOut(ToSatoshi(burn1) - 2, GraveScript1()))
        vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
        self.compose_and_send_tx(vout, False, 'bad-burned')

        # A009: burn2 is too small: rejected
        vout = []
        vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(pkh1)))
        vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
        vout.append(CTxOut(ToSatoshi(burn2) - 2, GraveScript2()))
        self.compose_and_send_tx(vout, False, 'bad-burned')

        # A010: burn1 is too small, burn1+burn2 is correct: rejected
        vout = []
        vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(pkh1)))
        vout.append(CTxOut(ToSatoshi(burn1) - 2, GraveScript1()))
        vout.append(CTxOut(ToSatoshi(burn2) + 2, GraveScript2()))
        self.compose_and_send_tx(vout, False, 'bad-burned')

        # A011: burn2 is too small, burn1+burn2 is correct: rejected
        vout = []
        vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(pkh1)))
        vout.append(CTxOut(ToSatoshi(burn1) + 2, GraveScript1()))
        vout.append(CTxOut(ToSatoshi(burn2) - 2, GraveScript2()))
        self.compose_and_send_tx(vout, False, 'bad-burned')

        # A012: burn1 and burn2 are messed: rejected
        vout = []
        vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(pkh1)))
        vout.append(CTxOut(ToSatoshi(burn2), GraveScript1()))
        vout.append(CTxOut(ToSatoshi(burn1), GraveScript2()))
        self.compose_and_send_tx(vout, False, 'bad-burned')

        # A019: Burn1 to self instead of burn1 address, burn2 ok: rejected
        vout = []
        vout.append(CTxOut(ToSatoshi(change), GetP2PKHScript(pkh1)))
        vout.append(CTxOut(ToSatoshi(burn1), self.main_scriptpubkey_p2pkh))
        vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
        self.compose_and_send_tx(vout, False)

        # Tx to self using different types of addresses:
        expected_results = \
        {
            # Input |                       output type:
            # type  |
            'p2pk':  { 'p2pk': True, 'p2pkh': True, 'fund1': False, 'fund2': False },
            'p2pkh': { 'p2pk': True, 'p2pkh': True, 'fund1': False, 'fund2': False },
            'fund1': { 'p2pk': True, 'p2pkh': True, 'fund1': True,  'fund2': False },
            'fund2': { 'p2pk': True, 'p2pkh': True, 'fund1': False, 'fund2': True  },
        }
        compose_and_send_tx_funcs = [(self.compose_and_send_tx_from_p2pk_input, 'p2pk'),
                                     (self.compose_and_send_tx_from_p2pkh_input, 'p2pkh'),
                                     (self.compose_and_send_tx_from_fund1_input, 'fund1'),
                                     (self.compose_and_send_tx_from_fund2_input, 'fund2')]
        dest_scripts = [(self.main_scriptpubkey_p2pk, 'p2pk'), (self.main_scriptpubkey_p2pkh, 'p2pkh'),
                        (self.main_scriptpubkey_fund1, 'fund1'), (self.main_scriptpubkey_fund2, 'fund2')]
        use_burnings = [True, False]
        for compose_and_send_tx_func_pair in compose_and_send_tx_funcs:
            compose_and_send_tx_func = compose_and_send_tx_func_pair[0]
            name_from = compose_and_send_tx_func_pair[1]
            for dest_script_pair in dest_scripts:
                dest_script = dest_script_pair[0]
                name_to = dest_script_pair[1]
                burn_free = expected_results[name_from][name_to]
                for use_burning in use_burnings:
                    logger.debug(f'Tx to self, from {name_from} to {name_to}, use_burning: {use_burning}, burn_free: {burn_free}')
                    vout = []
                    if use_burning:
                        vout.append(CTxOut(ToSatoshi(change), dest_script))
                        vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
                        vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
                    else:
                        vout.append(CTxOut(ToSatoshi(amount - fee), dest_script))
                    compose_and_send_tx_func(vout, accepted=use_burning or burn_free, reject_reason='bad-burned')



if __name__ == '__main__':
    GraveTest().main()
