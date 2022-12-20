#!/usr/bin/env python3
# Copyright (c) 2021 The PLC Ultima Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import *
from test_framework.script import *
from test_framework.certs import *
from test_framework.blocktools import create_coinbase, create_block, get_total_expected

'''
total_emission.py
'''

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


class TotalEmissionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [['-debug', '-whitelist=127.0.0.1']] * self.num_nodes
        self.outpoints = []
        self.moneybox_utxo_amounts = {}


    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node)
        self.test_node.add_connection(connection)

        self.test_node2 = TestNode()
        connection2 = NodeConn('127.0.0.1', p2p_port(2), self.nodes[2], self.test_node2)
        self.test_node2.add_connection(connection2)

        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()
        self.test_node2.wait_for_verack()
        self.test_node2.sync_with_ping()


    def run_scenario(self, name, tx_list, total_delta=None, node_index=0, accepted=True, reject_reason=None,
                     full_check=True, refill_mb=None, verbose=True):
        self.log.debug(f'Run scenario {name}, total_delta: {total_delta}, refill_mb: {refill_mb} ...')
        assert_in(node_index, [0,2])
        node = self.nodes[node_index]
        test_node = self.test_node if node_index == 0 else self.test_node2
        total_delta = ToSatoshi(total_delta) if total_delta else 0
        refill_mb = ToSatoshi(refill_mb) if refill_mb is not None else total_delta
        for tx in tx_list:
            tx.rehash()
        tmpl = self.nodes[0].getblocktemplate()
        coinbase_input_hex = tmpl['coinbaseextrains'][0]
        total_amount_orig = extract_total_amount_from_input(coinbase_input_hex)
        total_amount_correct = total_amount_orig + total_delta
        previousblockhash = int(tmpl['previousblockhash'], 16)
        curtime = tmpl['curtime']
        height = tmpl['height']
        bits = int(tmpl['bits'], 16)
        coinbasetxn = create_coinbase(height, None, 0, refill_mb, total_bc_amount=-1)  # without total amount yet

        if full_check and accepted:
            # No total amount coinbase input: rejected
            coinbasetxn_cpy = copy.deepcopy(coinbasetxn)
            coinbasetxn_cpy = add_cert_to_coinbase(coinbasetxn_cpy, COutPoint(int(self.root_cert_hash_holy, 16), 0),
                                                   COutPoint(int(self.pass_cert_hash_holy, 16), 0), self.super_key_holy)
            block = create_block(previousblockhash, coinbasetxn_cpy, curtime, bits, VB_TOP_BITS, tx_list)
            send_block(node, test_node, block, False, 'bad-coinbase-without-total', verbose=verbose)

            # Total amount is 1 satoshi more than required: rejected
            coinbasetxn_cpy = copy.deepcopy(coinbasetxn)
            total_amount = total_amount_correct + 1
            set_total_amount_to_cb_tx(coinbasetxn_cpy, total_amount)
            coinbasetxn_cpy = add_cert_to_coinbase(coinbasetxn_cpy, COutPoint(int(self.root_cert_hash_holy, 16), 0),
                                                   COutPoint(int(self.pass_cert_hash_holy, 16), 0), self.super_key_holy)
            block = create_block(previousblockhash, coinbasetxn_cpy, curtime, bits, VB_TOP_BITS, tx_list)
            send_block(node, test_node, block, False, 'bad-coinbase-wrong-total', verbose=verbose)

            # Total amount is 1 satoshi less than required: rejected
            coinbasetxn_cpy = copy.deepcopy(coinbasetxn)
            total_amount = total_amount_correct - 1
            set_total_amount_to_cb_tx(coinbasetxn_cpy, total_amount)
            coinbasetxn_cpy = add_cert_to_coinbase(coinbasetxn_cpy, COutPoint(int(self.root_cert_hash_holy, 16), 0),
                                               COutPoint(int(self.pass_cert_hash_holy, 16), 0), self.super_key_holy)
            block = create_block(previousblockhash, coinbasetxn_cpy, curtime, bits, VB_TOP_BITS, tx_list)
            send_block(node, test_node, block, False, 'bad-coinbase-wrong-total', verbose=verbose)

            # Zero total amount: rejected
            coinbasetxn_cpy = copy.deepcopy(coinbasetxn)
            total_amount = 0
            set_total_amount_to_cb_tx(coinbasetxn_cpy, total_amount)
            coinbasetxn_cpy = add_cert_to_coinbase(coinbasetxn_cpy, COutPoint(int(self.root_cert_hash_holy, 16), 0),
                                                   COutPoint(int(self.pass_cert_hash_holy, 16), 0), self.super_key_holy)
            block = create_block(previousblockhash, coinbasetxn_cpy, curtime, bits, VB_TOP_BITS, tx_list)
            send_block(node, test_node, block, False, 'bad-coinbase-wrong-total', verbose=verbose)

            # Empty total amount: rejected
            coinbasetxn_cpy = copy.deepcopy(coinbasetxn)
            total_amount = None
            set_total_amount_to_cb_tx(coinbasetxn_cpy, total_amount)
            coinbasetxn_cpy = add_cert_to_coinbase(coinbasetxn_cpy, COutPoint(int(self.root_cert_hash_holy, 16), 0),
                                                   COutPoint(int(self.pass_cert_hash_holy, 16), 0), self.super_key_holy)
            block = create_block(previousblockhash, coinbasetxn_cpy, curtime, bits, VB_TOP_BITS, tx_list)
            send_block(node, test_node, block, False, 'bad-coinbase-wrong-total', verbose=verbose)

        # Positive scenario at the end: accepted
        total_amount = total_amount_correct
        set_total_amount_to_cb_tx(coinbasetxn, total_amount)
        coinbasetxn.rehash()
        block = create_block(previousblockhash, coinbasetxn, curtime, bits, VB_TOP_BITS, tx_list)
        send_block(node, test_node, block, accepted, reject_reason, verbose=verbose)
        return total_amount


    def parse_moneybox_utxos(self, block_hash, verbose=False):
        moneybox_utxos = []
        block = self.nodes[0].getblock(block_hash, 1)
        txid_cb = block['tx'][0]
        tx_cb = self.nodes[0].getrawtransaction(txid_cb, 1)
        for v in tx_cb['vout']:
            if v['scriptPubKey']['type'] == 'scripthash' and v['scriptPubKey']['addresses'][0] == MoneyboxP2SHAddress():
                outpoint = COutPoint(int(txid_cb, 16), v['n'])
                moneybox_utxos.append(outpoint)
                self.moneybox_utxo_amounts[outpoint] = v['value']
        if verbose:
            self.log.debug(f'tx_cb: {tx_cb}')
        return moneybox_utxos

    def get_total_in_block(self, block_height=None):
        node0 = self.nodes[0]
        block_hash = node0.getblockhash(block_height) if block_height else node0.getbestblockhash()
        block = node0.getblock(block_hash, 2)
        height = block['height']
        total_got = ToCoins(extract_total_amount_from_cb_tx(block['tx'][0]))
        self.log.debug(f'total on height {height}: {total_got}')
        return total_got

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Check total amount in blockchain:
        total_amount_prev = 0
        for i in range(1, 200):
            hash1 = node0.getblockhash(i)
            block1 = node0.getblock(hash1, 2)
            total_am_inputs = [inp for inp in block1['tx'][0]['vin'] if inp['coinbasetype'] == TXIN_MARKER_TOTAL_AMOUNT]
            assert_equal(len(total_am_inputs), 1)
            total_amount = extract_total_amount_from_scriptsig(hex_str_to_bytes(total_am_inputs[0]['coinbase']))
            assert_greater_than_or_equal(total_amount, total_amount_prev)
            if total_amount:
                assert_equal(ToCoins(total_amount), BASE_CB_AMOUNT * min(i, 100))
            total_amount_prev = total_amount

        if not MONEYBOX_GRANULARITY:
            raise SkipTest('no moneybox - no new money - no reaching total emission limit')
        self.taxfree_cert_filename = os.path.join(self.options.tmpdir + '/node0/regtest', 'taxfree.cert')
        self.test_node.sync_with_ping()
        self.test_node2.sync_with_ping()
        fee = Decimal('0.00001000')
        fee_sum = 0

        (self.root_cert_hash_holy, self.pass_cert_hash_holy, self.super_key_holy) = generate_certs_pair(node0, self.test_node,
                                                                                         pass_cert_flag_default=ALLOW_MINING)
        node0.generate(1)

        # Root cert:
        genesis_key0 = create_key(True, GENESIS_PRIV_KEY0_BIN)
        (self.outpoints, fee_gen) = generate_outpoints(node0, 1, Decimal('1.03') + fee, AddressFromPubkey(genesis_key0.get_pubkey()))
        fee_sum += -fee_gen
        fee_sum += fee
        (tx2, ca3_cert_key) = compose_cert_tx(self.outpoints.pop(0), Decimal(1), genesis_key0, 'root_cert')
        root_cert_hash = send_tx(node0, self.test_node, tx2, True)
        node0.generate(1)

        # CA3 cert:
        (self.outpoints, fee_gen) = generate_outpoints(node0, 1, Decimal('1.03') + fee, AddressFromPubkey(ca3_cert_key.get_pubkey()))
        fee_sum += -fee_gen
        fee_sum += fee
        (tx2, red_key) = compose_cert_tx(self.outpoints.pop(0), Decimal(1), ca3_cert_key, 'user_cert')
        ca3_cert_hash = send_tx(node0, self.test_node, tx2, True)
        node0.generate(1)

        # User money:
        user_key = red_key
        (self.outpoints, fee_gen) = generate_outpoints(node0, 25, Decimal(4500), AddressFromPubkey(user_key.get_pubkey()))
        fee_sum += -fee_gen
        node0.generate(1)

        moneybox_utxos = []
        for i in range(1,101):
            block_hash = node0.getblockhash(i)
            moneybox_utxos.extend(self.parse_moneybox_utxos(block_hash))
        assert_equal(len(moneybox_utxos), 1000)

        total_mined = BASE_CB_AMOUNT * 100
        total_moneybox = 100 * 10 * 100

        node0.importprivkey(SecretBytesToBase58(self.super_key_holy.get_secret()))
        restart_node_with_cert(self, True, self.super_key_holy.get_pubkey(), self.root_cert_hash_holy, self.pass_cert_hash_holy)
        connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node)
        self.test_node.add_connection(connection)

        node1.importprivkey(SecretBytesToBase58(self.super_key_holy.get_secret()))
        restart_node_with_cert(self, True, self.super_key_holy.get_pubkey(), self.root_cert_hash_holy,
                               self.pass_cert_hash_holy, gen_block=False, index=1, next_indexes=[2])
        connect_nodes(node0, 1)
        node0.generate(1)
        self.sync_all()

        generate_many_blocks(node0, START_TOTAL_NG_BLOCK - node0.getblockcount() - 1)
        self.sync_all()
        self.test_node.sync_with_ping()

        node0.generate(1)  # this is the first block with total amount, check it:
        assert_equal(self.get_total_in_block(), total_mined + total_moneybox)

        self.run_scenario('empty block', [], 0, full_check=False)
        self.run_scenario('empty block with full check', [], 0)
        node0.generate(1)
        self.sync_all()
        assert_equal(self.get_total_in_block(), total_mined + total_moneybox)

        amount = Decimal(4500)
        dest_pkh = hash160(b'lord-the-son-of-a-bitch')
        dest_script = GetP2PKHScript(dest_pkh)
        (burn1, burn2, rest) = BurnedAndChangeAmount(amount - fee)
        destinations = {GraveScript1(): burn1, GraveScript2(): burn2, dest_script: rest}
        transactions = [compose_tx([self.outpoints.pop()], user_key, destinations) for _ in range(5)]
        total_amount = ToCoins(self.run_scenario('block with regular transactions', transactions, 0))
        node0.generate(1)
        self.sync_all()
        assert_equal(self.get_total_in_block(), total_mined + total_moneybox)

        transactions = [compose_tx([self.outpoints.pop()], user_key, destinations) for _ in range(5)]
        self.run_scenario('block regular transactions invalid total', transactions, 100, 0, False, 'bad-coinbase-wrong-total', refill_mb=0)
        node0.generate(2)
        sync_blocks(self.nodes)
        assert_equal(self.get_total_in_block(), total_mined + total_moneybox)

        height = node0.getblockcount()
        self.log.debug(f'height: {height}, total_mined: {total_mined}, total_moneybox: {total_moneybox}, fee_sum: {fee_sum}')

        mint_reward = Decimal(50000)
        mint_rewards_on_last_iteration = [mint_reward, mint_reward]
        last_iteration = False
        moneybox_gran = 100
        mint_fee = fee * 100
        fork_on_iterations = [1,3]
        for i in range(7):
            fee_sum_this_iter = 0
            moneybox_utxos_this_iter = []
            use_fork = (i in fork_on_iterations)
            total_moneybox_this_iter = 0
            total_mined_this_iter = 0
            if use_fork:
                self.sync_all()
                disconnect_nodes(node0, 1)
                disconnect_nodes(node1, 0)
            for j in range(2):
                mint_reward_now = min(mint_reward, (TOTAL_EMISSION_LIMIT - total_amount) // 100 * 100)
                if not mint_reward_now:
                    last_iteration = True
                    mint_reward_now = 0 if len(mint_rewards_on_last_iteration) == 0 else mint_rewards_on_last_iteration.pop()
                    if not mint_reward_now:
                        break
                assert(not (last_iteration and use_fork))  # don't use fork on last iteration
                needed_moneybox_utxos = int(mint_reward_now // moneybox_gran)
                self.log.debug(f'iter: {i}-{j}, mint_reward_now: {mint_reward_now}, last_iteration: {last_iteration}')
                now = node0.getblockheader(node0.getbestblockhash())['time']
                (tx3, _) = compose_mint_tx([self.outpoints.pop()], moneybox_utxos[0:needed_moneybox_utxos],
                                           COutPoint(int(root_cert_hash, 16), 0), COutPoint(int(ca3_cert_hash, 16), 0),
                                           user_key, Decimal(4500), now + ONE_YEAR * 10, Decimal(mint_reward_now) - mint_fee, 0, True)
                self.log.debug(f'mint tx: {print_tx_ex(tx3, inputs_cnt=2)}')
                del moneybox_utxos[0:needed_moneybox_utxos]
                gen_by_node = i or j
                if gen_by_node:
                    mint_txid = send_tx(node0, self.test_node, tx3, True)
                    self.log.debug(f'sent mint_tx: {mint_txid}')
                    next_block_hash = node0.generate(1)[0]
                else:
                    self.run_scenario('block with mint transaction', [tx3], mint_reward_now, verbose=False)
                    next_block_hash = node0.getbestblockhash()
                if not last_iteration:
                    moneybox_utxos_this_iter.extend(self.parse_moneybox_utxos(next_block_hash))
                    assert_equal(len(moneybox_utxos) + len(moneybox_utxos_this_iter), 1000)
                    total_moneybox_this_iter += mint_reward_now
                else:
                    # TODO: compose block with mb refill and confirm rejected
                    more = self.parse_moneybox_utxos(next_block_hash, True)
                    assert_equal(len(more), 0)
                fee_sum_this_iter += mint_fee
                total_amount = ToCoins(extract_total_amount_from_cb_tx(node0.getblock(next_block_hash, 2)['tx'][0]))
                expected = total_mined + total_mined_this_iter + total_moneybox + total_moneybox_this_iter
                self.log.debug(f'iter: {i}-{j}, height: {node0.getblockcount()}, total_amount: {total_amount}, expected: {expected}, total_mined_this_iter: {total_mined_this_iter}, total_mined: {total_mined}, total_moneybox_this_iter: {total_moneybox_this_iter}, total_moneybox: {total_moneybox}, fee_sum_this_iter: {fee_sum_this_iter}, fee_sum: {fee_sum}')
                assert_equal(total_amount, expected)
                if not last_iteration:
                    assert_greater_than_or_equal(TOTAL_EMISSION_LIMIT, total_amount)
            if not mint_reward_now:
                break
            blocks_to_gen = 101
            if use_fork:
                self.log.debug(f'fork, iter {i}')
                # We called node0.generate() twice after nodes were disconnected, ensure it
                assert_equal(node0.getblockcount(), node1.getblockcount() + 2)
                # generate longer chain on node1, node0 will switch to it and put 2 mined mint transactions back to mempool
                node1.generate(3)
                connect_nodes(node0, 1)
                sync_blocks(self.nodes)
                total_amount = ToCoins(extract_total_amount_from_cb_tx(node0.getblock(node0.getbestblockhash(), 2)['tx'][0]))
                # verify total amount after fork, don't count
                # total_mined_this_iter and total_moneybox_this_iter - old chain is no more actual
                assert_equal(total_amount, total_mined + total_moneybox)
                next_block_hash = node0.generate(1)[0]
                moneybox_utxos.extend(self.parse_moneybox_utxos(next_block_hash))
                blocks_to_gen -= 2
            else:
                moneybox_utxos.extend(moneybox_utxos_this_iter)
            if not last_iteration:
                assert_equal(len(moneybox_utxos), 1000)
            fee_sum += fee_sum_this_iter
            total_mined += total_mined_this_iter
            total_moneybox += total_moneybox_this_iter
            node0.generate(blocks_to_gen)

        # Here we reached TOTAL_EMISSION_LIMIT, but have a little coins in moneybox (less than 100 coins)
        assert_greater_than_or_equal(TOTAL_EMISSION_LIMIT, total_amount - 2 * CB_AMOUNT_AFTER_BLOCK_100)
        assert_greater_than(total_amount, TOTAL_EMISSION_LIMIT - ToCoins('0.1'))


if __name__ == '__main__':
    TotalEmissionTest().main()
