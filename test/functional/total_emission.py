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
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.extra_args = [['-debug', '-whitelist=127.0.0.1', '-holyminingblock-regtest=1000']]
        self.outpoints = []
        self.moneybox_utxo_amounts = {}


    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()


    def compose_and_send_block(self, coinbase, tx_list, accepted, reject_reason = None):
        coinbase.rehash()
        for tx in tx_list:
            tx.rehash()
        tmpl = self.nodes[0].getblocktemplate()
        block = create_block(int(tmpl['previousblockhash'], 16), coinbase, tmpl['curtime'], int(tmpl['bits'], 16), VB_TOP_BITS, tx_list)
        self.log.debug(f'block: {block}')
        send_block(self.nodes[0], self.test_node, block, accepted, reject_reason)


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


    def run_test(self):
        node0 = self.nodes[0]
        self.test_node.sync_with_ping()
        fee = Decimal('0.00001')
        fee_sum = 0

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
        (self.outpoints, fee_gen) = generate_outpoints(node0, 20, Decimal(4500), AddressFromPubkey(user_key.get_pubkey()))
        fee_sum += -fee_gen
        node0.generate(1)

        moneybox_utxos = []
        for i in range(1,101):
            block_hash = node0.getblockhash(i)
            moneybox_utxos.extend(self.parse_moneybox_utxos(block_hash))
        assert_equal(len(moneybox_utxos), 1000)

        height = node0.getblockcount()
        txoutsetinfo = node0.gettxoutsetinfo()
        total_mined = BASE_CB_AMOUNT * 100 + Decimal('0.005') * (height - 100)
        total_moneybox = 100 * 10 * 100
        self.log.debug(f'height: {height}, total_mined: {total_mined}, total_moneybox: {total_moneybox}, fee_sum: {fee_sum}, txoutsetinfo: {txoutsetinfo}')
        total_amount = txoutsetinfo['total_amount']
        assert_equal(total_amount, total_mined + total_moneybox - fee_sum)

        mint_reward = 50000
        mint_rewards_on_last_iteration = [mint_reward, mint_reward]
        last_iteration = False
        moneybox_gran = 100
        mint_fee = fee * 100
        for i in range(7):
            for j in range(2):
                mint_reward_now = min(mint_reward, int(TOTAL_EMISSION_LIMIT - total_amount) // 100 * 100)
                if not mint_reward_now:
                    last_iteration = True
                    mint_reward_now = 0 if len(mint_rewards_on_last_iteration) == 0 else mint_rewards_on_last_iteration.pop()
                    if not mint_reward_now:
                        break
                needed_moneybox_utxos = mint_reward_now // moneybox_gran
                self.log.debug(f'iter: {i}-{j}, mint_reward_now: {mint_reward_now}, last_iteration: {last_iteration}')
                now = node0.getblockheader(node0.getbestblockhash())['time']
                (tx3, _) = compose_mint_tx([self.outpoints.pop()], moneybox_utxos[0:needed_moneybox_utxos],
                                           COutPoint(int(root_cert_hash, 16), 0), COutPoint(int(ca3_cert_hash, 16), 0),
                                           user_key, Decimal(4500), now + ONE_YEAR * 10, Decimal(mint_reward_now) - mint_fee, 0, True)
                send_tx(node0, self.test_node, tx3, True)
                del moneybox_utxos[0:needed_moneybox_utxos]
                next_block_hash = node0.generate(1)[0]
                if not last_iteration:
                    moneybox_utxos.extend(self.parse_moneybox_utxos(next_block_hash))
                    assert_equal(len(moneybox_utxos), 1000)
                    total_moneybox += mint_reward_now
                else:
                    # TODO: compose block with mb refill and confirm rejected
                    more = self.parse_moneybox_utxos(next_block_hash, True)
                    if len(mint_rewards_on_last_iteration) > 0:
                        assert_equal(len(more), 1)
                        last_moneybox_amount = self.moneybox_utxo_amounts[more[0]]
                        assert_greater_than(100, last_moneybox_amount)
                        moneybox_utxos.extend(more)
                        total_moneybox += last_moneybox_amount
                        self.log.debug(f'iter: {i}-{j}, last_moneybox_amount: {last_moneybox_amount}')
                    else:
                        assert_equal(len(more), 0)
                fee_sum += mint_fee
                total_mined += Decimal('0.005')
                txoutsetinfo = node0.gettxoutsetinfo()
                total_amount = txoutsetinfo['total_amount']
                self.log.debug(f'iter: {i}-{j}, height: {node0.getblockcount()}, total_mined: {total_mined}, total_moneybox: {total_moneybox}, fee_sum: {fee_sum}, txoutsetinfo: {txoutsetinfo}')
                assert_equal(total_amount, total_mined + total_moneybox - fee_sum)
                if not last_iteration:
                    assert_greater_than_or_equal(TOTAL_EMISSION_LIMIT, total_amount)
            if not mint_reward_now:
                break
            node0.generate(98)
            total_mined += Decimal('0.005') * 98

        # Here we reached TOTAL_EMISSION_LIMIT, but have a little coins in moneybox (less than 100 coins)
        assert_greater_than_or_equal(TOTAL_EMISSION_LIMIT, total_amount - 2 * Decimal('0.005'))
        assert_greater_than(total_amount, TOTAL_EMISSION_LIMIT - ToCoins('0.1'))



if __name__ == '__main__':
    TotalEmissionTest().main()
