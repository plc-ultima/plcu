#!/usr/bin/env python3
# Copyright (c) 2022 The PLC Ultima X Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.certs import *

'''
miami_police.py
'''

fee = Decimal('0.00001000')


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


def fill_up_script(user_key, signature_user, super_key, signature_super, utxo_cert_root, utxo_cert_ca3, mess_script=0):
    ops = []
    if not mess_script:
        # Regular workflow:
        ops.extend([signature_user, user_key.get_pubkey(), 0, signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 1:
        # swap used and super:
        ops.extend([signature_super, super_key.get_pubkey(), 0, signature_user, user_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 2:
        # skip zero operand:
        ops.extend([signature_user, user_key.get_pubkey(), signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 3:
        # extra zero operand:
        ops.extend([signature_user, user_key.get_pubkey(), 0, 0, signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 4:
        # swap root and ca3 certs:
        ops.extend([signature_user, user_key.get_pubkey(), 0, signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_ca3.hash), utxo_cert_ca3.n, ser_uint256(utxo_cert_root.hash),
                    utxo_cert_root.n])
    elif mess_script == 5:
        # swap hash/n in certs:
        ops.extend([signature_user, user_key.get_pubkey(), 0, signature_super, super_key.get_pubkey(), utxo_cert_ca3.n,
                    ser_uint256(utxo_cert_ca3.hash), utxo_cert_root.n, ser_uint256(utxo_cert_root.hash)])
    elif mess_script == 6:
        # forget user sig/pubkey (with zero operand first):
        ops.extend([0, signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 7:
        # forget user sig/pubkey (with zero operand last):
        ops.extend([signature_super, super_key.get_pubkey(), 0,
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 8:
        # forget user sig/pubkey (without zero operand):
        ops.extend([signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 9:
        # forget super sig/pubkey (with zero operand first):
        ops.extend([0, signature_user, user_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 10:
        # forget super sig/pubkey (with zero operand last):
        ops.extend([signature_user, user_key.get_pubkey(), 0,
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 11:
        # forget super sig/pubkey (without zero operand):
        ops.extend([signature_user, user_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 12:
        # forget root cert:
        ops.extend([signature_user, user_key.get_pubkey(), 0, signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_ca3.hash), utxo_cert_ca3.n])
    elif mess_script == 13:
        # forget ca3 cert:
        ops.extend([signature_user, user_key.get_pubkey(), 0, signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n])
    elif mess_script == 14:
        # forget both certs:
        ops.extend([signature_user, user_key.get_pubkey(), 0, signature_super, super_key.get_pubkey()])
    elif mess_script == 15:
        # forget root cert and duplicate ca3:
        ops.extend([signature_user, user_key.get_pubkey(), 0, signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_ca3.hash), utxo_cert_ca3.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 16:
        # forget ca3 cert and duplicate root:
        ops.extend([signature_user, user_key.get_pubkey(), 0, signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_root.hash),
                    utxo_cert_root.n])
    elif mess_script == 17:
        # forget user sig/pubkey and duplicate super:
        ops.extend([signature_super, super_key.get_pubkey(), 0, signature_super, super_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    elif mess_script == 18:
        # forget super sig/pubkey and duplicate user:
        ops.extend([signature_user, user_key.get_pubkey(), 0, signature_user, user_key.get_pubkey(),
                    ser_uint256(utxo_cert_root.hash), utxo_cert_root.n, ser_uint256(utxo_cert_ca3.hash),
                    utxo_cert_ca3.n])
    else:
        assert 0, f'invalid mess_script arg: {mess_script}'
    return ops


class MiamiPoliceTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.extra_args = [['-debug', '-whitelist=127.0.0.1', '-totalforkblock-regtest=2500',
                            '-maxcablock-regtest=2500']] * self.num_nodes
        self.outpoints = []
        self.virtual_cur_time_offset = 0

    def setup_chain(self):
        cachedir = os.path.join(self.options.cachedir, 'more', 'cache_1300')
        if os.path.isdir(self.options.cachedir) and os.path.isdir(cachedir):
            self.log.debug(f'setup_chain, cachedir before: {self.options.cachedir}, now: {cachedir}')
            self.options.cachedir = cachedir
        super().setup_chain()

    def setup_network(self):
        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()


    def run_scenario(self, name, time_lock, spend_way, wait=0, blocks_on_wait=10, root_cert_key=None,
                     root_cert_flags=None, root_cert_hash=None, root_cert_sig_hash=None, root_cert_sig_key=None,
                     root_cert_signature=None, root_cert_revoked=False, pass_cert_key=None, pass_cert_flags=None,
                     pass_cert_hash=None, pass_cert_sig_hash=None, pass_cert_sig_key=None, pass_cert_signature=None,
                     pass_cert_revoked=False, super_key=None, amount=None, spend_user_key=None,
                     user_key_is_super=False, zero_timepoint=False, mess_script=0,
                     accepted=True, reject_reason_p2p=None):
        self.log.info(f'Start scenario {name} ...')
        assert_in(spend_way, [1, 2])
        node0 = self.nodes[0]

        (root_cert_hash, pass_cert_hash, super_key) = generate_certs_pair(node0, self.test_node,
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
                                                                          pass_cert_flag_default=MASTER_OF_TIME)
        node0.generate(1)
        self.sync_all()

        amount = amount if amount is not None else Decimal(75)
        user_key = super_key if user_key_is_super else create_key()
        print_key_verbose(user_key, 'user_key')
        (self.outpoints, _) = generate_outpoints(node0, 1, amount, AddressFromPubkey(user_key.get_pubkey()))
        node0.generate(1)
        self.sync_all()

        last_hash = node0.getbestblockhash()
        last_block = node0.getblock(last_hash)
        cur_time = last_block['time']
        timepoint = 0 if zero_timepoint else (cur_time + time_lock)
        self.log.debug(f'cur_time: {cur_time}, time_lock: {time_lock}, timepoint: {timepoint}')
        script_with_timelock = GetP2PKHScriptWithTimeLock(hash160(user_key.get_pubkey()), timepoint)
        dest_scripts_and_amounts = {script_with_timelock: amount - fee}
        tx1 = compose_tx([self.outpoints.pop(0)], user_key, dest_scripts_and_amounts)
        send_tx(node0, self.test_node, tx1, True, verbose=True)
        node0.generate(1)
        self.sync_all()

        if wait > 0:
            start_wait_time = cur_time
            virtual_cur_time_offset = 0
            self.log.debug(f'will wait {wait} seconds, blocks: {blocks_on_wait}, start_wait_time: {start_wait_time}')
            step = wait // blocks_on_wait
            for i in range(blocks_on_wait):
                virtual_cur_time_offset += step
                for node in self.nodes:
                    node.setmocktime(start_wait_time + virtual_cur_time_offset)
                blockhashes = self.nodes[0].generate(1)
                self.log.debug('wait, block {} time: {}'.format(i, self.nodes[0].getblock(blockhashes[0])['time']))
            sync_chain(self.nodes)
            self.test_node.sync_with_ping()

        amount_step2 = amount - fee * 2
        user_utxos = [COutPoint(int(tx1.hash, 16), 0)]
        if spend_user_key:
            user_key = spend_user_key

        if spend_way == 1:
            # Locked user outputs are in tx on previous step - set nLockTime field:
            locktime = node0.getblockheader(node0.getbestblockhash())['mediantime'] - 1
            dest_scripts_and_amounts = {GetP2PKHScript(hash160(user_key.get_pubkey())): amount_step2}
            tx2 = compose_tx_spending_locked_outputs(user_utxos, user_key,
                                                     dest_scripts_and_amounts, script_with_timelock, locktime)
            send_tx(node0, self.test_node, tx2, accepted, reject_reason_p2p, verbose=True)
        else:
            utxo_cert_root = COutPoint(int(root_cert_hash, 16), 0)
            utxo_cert_ca3 = COutPoint(int(pass_cert_hash, 16), 0)

            # compose_tx_with_cert:
            tx3 = CTransaction()
            for user_utxo in user_utxos:
                tx3.vin.append(CTxIn(user_utxo, script_with_timelock, 0xffffffff))
            tx3.vout.append(CTxOut(ToSatoshi(amount_step2), GetP2PKHScript(hash160(user_key.get_pubkey()))))

            for i in range(len(user_utxos)):
                (sig_hash, err) = SignatureHash(CScript(tx3.vin[i].scriptSig), tx3, i, SIGHASH_ALL)
                assert (err is None)
                signature_user = user_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                signature_super = super_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                operands = fill_up_script(user_key, signature_user, super_key, signature_super,
                                          utxo_cert_root, utxo_cert_ca3, mess_script)
                tx3.vin[i].scriptSig = CScript(operands)
            tx3.rehash()
            send_tx(node0, self.test_node, tx3, accepted, reject_reason_p2p, verbose=True)

        node0.generate(1)
        self.sync_all()
        self.log.debug(f'Finish scenario {name}')


    def run_test(self):
        node0 = self.nodes[0]
        txid = node0.sendtoaddress(node0.getnewaddress(), 100)
        generate_many_blocks(node0, CLTV_HEIGHT - node0.getblockcount())
        self.sync_all()
        self.test_node.sync_with_ping()

        fake_key = create_key()

        self.run_scenario('positive_1key_wait', ONE_YEAR, 1, ONE_YEAR + ONE_MONTH, blocks_on_wait=70)
        self.run_scenario('positive_1key_lock_to_current_wait', 0, 1, ONE_HOUR)
        self.run_scenario('positive_1key_lock_to_past_wait', -ONE_HOUR, 1, ONE_HOUR)
        self.run_scenario('negative_1key_nowait', ONE_YEAR, 1, 0, accepted=False)
        self.run_scenario('positive_1key_wait_user_key_is_super', ONE_HOUR, 1, ONE_DAY, user_key_is_super=True)
        self.run_scenario('negative_1key_wait_inv_userkey', ONE_HOUR, 1, ONE_DAY, spend_user_key=fake_key,
                          accepted=False)
        self.run_scenario('negative_1key_wait_zero_timepoint', 0, 1, ONE_HOUR, zero_timepoint=True, accepted=False)
        self.run_scenario('negative_1key_nowait_zero_timepoint', 0, 1, 0, zero_timepoint=True, accepted=False)
        self.run_scenario('positive_2keys_nowait_zero_timepoint', 0, 2, 0, zero_timepoint=True)
        self.run_scenario('positive_2keys_nowait', ONE_YEAR, 2, 0)
        self.run_scenario('positive_2keys_wait', ONE_HOUR, 2, ONE_DAY)
        self.run_scenario('negative_2keys_nowait_inv_userkey', ONE_YEAR, 2, 0, spend_user_key=fake_key, accepted=False)
        self.run_scenario('positive_2keys_nowait_flag_in_root_cert', ONE_YEAR, 2, 0, root_cert_flags=MASTER_OF_TIME,
                          pass_cert_flags=0)
        self.run_scenario('positive_2keys_nowait_flag_in_both_certs', ONE_YEAR, 2, 0, root_cert_flags=MASTER_OF_TIME,
                          pass_cert_flags=MASTER_OF_TIME)
        #
        # negative_2keys_nowait scenarios:
        #
        for i in range(1,19):
            self.run_scenario(f'negative_2keys_nowait_mess_script_{i}', ONE_YEAR, 2, 0, mess_script=i, accepted=False)

        self.run_scenario('missing_root_cert', ONE_YEAR, 2, 0,
                          root_cert_hash=bytes_to_hex_str(hash256(b'xyz')),
                          accepted=False)

        self.run_scenario('missing_pass_cert', ONE_YEAR, 2, 0,
                          pass_cert_hash=bytes_to_hex_str(hash256(b'xyz-again')),
                          accepted=False)

        self.run_scenario('tx_instead_of_root_cert', ONE_YEAR, 2, 0,
                          root_cert_hash=txid,
                          accepted=False)

        self.run_scenario('tx_instead_of_pass_cert', ONE_YEAR, 2, 0,
                          pass_cert_hash=txid,
                          accepted=False)

        self.run_scenario('root_cert_is_not_root', ONE_YEAR, 2, 0,
                          root_cert_key=fake_key,
                          accepted=False)

        self.run_scenario('pass_cert_is_not_child_of_root', ONE_YEAR, 2, 0,
                          pass_cert_key=fake_key,
                          accepted=False)

        self.run_scenario('super_key_not_mentioned_in_cert', ONE_YEAR, 2, 0,
                          super_key=fake_key,
                          accepted=False)

        self.run_scenario('no_flag_in_cert_v1', ONE_YEAR, 2, 0,
                          pass_cert_flags=0,
                          accepted=False)

        self.run_scenario('no_flag_in_cert_v2', ONE_YEAR, 2, 0,
                          pass_cert_flags=SILVER_HOOF | ALLOW_MINING,
                          accepted=False)

        self.run_scenario('root_cert_revoked', ONE_YEAR, 2, 0,
                          root_cert_revoked=True,
                          accepted=False)

        self.run_scenario('pass_cert_revoked', ONE_YEAR, 2, 0,
                          pass_cert_revoked=True,
                          accepted=False)

        self.run_scenario('root_cert_empty_signature', ONE_YEAR, 2, 0,
                          root_cert_signature=b'',
                          accepted=False)

        self.run_scenario('pass_cert_empty_signature', ONE_YEAR, 2, 0,
                          pass_cert_signature=b'',
                          accepted=False)

        self.run_scenario('root_cert_invalid_sig_hash', ONE_YEAR, 2, 0,
                          root_cert_sig_hash=hash256(b'no!'),
                          accepted=False)

        self.run_scenario('pass_cert_invalid_sig_hash', ONE_YEAR, 2, 0,
                          pass_cert_sig_hash=hash256(b'no-no-no dont even think'),
                          accepted=False)

        self.run_scenario('root_cert_block_signed_with_another_key', ONE_YEAR, 2, 0,
                          root_cert_sig_key=fake_key,
                          accepted=False)

        self.run_scenario('pass_cert_block_signed_with_another_key', ONE_YEAR, 2, 0,
                          pass_cert_sig_key=fake_key,
                          accepted=False)

        fake_signature = sign_compact(hash256(b'no_chance_either'), fake_key.get_secret())
        self.run_scenario('root_cert_invalid_signature', ONE_YEAR, 2, 0,
                          root_cert_signature=fake_signature,
                          accepted=False)

        fake_signature = sign_compact(hash256(b'aaaaaaaaaaaa'), fake_key.get_secret())
        self.run_scenario('pass_cert_invalid_signature', ONE_YEAR, 2, 0,
                          pass_cert_signature=fake_signature,
                          accepted=False)


if __name__ == '__main__':
    MiamiPoliceTest().main()
