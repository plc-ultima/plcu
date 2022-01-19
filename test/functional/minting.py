#!/usr/bin/env python3
# Copyright (c) 2019 The PLC Ultima Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import *
from test_framework.script import *
from test_framework.certs import *
from test_framework.blocktools import create_coinbase, create_block, get_tx_output_amount, get_moneybox_granularity
from test_framework.filelock import FileLock
from minting_testcases import get_minting_testcases

'''
MintingTest
'''

GUESS_SIGSIZES_MAX_ATTEMPTS = 5000
MAX_BLOCKS_IN_WAIT_CYCLE = 30

print_buffer = []


def split_names(names_str):
    names_list = names_str.split('+')
    if '' in names_list:
        names_list.remove('')
    return names_list


def print_to_buffer(s):
    global print_buffer
    print_buffer.append(s)


def shuffle_data(buffer, comment, print_func):
    buffer2 = bytearray(buffer)
    random.shuffle(buffer2)
    buffer2 = bytes(buffer2)
    print_func('shuffle_data, buffer before ({}): {}, buffer after ({}): {}, {}'.format(len(buffer), bytes_to_hex_str(buffer), len(buffer2), bytes_to_hex_str(buffer2), comment))
    return buffer2


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

class MintingTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = False
        self.extra_args = [['-debug', '-whitelist=127.0.0.1'], ['-debug']]
        self.genesis_key0 = create_key(True, GENESIS_PRIV_KEY0_BIN)
        self.virtual_cur_time_offset = 0
        self.txmap = {}
        self.user_keys = []
        self.user_keys_m = None
        self.ben_key = None
        self.keys_count_required = None
        self.keys_count_used = None
        self.multisig = None
        self.locked_outputs = False
        self.step = 1
        self.fund_police_key = None
        self.fund_project_key = None
        self.reward_hints = {}


    def add_options(self, parser):
        parser.add_option("--runtestcase", dest="runtestcase", action="store", help="runtestcase")
        parser.add_option("--runtestcasemask", dest="runtestcasemask", action="store", help="run testcase mask: run by mask")
        parser.add_option("--mintalltestcases", dest="mintalltestcases", action="store", help="mint all testcases: run all test scenarios")


    def acceptnonstdtxn_from_args(self):
        acceptnonstdtxn = 0
        name = self.options.runtestcase
        if name is not None:
            testcase = get_minting_testcases()[name]
            if 'acceptnonstdtxn' in testcase:
                acceptnonstdtxn = testcase['acceptnonstdtxn']
        return acceptnonstdtxn


    def setup_network(self):
        # add some more arguments to self.extra_args here,
        # in set_test_params() we don't know our testcase name yet:
        acc = self.acceptnonstdtxn_from_args()
        for args in self.extra_args:
            args.append(f'-acceptnonstdtxn={acc}')

        super().setup_network()

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()


    def apply_print_buffer(self):
        global print_buffer
        for line in print_buffer:
            self.log.debug(line)
        print_buffer.clear()


    def clear_print_buffer(self):
        global print_buffer
        print_buffer.clear()

    def set_default_print_func_if_none(self, print_func):
        if not print_func:
            print_func = self.log.debug
        return print_func

    def check_parameters(self, params):
        if 'skip_test' in params and params['skip_test']:
            raise SkipTest('skipped')
        if 'keys_count_required' not in params or params['keys_count_required'] is None:
            params['keys_count_required'] = 'random'
        if 'keys_count_total' not in params or params['keys_count_total'] is None:
            params['keys_count_total'] = random.randint(1,12)
        if 'keys_count_used' not in params or params['keys_count_used'] is None:
            params['keys_count_used'] = 'auto'
        if 'fee_total' not in params or params['fee_total'] is None:
            params['fee_total'] = 'auto'
        if params['keys_count_required'] == 'random':
            params['keys_count_required'] = 0 if not params['keys_count_total'] else random.randint(1, params['keys_count_total'])
        if params['keys_count_used'] == 'auto':
            required = params['keys_count_required'] if params['keys_count_required'] > 0 else params['keys_count_total']
            params['keys_count_used'] = required

        if 'sig_model' not in params:
            params['sig_model'] = 'singlesig'
        if params['sig_model'] == 'random':
            params['sig_model'] = 'singlesig' if random.randint(0, 1) == 0 else 'multisig'
        assert_in(params['sig_model'], ['singlesig', 'multisig'])

        self.ca3_age = params['ca3_age'] if 'ca3_age' in params else 0
        self.usermoney_age = params['usermoney_age'] if 'usermoney_age' in params else 0
        self.ben_enabled = params['ben_enabled'] if 'ben_enabled' in params else False
        self.keys_count_required = params['keys_count_required'] if params['keys_count_required'] > 0 else params['keys_count_total']
        self.keys_count_used = params['keys_count_used']
        self.multisig = params['sig_model'] == 'multisig'
        self.lock_interval_min = params['lock_interval_min'] if 'lock_interval_min' in params else 3600
        self.lock_interval_max = params['lock_interval_max'] if 'lock_interval_max' in params else 3600 * 24 * 365
        self.invalid_root_cert = params['invalid_root_cert'] if 'invalid_root_cert' in params else None
        self.invalid_user_cert = params['invalid_user_cert'] if 'invalid_user_cert' in params else None
        self.greenflag = params['greenflag'] if 'greenflag' in params else False
        self.green_flag_in_user_cert = params['green_flag_in_user_cert'] if 'green_flag_in_user_cert' in params else False
        self.exp_date_offset = params['ca3_expiration_offset'] if 'ca3_expiration_offset' in params else None
        self.minting_limit = params['ca3_minting_limit'] if 'ca3_minting_limit' in params else None
        self.daily_limit = params['ca3_daily_limit'] if 'ca3_daily_limit' in params else None
        self.free_ben_enabled = params['free_ben_enabled'] if 'free_ben_enabled' in params else False
        self.revoke_root_cert = params['revoke_root_cert'] if 'revoke_root_cert' in params else False
        self.revoke_user_cert = params['revoke_user_cert'] if 'revoke_user_cert' in params else False
        self.refill_moneybox_accepted = params['refill_moneybox_accepted'] if 'refill_moneybox_accepted' in params else True
        self.sivler_hoof = params['sivler_hoof'] if 'sivler_hoof' in params else False
        self.separate_white = params['separate_white'] if 'separate_white' in params else False
        self.gen_block_after_cert = params['gen_block_after_cert'] if 'gen_block_after_cert' in params else True
        self.pack_tx_into_block = params['pack_tx_into_block'] if 'pack_tx_into_block' in params else False
        self.use_burn = params['use_burn'] if 'use_burn' in params else True

        assert_equal(type(self.greenflag), bool)
        assert_equal(type(self.green_flag_in_user_cert), bool)
        assert_equal(type(self.ben_enabled), bool)
        assert_equal(type(self.free_ben_enabled), bool)
        assert_equal(type(self.sivler_hoof), bool)
        assert_equal(type(params['accepted']), bool)
        assert_equal(type(self.revoke_root_cert), bool)
        assert_equal(type(self.revoke_user_cert), bool)
        assert_equal(type(self.refill_moneybox_accepted), bool)

        assert (params['fee_user_percent'] == 'auto' or (params['fee_user_percent'] >= 0 and params['fee_user_percent'] <= 100))
        # if reward goes to ben, ben_enabled must be True:
        assert ('ben' not in params['reward_to'] or self.ben_enabled == True)
        assert ((params['keys_count_total'] >= 1 and params['keys_count_total'] <= 15) or not self.multisig)
        assert_in(self.invalid_root_cert, [None, 1, 2, 3, 4, 5, 20, 21, 22, 23] + list(range(60,70)))
        assert_in(self.invalid_user_cert, [None, 1, 2, 3, 4, 5, 20, 21, 22, 23])
        if 'invalid_refill_moneybox' in params:
            assert (params['invalid_refill_moneybox'] in [1, 2, 3, 4, 5])
        if 'step2_enabled' in params and params['step2_enabled'] == True:
            assert_equal(params['accepted'], True)  # if step2 presents, step1 must be successful
            assert_in('step2_wait_interval', params)
            assert_in('step2_rewardamount', params)
            assert_in('step2_reward_to', params)
            assert_in('step2_accepted', params)
            # if reward goes to ben, ben_enabled must be True:
            assert ('ben' not in params['step2_reward_to'] or self.ben_enabled == True)
            assert_equal(type(params['step2_accepted']), bool)
        if 'step3_enabled' in params and params['step3_enabled'] == True:
            assert_equal(params['accepted'], True)  # if step3 presents, step1 must be successful
            assert_equal(params['step2_enabled'], True)  # if step3 presents, step2 must present too
            assert_equal(params['step2_accepted'], True)  # if step3 presents, step2 must be successful
            assert_in('step3_wait_interval', params)
            assert_in('step3_rewardamount', params)
            assert_in('step3_reward_to', params)
            assert_in('step3_accepted', params)
            # if reward goes to ben, ben_enabled must be True:
            assert ('ben' not in params['step3_reward_to'] or self.ben_enabled == True)
            assert_equal(type(params['step3_accepted']), bool)

        if 'refill_moneybox' not in params or params['refill_moneybox'] is None:
            params['refill_moneybox'] = 'random'
        if params['refill_moneybox'] == 'random':
            params['refill_moneybox'] = 'node' if random.randint(0, 1) else 'script'
        assert_in(params['refill_moneybox'], ['script', 'node'])

        if 'tx_version' not in params:
            params['tx_version'] = 'random'
        if params['tx_version'] == 'random':
            params['tx_version'] = random.randint(1,2)
        assert_in(params['tx_version'], [1,2])
        self.tx_version = params['tx_version']

        if 'spend_reward' in params:
            assert_in('spend_reward_accepted', params)
            assert_equal(type(params['spend_reward_accepted']), bool)


    def pay_to_address(self, address, amount, generate_block = True, reason = None):
        amount = ToCoins(amount)
        node0 = self.nodes[0]
        txid = node0.sendtoaddress(address, amount)
        if generate_block:
            blocks = node0.generate(1)
            self.test_node.sync_with_ping()
            block = node0.getblock(blocks[0])
            height = block['height']
            blocktime = block['time']
            assert_in(txid, block['tx']) # Ensure the transaction is accepted by the node and is included into a block
            self.log.debug('pay_to_address {} amount {}: height: {}, time: {}'.format(address, amount, block['height'], blocktime))
        else:
            # Ensure our transaction is accepted by the node and is included into mempool:
            self.test_node.sync_with_ping()
            mempool = node0.getrawmempool()
            assert_in(txid, mempool)
            height = None
            blocktime = None
        tx = node0.getrawtransaction(txid, True)
        outputindex = -1
        for i, vout in enumerate(tx['vout']):
            if vout['value'] == amount:
                outputindex = vout['n']
                assert_equal(i, vout['n'])
                break
        assert (outputindex != -1)
        self.txmap[txid] = tx
        self.log.debug('pay_to_address {} amount: {}, height: {}, time: {}, reason: {}, outpoint: {}:{}'.format(address, amount, height, blocktime, reason, txid, outputindex))
        return (COutPoint(int(txid, 16), outputindex), blocktime)

    def get_multisig_script(self, keys, keys_count_unlock):
        multisigscript = CScript([keys_count_unlock])
        for key in keys:
            multisigscript += key.get_pubkey()
        multisigscript += len(keys)
        multisigscript += CScriptOp(OP_CHECKMULTISIG)
        return multisigscript

    def pay_to_multisig_address(self, keys, amount, keys_count_unlock, generate_block = True, reason = None):
        multisigscript = self.get_multisig_script(keys, keys_count_unlock)
        address = ScriptAddress(multisigscript)
        pubkeys_hex = [bytes_to_hex_str(key.get_pubkey()) for key in keys]
        self.log.debug('pay_to_multisig_address, keys count total: {}, keys count unlock: {}, pubkeys: {}, multisigscript ({}): {}, address: {}, amount: {}, generate_block: {}'.format(
            len(keys), keys_count_unlock, pubkeys_hex, len(multisigscript), bytes_to_hex_str(multisigscript), address, amount, generate_block))
        return self.pay_to_address(address, amount, generate_block, reason)


    def create_key(self, key_name, cert_name = None, print_func = None):
        print_func = self.set_default_print_func_if_none(print_func)
        key = CECKey()
        key.set_secretbytes(open("/dev/urandom","rb").read(32))
        if not key.is_compressed():
            key.set_compressed(True)
        pubkey = key.get_pubkey()
        print_func('Details for {} in {}: pubkey ({}): {}, pubkeyhash: {}, address: {}, priv_key: {}'.
                   format(key_name, cert_name, len(pubkey), bytes_to_hex_str(pubkey), bytes_to_hex_str(reverse(hash160(pubkey))),
                          AddressFromPubkey(pubkey), bytes_to_hex_str(key.get_secret())))
        return key

    def create_other_keys(self, count, name, cert_name = None):
        other_keys = []
        for i in range(count):
            other_keys.append(self.create_key(name + '_' + str(i), cert_name))
        return other_keys

    def create_cert(self, utxo_coins, amount, parent_key, keys_count_total, keys_count_required, green_flag, has_device,
                    has_ben, silver_hoof, cert_name, user_keys_to_use=None, alt_dest_pubkeyhash=None, exp_date_offset=None,
                    minting_limit=None, daily_limit=None, free_ben_enabled=False, invalid_signature=None):
        bestblockhash = self.nodes[0].getbestblockhash()
        block_time = self.nodes[0].getblock(bestblockhash)['time'] + 1

        assert(keys_count_total > 0 or not self.multisig)
        node0 = self.nodes[0]
        parent_pubkey_bin = parent_key.get_pubkey()
        pubkeyhash = hash160(parent_pubkey_bin)

        user_keys = []
        dev_key = CECKey()
        ben_key = CECKey()
        if user_keys_to_use is None:
            for i in range(keys_count_total if self.multisig else 1):
                user_key = self.create_key('user_key_{}'.format(i), cert_name)
                user_keys.append(user_key)
        else:
            assert_equal(len(user_keys_to_use), keys_count_total if self.multisig else 1)
            user_keys = user_keys_to_use
        flags = 0
        if green_flag:
            flags |= FAST_MINTING
        if has_device:
            flags |= HAS_DEVICE_KEY
        if has_ben:
            flags |= HAS_BEN_KEY
        if exp_date_offset is not None:
            flags |= HAS_EXPIRATION_DATE
        if minting_limit is not None:
            flags |= HAS_MINTING_LIMIT
        if daily_limit is not None:
            flags |= HAS_DAILY_LIMIT
        if free_ben_enabled:
            flags |= FREE_BEN
        if silver_hoof:
            flags |= SILVER_HOOF
        if self.multisig:
            flags |= ((keys_count_total << 12) & TOTAL_PUBKEYS_COUNT_MASK)
            if keys_count_required is not None:
                assert_greater_than(keys_count_required, 0)
                flags |= ((keys_count_required << 28) & REQUIRED_PUBKEYS_COUNT_MASK)

        block1 = bytearray(struct.pack(b"<I", flags))
        for user_key in user_keys:
            user_pubkeyhash = hash160(user_key.get_pubkey())
            block1.extend(user_pubkeyhash)
        if has_device:
            dev_key = self.create_key('dev_key', cert_name)
            dev_pubkeyhash = hash160(dev_key.get_pubkey())
            block1.extend(dev_pubkeyhash)
        if has_ben:
            ben_key = self.create_key('ben_key', cert_name)
            ben_pubkeyhash = hash160(ben_key.get_pubkey())
            block1.extend(ben_pubkeyhash)
        if exp_date_offset is not None:
            block1.extend(struct.pack(b"<I", block_time + exp_date_offset))
        if minting_limit is not None:
            block1.extend(struct.pack(b"<q", minting_limit))
        if daily_limit is not None:
            block1.extend(struct.pack(b"<q", daily_limit))
        block1_hash = hash256(block1)
        # block2 = parent_key.sign(block1_hash)
        block2 = sign_compact(block1_hash, parent_key.get_secret())
        if invalid_signature is not None:
            if invalid_signature == 20:
                # (invalid sig_hash)
                block1_hashA = bytearray(block1_hash)
                random.shuffle(block1_hashA)
                block1_hashA = bytes(block1_hashA)
                block2 = sign_compact(block1_hashA, parent_key.get_secret())
                self.log.debug('invalid_signature: {}, block1_hash before: {}, block1_hash after: {}, signature: {}'.format(invalid_signature, bytes_to_hex_str(block1_hash), bytes_to_hex_str(block1_hashA), bytes_to_hex_str(block2)))
            elif invalid_signature == 21:
                # (signed with another key)
                fake_key = self.create_key('fake_key_for_invalid_signature', cert_name)
                block2 = sign_compact(block1_hash, fake_key.get_secret())
                self.log.debug('invalid_signature: {}, signature: {}'.format(invalid_signature, bytes_to_hex_str(block2)))
            elif invalid_signature == 22:
                # (corrupted signature)
                block2A = bytearray(block2)
                random.shuffle(block2A)
                self.log.debug('invalid_signature: {}, signature (block2) before: {}, signature (block2) after: {}'.format(invalid_signature, bytes_to_hex_str(block2), bytes_to_hex_str(block2A)))
                block2 = bytes(block2A)
            elif invalid_signature == 23:
                # missing signature (empty block instead of signature)
                block2 = b''
            else:
                assert (0)
        dest_pubkeyhash = alt_dest_pubkeyhash if alt_dest_pubkeyhash is not None else pubkeyhash
        scriptOutPKH = CScript([block1, block2, OP_2DROP, OP_DUP, OP_HASH160, dest_pubkeyhash, OP_EQUALVERIFY, OP_CHECKSIG])
        (burn1, burn2) = GetBurnedValue(amount)
        tx2 = CTransaction()
        tx2.nVersion = self.tx_version
        tx2.vin.append(CTxIn(utxo_coins, b"", 0xffffffff))
        tx2.vout.append(CTxOut(ToSatoshi(amount), scriptOutPKH))
        tx2.vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
        tx2.vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))

        scriptPubKey = GetP2PKHScript(pubkeyhash)
        (sig_hash, err) = SignatureHash(scriptPubKey, tx2, 0, SIGHASH_ALL)
        assert (err is None)
        signature = parent_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx2.vin[0].scriptSig = CScript([signature, parent_pubkey_bin])
        tx2.rehash()

        self.log.debug('cert {}: tx2.hash: {}, flags: {} ({}), scriptPubKey ({}): {}, block1_hash: {}, parent_pubkey: {}, parent_pubkeyhash: {}, parent_privkey: {}, sig_hash: {}, signature ({}): {}, multisig: {}, amount: {}, block_time: {}, exp_date_offset: {}, minting_limit: {}, daily_limit: {}, free_ben_enabled: {}, invalid_signature: {}'.
              format(cert_name, tx2.hash, hex(flags), flags_to_str(flags), len(scriptOutPKH), bytes_to_hex_str(scriptOutPKH),
                     bytes_to_hex_str(reverse(block1_hash)), bytes_to_hex_str(parent_key.get_pubkey()),
                     bytes_to_hex_str(reverse(hash160(parent_key.get_pubkey()))), bytes_to_hex_str(parent_key.get_secret()),
                     bytes_to_hex_str(sig_hash), len(signature), bytes_to_hex_str(signature),
                     self.multisig, amount, block_time, exp_date_offset, minting_limit,
                     daily_limit, free_ben_enabled, invalid_signature))
        tx2_full = tx2.serialize()
        self.log.debug('tx2: {}'.format(node0.decoderawtransaction(bytes_to_hex_str(tx2_full))))
        self.log.debug('tx2 hex ({}): {}'.format(len(tx2_full), bytes_to_hex_str(tx2_full)))

        if self.pack_tx_into_block:
            height = self.nodes[0].getblockcount() + 1
            block = create_block(int(bestblockhash, 16), create_coinbase(height), block_time)
            block.vtx.extend([tx2])
            block.hashMerkleRoot = block.calc_merkle_root()
            block.solve()
            block_message = msg_block(block)
            self.test_node.send_message(block_message)
            self.test_node.sync_with_ping()

            new_best_hash = node0.getbestblockhash()
            last_block = node0.getblock(new_best_hash)
            assert_equal(self.nodes[0].getblockcount(), height)
            assert_equal(last_block['time'], block_time)
            assert_equal(new_best_hash, block.hash)
            assert (bestblockhash != new_best_hash)

            # Ensure our transaction is accepted by the node and is included into a block:
            assert_in(tx2.hash, last_block['tx'])
            block_time = last_block['time']
        else:
            tx_message = msg_tx(tx2)
            tx_message_bytes = tx_message.serialize()
            self.test_node.send_message(tx_message)
            self.test_node.sync_with_ping()

            if self.test_node.reject_message is not None:
                self.log.error('got reject message: {}'.format(self.test_node.reject_message))

            # Ensure our transaction is accepted by the node and is included into mempool:
            assert_in(tx2.hash, node0.getrawmempool())
            block_time = None
            if self.gen_block_after_cert:
                hashes = node0.generate(1)
                block_time = node0.getblockheader(hashes[0])['time']

        self.txmap[tx2.hash] = tx2
        return (user_keys, dev_key, ben_key, COutPoint(tx2.sha256, 0), block_time)


    def ensure_fund_keys_created(self):
        if self.fund_police_key is None:
            self.fund_police_key = self.create_key('fund_police_key')
        if self.fund_project_key is None:
            self.fund_project_key = self.create_key('fund_project_key')

    def pay_to_fixed_key(self):
        if self.fixed_key is None:
            self.fixed_key = self.create_key('fixed_key')
            amount = Decimal('2.25')
            (utxo, _) = self.pay_to_address(AddressFromPubkey(self.fixed_key.get_pubkey()), amount, reason='pay_to_fixed_key')
            self.reward_hints['fixed'] = ('%064x' % (utxo.hash), utxo.n, amount, GetP2PKHScript(hash160(self.fixed_key.get_pubkey())))

    def emulate_fast_wait(self, time_seconds, params, timepoint_from = None, description = None):
        generate_period = 90
        max_blocks_in_wait_cycle = params['max_blocks_in_wait_cycle'] if 'max_blocks_in_wait_cycle' in params else MAX_BLOCKS_IN_WAIT_CYCLE
        while time_seconds // generate_period > max_blocks_in_wait_cycle:
            generate_period *= 2
        return self.emulate_wait(time_seconds, timepoint_from, description, generate_period)

    def emulate_wait(self, time_seconds, timepoint_from = None, description = None, generate_period = 90):
        time_seconds_orig = time_seconds
        start_wait_time_real = int(time.time())
        start_wait_time_virt = start_wait_time_real + self.virtual_cur_time_offset
        if timepoint_from is not None:
            time_seconds += (timepoint_from - start_wait_time_virt)
        blocks = time_seconds // generate_period
        self.log.debug('will wait {} seconds (before correction {} seconds), generate_period: {}, blocks: {}, start_wait_time_virt: {}, virtual_cur_time_offset: {}, timepoint_from: {}, description: {}'.
                       format(time_seconds, time_seconds_orig, generate_period, blocks, start_wait_time_real + self.virtual_cur_time_offset, self.virtual_cur_time_offset, timepoint_from, description))
        if time_seconds <= 0:
            # after correction wait time may become negative - ignore it
            assert_greater_than_or_equal(time_seconds_orig, 0)
            return
        self.nodes[0].setmocktime(start_wait_time_virt)
        self.nodes[1].setmocktime(start_wait_time_virt)
        if time_seconds > 0:
            self.nodes[0].generate(1)
        for i in range(blocks):
            step = generate_period if i > 0 else generate_period + (time_seconds % generate_period)
            self.virtual_cur_time_offset += step
            self.nodes[0].setmocktime(start_wait_time_real + self.virtual_cur_time_offset)
            self.nodes[1].setmocktime(start_wait_time_real + self.virtual_cur_time_offset)
            blockhashes = self.nodes[0].generate(1)
            self.log.debug('wait, block {} time: {}'.format(i, self.nodes[0].getblock(blockhashes[0])['time']))
        sync_chain(self.nodes)
        self.test_node.sync_with_ping()

    def get_utxo(self, address, from_conf = 6, to_conf = 9999999):
        # find utxos with the help of the second node:
        sync_chain(self.nodes)
        node1 = self.nodes[1]
        self.log.debug('will import address {}...'.format(address))
        node1.importaddress(address)
        return node1.listunspent(from_conf, to_conf, [address])

    def get_moneybox_outputs_names(self, params):
        if 'moneybox_change_dest' in params:
            return split_names(params['moneybox_change_dest'])
        return ['moneybox']

    def get_dest_scriptpubkey(self, dest_output, params, print_func = None):
        print_func = self.set_default_print_func_if_none(print_func)
        def get_lock_timepoint(name, params):
            if len(self.lock_intervals) >= 1:
                lock_interval = self.lock_intervals[0]
                self.lock_intervals = tuple(self.lock_intervals[1:])
            else:
                lock_interval = random.randint(self.lock_interval_min, self.lock_interval_max)
            timepoint = self.now + lock_interval
            print_func('set timepoint for {}: {}, lock_interval: {}, now: {}'.format(name, timepoint, lock_interval, self.now))
            return timepoint

        if dest_output == 'moneybox':
            return GetP2SHMoneyboxScript()
        elif dest_output == 'user':
            if self.multisig:
                multisig_script = self.get_multisig_script(self.user_keys, self.keys_count_used)
                return GetP2SHScript(hash160(multisig_script))
            else:
                return GetP2PKHScript(hash160(self.user_keys[0].get_pubkey()))
        elif dest_output == 'user_shuffled':
            assert_equal(self.multisig, True)
            assert_greater_than(len(self.user_keys), 1)
            keys_shuffled = [key for key in self.user_keys]
            while keys_shuffled == self.user_keys:
                random.shuffle(keys_shuffled)
            multisig_script = self.get_multisig_script(keys_shuffled, self.keys_count_used)
            return GetP2SHScript(hash160(multisig_script))
        elif dest_output == 'user_pure_multisig':
            assert_equal(self.multisig, True)
            return self.get_multisig_script(self.user_keys, self.keys_count_used)
        elif dest_output == 'ben':
            return GetP2PKHScript(hash160(self.ben_key.get_pubkey()))
        elif dest_output == 'other_p2pkh' or dest_output == 'other':
            other_key = self.create_key('other_p2pkh', print_func = print_func)
            return GetP2PKHScript(hash160(other_key.get_pubkey()))
        elif dest_output == 'other_p2sh':
            other_key = self.create_key('other_p2sh', print_func = print_func)
            return GetP2SHScript(hash160(other_key.get_pubkey()))
        elif dest_output == 'op_true':
            return CScript([OP_TRUE])
        elif dest_output == 'op_false':
            return CScript([OP_FALSE])
        elif dest_output == 'user_locked':
            if self.multisig:
                multisig_script = self.get_multisig_script(self.user_keys, self.keys_count_used)
                return GetP2SHScriptWithTimeLock(hash160(multisig_script), get_lock_timepoint(dest_output, params))
            else:
                return GetP2PKHScriptWithTimeLock(hash160(self.user_keys[0].get_pubkey()), get_lock_timepoint(dest_output, params))
        elif dest_output == 'ben_locked':
            return GetP2PKHScriptWithTimeLock(hash160(self.ben_key.get_pubkey()), get_lock_timepoint(dest_output, params))
        elif dest_output == 'other_p2pkh_locked' or dest_output == 'other_locked':
            other_key = self.create_key('other_p2pkh', print_func = print_func)
            return GetP2PKHScriptWithTimeLock(hash160(other_key.get_pubkey()), get_lock_timepoint(dest_output, params))
        elif dest_output == 'user_ab':
            self.ensure_fund_keys_created()
            return GetAbMintingMultisigScript(self.fund_police_key, self.user_keys[0], self.fund_project_key)
        elif dest_output == 'user_ab_ex2':
            self.ensure_fund_keys_created()
            return GetAbMintingMultisigScript(self.user_keys[0], self.user_keys[0], self.fund_project_key)
        elif dest_output == 'user_ab_ex3':
            self.ensure_fund_keys_created()
            return GetAbMintingMultisigScript(self.user_keys[0], self.user_keys[0], self.user_keys[0])
        elif dest_output == 'user_ab_locked':
            self.ensure_fund_keys_created()
            return GetAbMintingLockedMultisigScript(self.user_keys[0], self.fund_project_key, get_lock_timepoint(dest_output, params))
        elif dest_output == 'ben_ab':
            self.ensure_fund_keys_created()
            return GetAbMintingMultisigScript(self.fund_police_key, self.ben_key, self.fund_project_key)
        elif dest_output == 'ben_ab_locked':
            self.ensure_fund_keys_created()
            return GetAbMintingLockedMultisigScript(self.ben_key, self.fund_project_key, get_lock_timepoint(dest_output, params))
        else:
            raise AssertionError('invalid dest_output: {}'.format(dest_output))

    def appent_moneybox_outputs_to_tx(self, tx3, amount, params, print_func = None):
        print_func = self.set_default_print_func_if_none(print_func)
        moneybox_change_dest = self.get_moneybox_outputs_names(params)
        moneybox_outputs_count = len(moneybox_change_dest)
        amount_to_each = ToSatoshi(amount) // moneybox_outputs_count if moneybox_outputs_count > 0 else 0
        amount_sum = 0

        for i, dest_output in enumerate(moneybox_change_dest):
            amount_chunk = amount_to_each if i + 1 < moneybox_outputs_count else (ToSatoshi(amount) - amount_sum)
            amount_sum += amount_chunk
            tx3.vout.append(CTxOut(ToSatoshi(amount_chunk), self.get_dest_scriptpubkey(dest_output, params, print_func)))

            if dest_output == 'moneybox':
                print_func('tx3 vout[{}] moneybox: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk)))
            else:
                print_func('tx3 vout[{}] moneybox: {}, dest: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk), dest_output))


    def get_user_outputs_names(self, params):
        return split_names(self.get_param(params, 'user_outputs_dest', 'user'))


    def appent_user_outputs_to_tx(self, tx3, amount, params, print_func = None):
        print_func = self.set_default_print_func_if_none(print_func)
        user_outputs_dest = self.get_user_outputs_names(params)
        user_outputs_cnt = len(user_outputs_dest)

        if 'user_outputs_ratio' in params:
            user_outputs_ratio = params['user_outputs_ratio']
            coefficients = [int(c) for c in user_outputs_ratio.split(':')]
            assert_equal(len(coefficients), user_outputs_cnt)
            coeff_sum = sum(coefficients)
            amount_to_each = None
        else:
            amount_to_each = (ToSatoshi(amount) // user_outputs_cnt) if user_outputs_cnt else 0
        amount_sum = 0
        vout_indexes = []

        for i, dest_output in enumerate(user_outputs_dest):
            amount_to_each_now = amount_to_each if amount_to_each else (ToSatoshi(amount) * coefficients[i] // coeff_sum)
            amount_chunk = amount_to_each_now if i+1 < user_outputs_cnt else (ToSatoshi(amount) - amount_sum)
            amount_sum += amount_chunk
            tx3.vout.append(CTxOut(amount_chunk, self.get_dest_scriptpubkey(dest_output, params, print_func)))
            vout_indexes.append(len(tx3.vout) - 1)

            if dest_output == 'user':
                print_func('tx3 vout[{}] user_output: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk)))
            else:
                print_func('tx3 vout[{}] user_output: {}, dest: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk), dest_output))

        return vout_indexes


    def get_all_reward_outputs_names(self, reward_to):
        return split_names(reward_to)


    ''' Return real outputs names, excluding 'user', because reward to user doesn't create separate outputs '''
    def get_real_reward_outputs_names(self, reward_to, params):
        names = self.get_all_reward_outputs_names(reward_to)
        join_user_reward_to_user_outputs = params['join_user_reward_to_user_outputs'] if 'join_user_reward_to_user_outputs' in params else True
        return [x for x in names if x != 'user'] if join_user_reward_to_user_outputs else names


    def appent_reward_outputs_to_tx(self, tx3, amount, reward_to, user_output_index, params, print_func = None):
        print_func = self.set_default_print_func_if_none(print_func)
        reward_outputs_dest = self.get_all_reward_outputs_names(reward_to)
        reward_outputs_cnt = len(reward_outputs_dest)
        amount_to_each = ToSatoshi(amount) // reward_outputs_cnt if reward_outputs_cnt > 0 else 0
        amount_sum = 0
        reward_add_to_user_output = 0
        join_user_reward_to_user_outputs = params['join_user_reward_to_user_outputs'] if 'join_user_reward_to_user_outputs' in params else True

        for i, dest_output in enumerate(reward_outputs_dest):
            amount_chunk = amount_to_each if i+1 < reward_outputs_cnt else (ToSatoshi(amount) - amount_sum)
            amount_sum += amount_chunk

            if (dest_output == 'user' or dest_output == 'user_locked') and join_user_reward_to_user_outputs:
                # add amount to existing user output, don't append output to transaction:
                reward_add_to_user_output += amount_chunk
                if user_output_index != -1:
                    tx3.vout[user_output_index].nValue += ToSatoshi(amount_chunk)
                    print_func('adding reward amount {} to existing user_output {}, now {}'.format(
                        ToCoins(amount_chunk), user_output_index, ToCoins(tx3.vout[user_output_index].nValue)))
            else:
                tx3.vout.append(CTxOut(ToSatoshi(amount_chunk), self.get_dest_scriptpubkey(dest_output, params, print_func)))
                print_func('tx3 vout[{}] reward_output: {}, reward_to: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk), dest_output))
                if dest_output not in self.reward_hints:
                    self.reward_hints[dest_output] = []
                self.reward_hints[dest_output].append(('', len(tx3.vout) - 1, ToCoins(amount_chunk), tx3.vout[-1].scriptPubKey))


    def get_bytes_in_tx_inputs(self, tx, start_index, count):
        bytes_cnt = 0
        for i in range(start_index, start_index + count):
            bytes_cnt += len(tx.vin[i].serialize())
        return bytes_cnt


    def moneybox_inputs_from_cache(self):
        # json doesn't support Decimal: convert them to strings when saving, and back to Decimals when loading
        minting_dir = os.path.join(self.options.cachedir, 'minting')
        moneybox_inputs_json = os.path.join(minting_dir, 'moneybox_inputs.json')
        moneybox_inputs_lock = os.path.join(minting_dir, 'moneybox_inputs.lock')

        while os.path.isfile(moneybox_inputs_lock):
            self.log.debug('waiting for {}...'.format(moneybox_inputs_lock))
            time.sleep(1)

        if os.path.isfile(moneybox_inputs_json):
            self.log.debug('loading moneybox_inputs from {}...'.format(moneybox_inputs_json))
            moneybox_inputs = json.load(open(moneybox_inputs_json))
            for inp in moneybox_inputs:
                inp['amount'] = Decimal(inp['amount'])
        else:
            os.makedirs(minting_dir, exist_ok=True)
            with FileLock(moneybox_inputs_lock):
                self.log.debug('will get moneybox_inputs...')
                moneybox_inputs = self.get_utxo(MoneyboxP2SHAddress())
                moneybox_inputs_copy = copy.deepcopy(moneybox_inputs)
                for inp in moneybox_inputs_copy:
                    inp['amount'] = str(inp['amount'])
                with open(moneybox_inputs_json, 'w') as file:
                    file.write(json.dumps(moneybox_inputs_copy, indent=2))
                self.log.debug('wrote moneybox_inputs to {}'.format(moneybox_inputs_json))

        assert_equal(len(moneybox_inputs), 1000)
        return moneybox_inputs


    def get_param(self, params, name, default_val = None):
        assert_in(self.step, [1,2,3])
        if self.step != 1:
            name = 'step{}_{}'.format(self.step, name)
        if default_val is None:
            assert_in(name, params)
            return params[name]
        elif name in params:
            return params[name]
        else:
            return default_val


    def mint(self, user_inputs, utxo_cert_root, utxo_cert_ca3, params, more_moneybox_inputs=[], take_moneybox_inputs_from_cache = False):
        node0 = self.nodes[0]
        self.now = node0.getblockheader(node0.getbestblockhash())['time']
        rewardamount = self.get_param(params, 'rewardamount')
        reward_to = self.get_param(params, 'reward_to')
        accepted = self.get_param(params, 'accepted')
        skip_checks = False
        if self.multisig:
            p2sh_like_dests = set(['user', 'user_shuffled', 'moneybox', 'other_p2sh'])
            p2pkh_like_dests = set(['ben', 'other', 'other_p2pkh'])
        else:
            p2sh_like_dests = set(['moneybox', 'other_p2sh'])
            p2pkh_like_dests = set(['user', 'user_shuffled', 'ben', 'other', 'other_p2pkh'])
        user_type_dests = p2sh_like_dests if self.multisig else p2pkh_like_dests
        moneybox_outputs_names = self.get_moneybox_outputs_names(params)
        user_outputs_names = self.get_user_outputs_names(params)
        rewadr_real_output_names = self.get_real_reward_outputs_names(reward_to, params)
        nLockTime = 0
        spend_inputs_with_proj_key = ()
        if self.step == 2 and 'step2_spend_inputs_with_proj_key' in params:
            spend_inputs_with_proj_key = params['step2_spend_inputs_with_proj_key']
            assert_equal(type(spend_inputs_with_proj_key), tuple)
        if len(moneybox_outputs_names) == 0 or set.union(set(moneybox_outputs_names), p2sh_like_dests) != p2sh_like_dests:
            # if no moneybox outputs (first condition) or at least one output is not p2sh-like (second condition),
            # skip checks, this is non-standard transaction:
            skip_checks = True
            self.log.debug('skip_checks == True (case 1)')
        if len(user_outputs_names) == 0 or set.union(set(user_outputs_names), user_type_dests) != user_type_dests:
            # if no user outputs (first condition) or at least one output is not user_type_dests-like (second condition),
            # skip checks, this is non-standard transaction:
            skip_checks = True
            self.log.debug('skip_checks == True (case 2)')
        if set.union(set(rewadr_real_output_names), p2pkh_like_dests) != p2pkh_like_dests:
            # if at least one reward output is not p2pkh-like, skip checks, because we consider all outputs are p2pkh-like:
            skip_checks = True
            self.log.debug('skip_checks == True (case 3)')
        if rewardamount == 0:
            # no reward outputs:
            skip_checks = True
            self.log.debug('skip_checks == True (case 4)')
        if self.user_keys_m is None:
            # In regular workflow user_keys_m and user_keys are the same, but in some special cases they may be different.
            self.user_keys_m = self.user_keys

        if self.locked_outputs:
            # Locked user outputs are in tx on previous step - set nLockTime field:
            nLockTime = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())['mediantime'] - 1
            self.log.debug('At least 1 locked user output in prev tx, set nLockTime to {}'.format(nLockTime))

        fee_total_given = params['fee_total']
        fee_user_percent_orig = 0 \
            if params['fee_user_percent'] == 'auto' and (reward_to == 'user' or reward_to == 'ben') \
            else params['fee_user_percent']
        multisig_script = self.get_multisig_script(self.user_keys, self.keys_count_used)
        if take_moneybox_inputs_from_cache:
            moneybox_inputs = self.moneybox_inputs_from_cache()
        else:
            moneybox_inputs = self.get_utxo(MoneyboxP2SHAddress())
        # For more complexity sort them by amount: lets first be with small amount:
        moneybox_inputs = sorted(moneybox_inputs, key=lambda k: k['amount'])
        #assert_greater_than(len(user_inputs), 0)  # in special tests transaction may be without user inputs
        assert_greater_than(len(moneybox_inputs) + len(more_moneybox_inputs), 0)
        attemps = 0
        total_delta_user = 0        # accumulated difference between real and guessed sizes of tx user bytes (for statistics analysis)
        total_delta_moneybox = 0    # accumulated difference between real and guessed sizes of tx moneybox bytes (for statistics analysis)
        invalid_signature = params['invalid_signature'] if 'invalid_signature' in params else None
        alt_behavior = params['alt_behavior'] if 'alt_behavior' in params else None
        extra_moneybox_inputs_count = params['extra_moneybox_inputs_count'] if 'extra_moneybox_inputs_count' in params else 0

        try:
            moneybox_bytes_real_prev = None
            user_bytes_real_prev = None
            more_inputs_count_on_prev_step = None
            while True:
                # will use print_to_buffer() instead of self.log.debug() function inside this loop,
                # because we need to print only successful (last) attempt of composing transaction:
                self.clear_print_buffer()
                tx3 = CTransaction()
                tx3.nVersion = self.tx_version
                tx3.nLockTime = nLockTime
                user_amount = Decimal('0')
                reward_to_ben = ToCoins(rewardamount)
                reward_change = Decimal('0')
                reward_taken = Decimal('0')
                moneybox_inputs_enough = False
                self.lock_intervals = params['lock_intervals'] if 'lock_intervals' in params else ()

                for user_input in user_inputs:
                    user_input_hash_hex = hashToHex(user_input.hash)
                    assert_in(user_input_hash_hex, self.txmap)
                    tx_prev = self.txmap[user_input_hash_hex]
                    assert_equal(tx_prev['vout'][user_input.n]['n'], user_input.n)
                    amount = tx_prev['vout'][user_input.n]['value']
                    user_amount += amount
                    print_to_buffer('tx3 vin[{}] user_input: {}'.format(len(tx3.vin), amount))
                    seq = 0xfffffffe if self.locked_outputs else 0xffffffff
                    if self.multisig:
                        tx3.vin.append(CTxIn(user_input, multisig_script, seq))
                    else:
                        scriptPubKey = tx_prev['vout'][user_input.n]['scriptPubKey']['hex']
                        tx3.vin.append(CTxIn(user_input, hex_str_to_bytes(scriptPubKey), seq))

                for moneybox_input in moneybox_inputs + more_moneybox_inputs:
                    print_to_buffer('tx3 vin[{}] moneybox_input: {}'.format(len(tx3.vin), moneybox_input['amount']))
                    seq = 0xfffffffe if self.locked_outputs else 0xffffffff
                    tx3.vin.append(CTxIn(COutPoint(int(moneybox_input['txid'], 16), moneybox_input['vout']), hex_str_to_bytes(moneybox_input['scriptPubKey']), seq))
                    reward_taken += moneybox_input['amount']
                    if reward_taken >= reward_to_ben:
                        if extra_moneybox_inputs_count > 0:
                            extra_moneybox_inputs_count -= 1
                        else:
                            reward_change = reward_taken - reward_to_ben
                            moneybox_inputs_enough = True
                            break

                if not moneybox_inputs_enough:
                    moneybox_sum = sum(elem['amount'] for elem in moneybox_inputs)
                    more_moneybox_sum = sum(elem['amount'] for elem in more_moneybox_inputs)
                    print_to_buffer('moneybox_inputs: {}'.format(moneybox_inputs))
                    print_to_buffer('more_moneybox_inputs: {}'.format(more_moneybox_inputs))
                    print_to_buffer('Alarm! Not enough moneybox money! moneybox_inputs: {}, moneybox_sum: {}, more_moneybox_inputs: {}, more_moneybox_sum: {}, reward_to_ben: {}, reward_taken: {}, height: {}'.format(
                        len(moneybox_inputs), moneybox_sum, len(more_moneybox_inputs), more_moneybox_sum, reward_to_ben, reward_taken, node0.getblockcount()))
                    assert_equal(moneybox_inputs_enough, True)

                relayfee = node0.getnetworkinfo()['relayfee']  #  (numeric) minimum relay fee for non-free transactions in PLCU/kB
                HASH160_SIZE = 20
                P2PKH_OUTPUT_BYTES = (
                        8 +   # nValue
                        1 +   # scriptPubkeyLen
                        HASH160_SIZE + 5
                )
                P2SH_OUTPUT_BYTES = (
                        8 +   # nValue
                        1 +   # scriptPubkeyLen
                        HASH160_SIZE + 3
                )
                COMMON_BYTES = (
                        4 +                                 # tx version
                        getVarIntLen(len(tx3.vin)) +        # inputs count (VarInt)
                        1 +                                 # outputs count (VarInt)
                        4 +                                 # nLockTime
                        (4 if self.tx_version == 3 else 0)  # nActiveTime
                )

                user_output_bytes = P2SH_OUTPUT_BYTES if self.multisig else P2PKH_OUTPUT_BYTES
                user_inputs_lens_sum = user_bytes_real_prev if user_bytes_real_prev is not None else 0
                moneybox_inputs_lens_sum = moneybox_bytes_real_prev if moneybox_bytes_real_prev is not None else 0

                bytes_user_part = user_inputs_lens_sum + \
                                  len(self.get_user_outputs_names(params)) * user_output_bytes + \
                                  len(self.get_real_reward_outputs_names(reward_to, params)) * P2PKH_OUTPUT_BYTES
                bytes_moneybox_part = moneybox_inputs_lens_sum + \
                                      len(self.get_moneybox_outputs_names(params)) * P2SH_OUTPUT_BYTES

                tx_size = bytes_user_part + bytes_moneybox_part + COMMON_BYTES
                self.log.debug(f'user_output_bytes: {user_output_bytes}, user_inputs_lens_sum: {user_inputs_lens_sum}, moneybox_inputs_lens_sum: {moneybox_inputs_lens_sum}, ' +
                               f'bytes_user_part: {bytes_user_part}, bytes_moneybox_part: {bytes_moneybox_part}, COMMON_BYTES: {COMMON_BYTES}')
                # will take (relayfee * 5)
                total_fee_calculated = Decimal(tx_size) * relayfee * 5 / Decimal(1000)
                if fee_user_percent_orig == 'auto':
                    # We decided to consider COMMON_BYTES as user part of transaction:
                    fee_user_percent = Decimal(bytes_user_part + COMMON_BYTES) / Decimal(tx_size)
                else:
                    fee_user_percent = Decimal(fee_user_percent_orig) / 100
                assert(fee_user_percent >= 0 and fee_user_percent <= 1)
                total_fee = fee_total_given if fee_total_given != 'auto' else total_fee_calculated
                fee_user = satoshi_round(total_fee * fee_user_percent)
                fee_moneybox = satoshi_round(total_fee * (1 - fee_user_percent))
                print_to_buffer('mint: fee calculation: relayfee: {}, bytes_user_part: {}, bytes_moneybox_part: {}, total_fee_calculated: {}, total_fee: {}, fee_user_percent: {}'.
                      format(relayfee, bytes_user_part, bytes_moneybox_part, total_fee_calculated, total_fee, fee_user_percent))

                # append user_outputs to tx:
                user_outputs_indexes = self.appent_user_outputs_to_tx(tx3, user_amount, params, print_to_buffer)
                user_output_index = -1 if len(user_outputs_indexes) == 0 else user_outputs_indexes[-1]

                # append reward_outputs to tx:
                reward_payed1 = reward_to_ben - fee_user
                (burn1, burn2, reward_payed2) = BurnedAndChangeAmount(reward_payed1) if reward_payed1 > 0 and self.use_burn else (0, 0, reward_payed1)
                burn = burn1 + burn2
                if len(self.get_real_reward_outputs_names(reward_to, params)) > 0:
                    # if reward is payed to separate output(s), must be (reward > fee_user)
                    assert_greater_than_or_equal(reward_to_ben, fee_user)
                    print_to_buffer('reward_payed: {}, reward_to_ben: {}, fee_user: {}, burn: {}'.format(ToCoins(reward_payed2), reward_to_ben, ToCoins(fee_user), burn))
                if reward_payed2 > 0:
                    self.appent_reward_outputs_to_tx(tx3, reward_payed2, reward_to, user_output_index, params, print_to_buffer)
                if burn1 > 0:
                    tx3.vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
                    print_to_buffer('tx3 vout[{}] burn1_output: {}'.format(len(tx3.vout) - 1, burn1))
                if burn2 > 0:
                    tx3.vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
                    print_to_buffer('tx3 vout[{}] burn2_output: {}'.format(len(tx3.vout) - 1, burn2))


                # append moneybox_outputs to tx:
                if fee_moneybox > reward_change:
                    # When we take moneybox inputs, at that point we don't know fee amount,
                    # so we take them for amount without fee (approximately).
                    # At this point (here) we caught the case when selected moneybox inputs are not enough:
                    if more_inputs_count_on_prev_step is not None:
                        more_inputs_count_on_prev_step += 1
                    else:
                        more_inputs_count_on_prev_step = 1
                    more_inputs_count = more_inputs_count_on_prev_step
                    extra_moneybox_inputs_count += more_inputs_count
                    print_to_buffer('need more moneybox inputs, will continue, fee_moneybox: {}, reward_change: {}, reward_taken: {}, more_inputs_count: {}'.format(
                        fee_moneybox, reward_change, reward_taken, more_inputs_count))
                    continue
                reward_change_orig = reward_change
                reward_change -= fee_moneybox
                drop_moneybox_dust_change = params['drop_moneybox_dust_change'] if 'drop_moneybox_dust_change' in params else True
                if reward_change > ToCoins(DUST_OUTPUT_THRESHOLD) or (reward_change > 0 and not drop_moneybox_dust_change):
                    print_to_buffer('moneybox change (reward_change_orig - fee_moneybox): {}, reward_change_orig: {}, fee_moneybox: {}'.
                          format(ToCoins(reward_change), reward_change_orig, ToCoins(fee_moneybox)))
                    self.appent_moneybox_outputs_to_tx(tx3, reward_change, params, print_to_buffer)
                else:
                    print_to_buffer('skipping moneybox output (too small reward_change: {})'.format(reward_change))
                    reward_change = 0
                    skip_checks = True
                if 'zero_change_to_moneybox' in params:
                    for _ in range(params['zero_change_to_moneybox']):
                        self.appent_moneybox_outputs_to_tx(tx3, 0, params, print_to_buffer)
                    skip_checks = True

                total_fee_real = ToSatoshi(user_amount + reward_taken)
                for vout in tx3.vout:
                    assert_greater_than(total_fee_real, ToSatoshi(vout.nValue))
                    total_fee_real -= ToSatoshi(vout.nValue)
                print_to_buffer('mint, total_fee_real (after correction): {}'.format(ToCoins(total_fee_real)))
                if not skip_checks:
                    assert_greater_than_or_equal(1, abs(total_fee_real - ToSatoshi(total_fee)))   # assumed fee and real fee may differ on 1 satoshi due to fractional number truncation

                def select_keys(keys, count, indexes = None):
                    assert_greater_than_or_equal(len(keys), count)
                    if indexes is None:
                        indexes = []
                        while len(indexes) < count:
                            next = random.randint(0, len(keys) - 1)
                            if next not in indexes:
                                indexes.append(next)
                        indexes.sort()
                    else:
                        assert_equal(len(indexes), count)
                    ret_keys = []
                    for i in indexes:
                        ret_keys.append(keys[i])
                    return (ret_keys, indexes)

                (used_user_keys, indexes) = select_keys(self.user_keys, self.keys_count_used if self.multisig else 1)
                (used_user_keys_m, _) = select_keys(self.user_keys_m, self.keys_count_used if self.multisig else 1, indexes)
                print_to_buffer('indexes for used_keys ({}): {}'.format(len(indexes), indexes))

                if invalid_signature is not None:
                    print_to_buffer('invalid_signature scenario: {}'.format(invalid_signature))

                if alt_behavior == 10:
                    # different user keys are used to sign user inputs and moneybox inputs (another M of N keys)
                    assert_equal(self.multisig, True)
                    assert_greater_than(len(self.user_keys), self.keys_count_used)
                    indexes_orig = copy.deepcopy(indexes)
                    while set(indexes) == set(indexes_orig):
                        (_, indexes) = select_keys(self.user_keys, self.keys_count_used)
                    (used_user_keys_m, _) = select_keys(self.user_keys_m, self.keys_count_used, indexes)
                    print_to_buffer('alt_behavior scenario: {}, new indexes ({}): {}'.format(alt_behavior, len(indexes), indexes))
                elif alt_behavior == 11:
                    # different key order is used to sign user inputs and moneybox inputs (the same user keys, but in wrong order)
                    assert_equal(self.multisig, True)
                    indexes_orig = copy.deepcopy(indexes)
                    while indexes == indexes_orig:
                        random.shuffle(indexes)
                    (used_user_keys_m, _) = select_keys(self.user_keys_m, self.keys_count_used, indexes)
                    print_to_buffer('alt_behavior scenario: {}, shuffled indexes ({}): {}'.format(alt_behavior, len(indexes), indexes))
                if invalid_signature == 111 and self.keys_count_used >= 2:
                    assert_equal(self.multisig, True)
                    assert_greater_than(len(used_user_keys), 1)
                    used_user_keys[1] = used_user_keys[0]
                if invalid_signature == 112:
                    assert_equal(self.multisig, True)
                    assert_greater_than(len(used_user_keys), 1)
                    used_user_keys = [used_user_keys[0]] * self.keys_count_used
                if invalid_signature == 211 and self.keys_count_used >= 2:
                    assert_equal(self.multisig, True)
                    assert_greater_than(len(used_user_keys_m), 1)
                    used_user_keys_m[1] = used_user_keys_m[0]
                if invalid_signature == 212:
                    assert_equal(self.multisig, True)
                    assert_greater_than(len(used_user_keys_m), 1)
                    used_user_keys_m = [used_user_keys_m[0]] * self.keys_count_used

                for i in range(len(user_inputs)):
                    (sig_hash, err) = SignatureHash(CScript(tx3.vin[i].scriptSig), tx3, i, SIGHASH_ALL)
                    assert (err is None)
                    if invalid_signature == 101:
                        sig_hash = shuffle_data(sig_hash, 'replace sig_hash in user_input {}'.format(i), print_to_buffer)
                    if not self.multisig:
                        user_key = self.user_keys[0]
                        signature = user_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                        if i in spend_inputs_with_proj_key:
                            signature_proj = self.fund_project_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                            tx3.vin[i].scriptSig = CScript([OP_0, signature, signature_proj, OP_2, user_key.get_pubkey(), self.fund_project_key.get_pubkey()])
                            print_to_buffer('mint, user input {}, sig_hash ({}): {}, signature_user ({}): {}, signature_proj: {}, scriptSig ({}): {}'.format(
                                i, len(sig_hash), bytes_to_hex_str(reverse(sig_hash)),
                                len(signature), bytes_to_hex_str(signature), bytes_to_hex_str(signature_proj),
                                len(tx3.vin[i].scriptSig), bytes_to_hex_str(tx3.vin[i].scriptSig)))
                        else:
                            if invalid_signature == 102:
                                temp_key = self.create_key('temp_key_{}_for_invalid_signature'.format(i), None, print_to_buffer)
                                signature = temp_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                            elif invalid_signature == 110:
                                signature = shuffle_data(signature[0:-1], 'in user_input {}'.format(i), print_to_buffer) + bytes(bytearray([SIGHASH_ALL]))
                            if invalid_signature == 100:
                                tx3.vin[i].scriptSig = CScript([user_key.get_pubkey()])
                            else: # regular workflow
                                tx3.vin[i].scriptSig = CScript([signature, user_key.get_pubkey()])
                            print_to_buffer('mint, user input {}, sig_hash ({}): {}, signature ({}): {}, scriptSig ({}): {}'.format(
                                i, len(sig_hash), bytes_to_hex_str(reverse(sig_hash)),
                                len(signature), bytes_to_hex_str(signature),
                                len(tx3.vin[i].scriptSig), bytes_to_hex_str(tx3.vin[i].scriptSig)))
                    else:
                        scriptSig = CScript([OP_0])
                        for user_key in used_user_keys:
                            signature = user_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                            if invalid_signature == 102:
                                temp_key = self.create_key('temp_key_{}_for_invalid_signature'.format(i), None, print_to_buffer)
                                signature = temp_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                            elif invalid_signature == 110:
                                signature = shuffle_data(signature[0:-1], 'in user_input {}'.format(i), print_to_buffer) + bytes(bytearray([SIGHASH_ALL]))
                            if invalid_signature != 100:
                                scriptSig += signature
                            print_to_buffer('mint, user input {}, pubkey: {}, signature ({}): {}'.format(i, bytes_to_hex_str(user_key.get_pubkey()), len(signature), bytes_to_hex_str(signature)))
                        scriptSig += multisig_script
                        tx3.vin[i].scriptSig = scriptSig
                        print_to_buffer('mint, user input {}, sig_hash ({}): {}, scriptSig ({}): {}'.format(
                            i, len(sig_hash), bytes_to_hex_str(reverse(sig_hash)), len(scriptSig), bytes_to_hex_str(scriptSig)))
                for i in range(len(user_inputs), len(tx3.vin)):
                    # There are no common rules of composing signature for p2sh transaction inputs,
                    # we made agreement to replace scriptSig with inner script (CScript(OP_CHECKREWARD)), not
                    # with the public key script of the referenced transaction output
                    # (excluding all occurences of OP CODESEPARATOR in it), as for p2pkh transactions:
                    scriptSig = CScript([OP_CHECKREWARD])
                    (sig_hash, err) = SignatureHash(scriptSig, tx3, i, SIGHASH_ALL)
                    assert (err is None)
                    if invalid_signature == 201:
                        sig_hash = shuffle_data(sig_hash, 'replace sig_hash in moneybox_input {}'.format(i), print_to_buffer)
                    signatures_and_keys = []
                    for user_key in used_user_keys_m:
                        signature = user_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                        if invalid_signature == 202 or invalid_signature == 203:
                            temp_key = self.create_key('temp_key_{}_for_invalid_signature'.format(i), None, print_to_buffer)
                            signature = temp_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                            if invalid_signature == 203:
                                user_key = temp_key
                        elif invalid_signature == 204:
                            assert_equal(self.multisig, True)
                            assert_greater_than(len(used_user_keys_m), 1)
                            index = used_user_keys_m.index(user_key)
                            next_index = index + 1 if index + 1 < len(used_user_keys_m) else 0
                            user_key = used_user_keys_m[next_index]
                        elif invalid_signature == 210:
                            signature = shuffle_data(signature[0:-1], 'in moneybox_input {}'.format(i), print_to_buffer) + bytes(bytearray([SIGHASH_ALL]))
                        if invalid_signature != 200:
                            signatures_and_keys.append(signature)
                            signatures_and_keys.append(user_key.get_pubkey())
                    tx3.vin[i].scriptSig = CScript(signatures_and_keys +
                                                   [ ser_uint256(utxo_cert_root.hash), utxo_cert_root.n,
                                                     ser_uint256(utxo_cert_ca3.hash), utxo_cert_ca3.n,
                                                     CScript([OP_CHECKREWARD])])
                    signatures_and_keys_hex = [bytes_to_hex_str(item) for item in signatures_and_keys]
                    print_to_buffer('mint, moneybox input {}, sig_hash ({}): {}, keys_count_used: {}, signatures_and_keys: {}, scriptSig ({}): {}'.format(
                        i, len(sig_hash), bytes_to_hex_str(reverse(sig_hash)),
                        self.keys_count_used, signatures_and_keys_hex,
                        len(tx3.vin[i].scriptSig), bytes_to_hex_str(tx3.vin[i].scriptSig)))

                user_bytes_real = self.get_bytes_in_tx_inputs(tx3, 0, len(user_inputs))
                moneybox_bytes_real = self.get_bytes_in_tx_inputs(tx3, len(user_inputs), len(tx3.vin) - len(user_inputs))
                if user_bytes_real == user_inputs_lens_sum and moneybox_bytes_real == moneybox_inputs_lens_sum:
                    self.log.debug('Guessed signature sizes, user_bytes: {}, moneybox_bytes: {}'.format(user_bytes_real, moneybox_bytes_real))
                    skip_checks = True
                    break
                if fee_user_percent_orig != 'auto' and fee_total_given != 'auto':
                    self.log.debug('Skipped guessing signature sizes: fee_user_percent_orig={}, fee_total_given={}'.format(fee_user_percent_orig, fee_total_given))
                    skip_checks = True
                    break
                if fee_user_percent_orig != 'auto' and attemps == 1:
                    self.log.debug('Skipped guessing signature sizes: fee_user_percent_orig={}'.format(fee_user_percent_orig))
                    skip_checks = True
                    break
                if attemps > 0:
                    total_delta_user += (user_bytes_real - user_inputs_lens_sum)
                    total_delta_moneybox += (moneybox_bytes_real - moneybox_inputs_lens_sum)
                attemps += 1
                self.log.debug('Didn\'t guess signature sizes, attemps: {}, user_bytes_real: {}, user_bytes_guessed: {}, mb_bytes_real: {}, mb_bytes_guessed: {}, total_delta_user: {}, total_delta_mb: {}'.
                               format(attemps, user_bytes_real, user_inputs_lens_sum, moneybox_bytes_real, moneybox_inputs_lens_sum, total_delta_user, total_delta_moneybox))
                assert_greater_than(GUESS_SIGSIZES_MAX_ATTEMPTS, attemps) # if we didn't guess in GUESS_SIGSIZES_MAX_ATTEMPTS attempts, something goes wrong
                moneybox_bytes_real_prev = moneybox_bytes_real
                user_bytes_real_prev = user_bytes_real
                # restore extra_moneybox_inputs_count to default:
                extra_moneybox_inputs_count = params['extra_moneybox_inputs_count'] if 'extra_moneybox_inputs_count' in params else 0
                more_inputs_count_on_prev_step = None
        finally:
            self.apply_print_buffer()

        # Store information about locked_outputs to be used on the next step:
        self.locked_outputs = any(('locked' in fragment) for fragment in user_outputs_names)

        tx3.rehash()
        self.log.debug('tx3.hash: {}, multisig_script ({}): {}'.format(tx3.hash, len(multisig_script), bytes_to_hex_str(multisig_script)))

        # Update reward_hints, add tx3.hash there:
        for reward_recip in self.reward_hints:
            for i in range(len(self.reward_hints[reward_recip])):
                p = self.reward_hints[reward_recip][i]
                self.reward_hints[reward_recip][i] = (tx3.hash, p[1], p[2], p[3])

        tx_message = msg_tx(tx3)
        tx_message_bytes = tx_message.serialize()

        tx_real_size = len(tx_message_bytes)
        self.log.debug('tx3 hex ({}): {}'.format(tx_real_size, bytes_to_hex_str(tx_message_bytes)))
        if not skip_checks:
            assert_equal(tx_real_size, tx_size)

        self.test_node.send_message(tx_message)
        self.test_node.sync_with_ping()

        if self.test_node.reject_message is not None:
            self.log.info('got reject message: {}'.format(self.test_node.reject_message))

        # Ensure our transaction is accepted by the node and is included into mempool:
        mempool = node0.getrawmempool()
        assert_equal(tx3.hash in mempool, accepted)

        if accepted:
            self.txmap[tx3.hash] = node0.getrawtransaction(tx3.hash, True)
        else:
            self.check_error(self.test_node.reject_message, params)
            self.test_node.reject_message = None

            # Try to create a block with a bad tx, and ensure the node will not accept it too:
            bestblockhash = self.nodes[0].getbestblockhash()
            block_time = self.nodes[0].getblock(bestblockhash)['time'] + 1
            height = self.nodes[0].getblockcount() + 1
            block = create_block(int(bestblockhash, 16), create_coinbase(height), block_time)
            block.vtx.extend([tx3])
            block.hashMerkleRoot = block.calc_merkle_root()
            block.solve()
            block_message = msg_block(block)
            self.log.debug('Sending block {}: {}'.format(block.hash, bytes_to_hex_str(block_message.serialize())))
            self.test_node.send_message(block_message)
            self.test_node.sync_with_ping()
            assert_equal(bestblockhash, self.nodes[0].getbestblockhash())

        return (tx3.hash, user_outputs_indexes, ToSatoshi(reward_taken - reward_change), ToSatoshi(reward_payed2))


    def check_error(self, reject_message, params):
        reject_code = reject_message.code
        reject_reason = reject_message.reason.decode('ascii')
        error = params['error'] if 'error' in params else None
        if error is not None and error[0] is not None:
            assert_equal(reject_code, error[0])
        if error is not None and error[1] is not None:
            if isinstance(error[1], list):
                errors_list = error[1]
                found = False
                for errmsg in errors_list:
                    if reject_reason.startswith(errmsg):
                        found = True
                        break
                if not found:
                    self.log.error('Received error message "{}" does not match any of the given messages ({}): {}'.format(reject_reason, len(errors_list), errors_list))
                assert_equal(found, True)
            else:
                assert_startswith(reject_reason, error[1])


    def refill_moneybox(self, amount, params, parent_hash = None, parent_block = None, skip_transactions = []):
        active = (params['refill_moneybox'] == 'script')
        invalid_refill_moneybox = params['invalid_refill_moneybox'] if 'invalid_refill_moneybox' in params else None
        refill_moneybox_dest_list = split_names(params['refill_moneybox_dest']) if 'refill_moneybox_dest' in params else None
        self.log.debug('will refill_moneybox, amount: {}, active: {}, refill_moneybox_accepted: {}'.format(amount, active, self.refill_moneybox_accepted))
        if invalid_refill_moneybox is not None:
            self.log.debug('invalid_refill_moneybox: {}'.format(invalid_refill_moneybox))
        if refill_moneybox_dest_list is not None:
            assert_equal(len(refill_moneybox_dest_list), 1) # only one destination is supported
            self.log.debug('refill_moneybox_dest_list ({}): {}'.format(len(refill_moneybox_dest_list), refill_moneybox_dest_list))
        node0 = self.nodes[0]
        if active:
            # We compose a new block and refill money-box, and then ensure the node accepts this block:
            self.test_node.sync_with_ping()
            if parent_hash is None:
                parent_hash = node0.getbestblockhash()
            if parent_block is None:
                parent_block = node0.getblock(parent_hash)
            self.log.debug('parent_block: {}'.format(parent_block))
            assert_equal(parent_hash, parent_block['hash'])
            block = CBlock()
            block.nVersion = parent_block['version']
            block.hashPrevBlock = int(parent_hash, 16)
            block.nTime = parent_block['time'] + 1
            block.nBits = int(parent_block['bits'], 16)
            height = parent_block['height'] + 1
            if invalid_refill_moneybox is None and refill_moneybox_dest_list is None:
                # regular workflow:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount))
            elif invalid_refill_moneybox == 1:
                coinbase = create_coinbase(height, None, 0, 0)
            elif invalid_refill_moneybox == 2:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount) - 1)
            elif invalid_refill_moneybox == 3:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount) + 1)
            elif invalid_refill_moneybox == 4:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount), granularity = get_moneybox_granularity(height) // 2)
            elif invalid_refill_moneybox == 5:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount), granularity = get_moneybox_granularity(height) * 2)
            elif len(refill_moneybox_dest_list) == 1:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount),
                                           moneyboxscript = self.get_dest_scriptpubkey(refill_moneybox_dest_list[0], params))
            else:
                assert (0)
            block.vtx.append(coinbase)
            mempool = node0.getrawmempool()
            for txid in mempool:
                if txid not in skip_transactions:
                    tx = FromHex(CTransaction(), node0.getrawtransaction(txid))
                    block.vtx.append(tx)
                    self.log.debug('tx from mempool {}: added to block'.format(txid))
                else:
                    self.log.debug('tx from mempool {}: skipped'.format(txid))
            block.hashMerkleRoot = block.calc_merkle_root()
            block.nNonce = random.randint(0,0xffff)
            block.solve()
            self.test_node.send_and_ping(msg_block(block))
            self.log.debug('bestblockhash: {}, block.hash: {}, refill_moneybox_accepted: {}'.format(node0.getbestblockhash(), block.hash, self.refill_moneybox_accepted))
            assert_equal(int(node0.getbestblockhash(), 16) == block.sha256, self.refill_moneybox_accepted)
            return block.hash
        else:
            # We tell the node to generate a new block, and then ensure that money-box is refilled with expected amount:
            assert_equal(len(skip_transactions), 0) # if we want to skip transactions, we must generate a new block ourselves, not by node
            node0.generate(1)
            self.test_node.sync_with_ping()
            best_hash = node0.getbestblockhash()
            last_block = node0.getblock(best_hash)
            amount_got = Decimal(0)
            txid0 = last_block['tx'][0]
            txraw0 = node0.getrawtransaction(txid0)
            tx0 = node0.decoderawtransaction(txraw0)
            moneybox_script_hex = bytes_to_hex_str(GetP2SHMoneyboxScript())
            for i, vout in enumerate(tx0['vout']):
                scriptPubKey = vout['scriptPubKey']['hex']
                if i == 0:
                    assert(scriptPubKey != moneybox_script_hex)
                    continue
                if hex_str_to_bytes(scriptPubKey)[0] == int(OP_RETURN):
                    continue
                if i != 0:
                    assert_equal(scriptPubKey, moneybox_script_hex)
                    amount_got += vout['value']
            self.log.debug('amount expected: {}, amount got: {}, refill_moneybox_accepted: {}'.format(
                ToCoins(amount), ToCoins(amount_got), self.refill_moneybox_accepted))
            assert_equal(ToSatoshi(amount_got) == ToSatoshi(amount), self.refill_moneybox_accepted)
            return best_hash

    def spend_utxo(self, utxo, key, generate_block = True, reason = None):
        utxo_hash_hex = hashToHex(utxo.hash)
        assert_in(utxo_hash_hex, self.txmap)
        prevtx = self.txmap[utxo_hash_hex]
        assert_greater_than(len(prevtx.vout), utxo.n)
        amount = ToCoins(prevtx.vout[utxo.n].nValue)
        fee = Decimal('0.00001')
        (burn1, burn2, rest) = BurnedAndChangeAmount(amount - fee)
        prevScriptPubKey = prevtx.vout[utxo.n].scriptPubKey
        tx4 = CTransaction()
        tx4.vin.append(CTxIn(utxo, b"", 0xffffffff))
        tx4.vout.append(CTxOut(ToSatoshi(rest), GetP2PKHScript(hash160(b'xyu')))) # send money to 'xyu'
        tx4.vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
        tx4.vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
        (sig_hash, err) = SignatureHash(prevScriptPubKey, tx4, 0, SIGHASH_ALL)
        assert (err is None)
        signature = key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx4.vin[0].scriptSig = CScript([signature, key.get_pubkey()])
        tx4.rehash()

        self.log.debug('spend_utxo, utxo: {}, amount: {}, amount_sent: {}, pubkeyhash: {}, txid: {}, prevScriptPubKey ({}): {}, reason: {}'.
                       format(utxo, amount, rest, bytes_to_hex_str(reverse(hash160(key.get_pubkey()))), tx4.hash,
                              len(prevScriptPubKey), bytes_to_hex_str(prevScriptPubKey), reason))

        tx_message = msg_tx(tx4)
        self.test_node.send_message(tx_message)
        self.test_node.sync_with_ping()
        if self.test_node.reject_message is not None:
            self.log.debug('got reject message: {}'.format(self.test_node.reject_message))
        node0 = self.nodes[0]
        del self.txmap[utxo_hash_hex]

        if generate_block:
            node0.generate(1)
            self.test_node.sync_with_ping()
            best_hash = node0.getbestblockhash()
            last_block = node0.getblock(best_hash)
            # Ensure our transaction is accepted by the node and is included into a block:
            assert_in(tx4.hash, last_block['tx'])
        else:
            # Ensure our transaction is accepted by the node and is included into mempool:
            mempool = node0.getrawmempool()
            assert_in(tx4.hash, mempool)


    def create_root_certificate(self, params):
        utxo_cert_root = None
        ca3_key = None
        invalid_signature = None
        rootcertamount = ToCoins(params['rootcertamount'])
        (burn1, burn2) = GetBurnedValue(rootcertamount)
        burn = burn1 + burn2
        fee = ToCoins('0.01')

        if self.invalid_root_cert is None:
            # regular workflow
            pass
        elif self.invalid_root_cert == 1:
            # non-existing transaction (certificate)
            utxo_cert_root = COutPoint(uint256_from_str(hash256(b'xyu')), 50)
        elif self.invalid_root_cert == 2:
            # regular P2PKH transaction, not certificate
            (utxo_cert_root, _) = self.pay_to_address(AddressFromPubkey(self.genesis_key0.get_pubkey()), rootcertamount + burn + fee)
        elif self.invalid_root_cert == 3:
            # invalid certificate: transfers money to another P2PKH address, not to itself
            away_key = self.create_key('away_key', 'fake_root_cert')
            (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(self.genesis_key0.get_pubkey()),
                                                       rootcertamount + burn + fee)
            (ca3_keys, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, rootcertamount,
                                                                   self.genesis_key0, 1, 1, self.greenflag, False, False, False,
                                                                   'fake_root_cert', alt_dest_pubkeyhash = hash160(away_key.get_pubkey()))
            assert_equal(len(ca3_keys), 1)
            ca3_key = ca3_keys[0]
        elif self.invalid_root_cert == 4:
            # will be processed in update_root_certificate() later
            # another root certificate, not a parent of user certificate (CA3 keys in root and user certificates are different)
            pass
        elif self.invalid_root_cert == 5:
            # invalid root certificate, with unknown root key not mentioned in genesis block
            fake_genezis_key = self.create_key('fake_genezis_key')
            (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(fake_genezis_key.get_pubkey()),
                                                       rootcertamount + burn + fee,
                                                       self.gen_block_after_cert)
            (ca3_keys, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, rootcertamount,
                                                                   fake_genezis_key, 1, 1, self.greenflag, False,
                                                                   False, False, 'fake_root_cert')
            assert_equal(len(ca3_keys), 1)
            ca3_key = ca3_keys[0]
        elif self.invalid_root_cert in list(range(60,70)):
            # use GENESIS_PRIV_KEY_N instead of GENESIS_PRIV_KEY0:
            index = self.invalid_root_cert - 60
            genezis_key1 = CECKey()
            genezis_key1.set_secretbytes(Base58ToSecretBytes(GENESIS_PRIV_KEYS[index]))
            if not genezis_key1.is_compressed():
                genezis_key1.set_compressed(True)
            (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(genezis_key1.get_pubkey()),
                                                       rootcertamount + burn + fee,
                                                       self.gen_block_after_cert)
            (ca3_keys, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, rootcertamount,
                                                                   genezis_key1, 1, 1, self.greenflag, False,
                                                                   False, False, 'root_cert')
            assert_equal(len(ca3_keys), 1)
            ca3_key = ca3_keys[0]
        elif self.invalid_root_cert in [20, 21, 22, 23]:
            invalid_signature = self.invalid_root_cert
        else:
            assert (0)

        if utxo_cert_root is not None:
            if ca3_key is None:
                ca3_key = self.create_key('ca3_key', 'fake_root_cert')
            self.log.debug('create_root_certificate, invalid_root_cert: {}, utxo_cert_root: {}'.format(self.invalid_root_cert, utxo_cert_root))
            return (utxo_cert_root, ca3_key)

        #
        # now regular workflow:
        #

        # Script pays to address ROOT_PKH:
        (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(self.genesis_key0.get_pubkey()),
                                                   rootcertamount + burn + fee,
                                                   self.gen_block_after_cert, 'create_root_cert')

        # Скрипт переводит с адреса ROOT_PKH на этот же адрес некоторую сумму, например 1 PLCU, активируя CA3_PKH ключ.
        (ca3_keys, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, rootcertamount,
                                                               self.genesis_key0,
                                                               1, 1, self.greenflag, False, False, False, 'root_cert',
                                                               invalid_signature=invalid_signature)
        assert_equal(len(ca3_keys), 1)
        ca3_key = ca3_keys[0]
        return (utxo_cert_root, ca3_key)


    def update_root_certificate(self, params, utxo_cert_root):
        rootcertamount = ToCoins(params['rootcertamount'])
        (burn1, burn2) = GetBurnedValue(rootcertamount)
        burn = burn1 + burn2
        fee = ToCoins('0.01')

        if self.revoke_root_cert:
            self.spend_utxo(utxo_cert_root, self.genesis_key0, self.gen_block_after_cert, 'revoke_root_cert')
            self.log.debug('update_root_certificate: revoke_root_cert == True, spending {}'.format(utxo_cert_root))

        if self.invalid_root_cert == 4:
            # another root certificate, not a parent of user certificate (CA3 keys in root and user certificates are different)
            # create one more root certificate:
            (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(self.genesis_key0.get_pubkey()),
                                                       rootcertamount + burn + fee,
                                                       self.gen_block_after_cert)
            (_, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, rootcertamount, self.genesis_key0,
                                                                  1, 1, self.greenflag, False, False, False, 'root_cert_2')
            self.log.debug('update_root_certificate, invalid_root_cert: {}, utxo_cert_root: {}'.format(self.invalid_root_cert, utxo_cert_root))

        return utxo_cert_root


    def create_user_certificate(self, params, ca3_key, user_keys_to_use = None):
        utxo_cert_ca3 = None
        user_keys = None
        ben_key = None
        time_ca3 = None
        invalid_signature = None
        ca3certamount = ToCoins(params['ca3certamount'])
        (burn1, burn2) = GetBurnedValue(ca3certamount)
        burn = burn1 + burn2
        fee = ToCoins('0.01')

        if self.invalid_user_cert is None:
            # regular workflow
            pass
        elif self.invalid_user_cert == 1:
            # non-existing transaction (certificate)
            utxo_cert_ca3 = COutPoint(uint256_from_str(hash256(b'xyu_ca3')), 100)
        elif self.invalid_user_cert == 2:
            # regular P2PKH transaction, not certificate
            (utxo_cert_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()), ca3certamount + burn + fee,
                                                     self.gen_block_after_cert)
        elif self.invalid_user_cert == 3:
            # invalid certificate: transfers money to another P2PKH address, not to itself
            away_key = self.create_key('away_key', 'fake_ca3_cert')
            (utxo_coins_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()),
                                                      ca3certamount + burn + fee,
                                                      self.gen_block_after_cert)
            (user_keys, _, ben_key, utxo_cert_ca3, time_ca3) = self.create_cert(utxo_coins_ca3, ca3certamount,
                                                                                ca3_key, params['keys_count_total'], self.keys_count_required,
                                                                                self.green_flag_in_user_cert, True,
                                                                                self.ben_enabled, self.sivler_hoof,
                                                                                'fake_ca3_cert', user_keys_to_use,
                                                                                exp_date_offset=self.exp_date_offset,
                                                                                minting_limit=self.minting_limit,
                                                                                daily_limit=self.daily_limit,
                                                                                free_ben_enabled=self.free_ben_enabled,
                                                                                alt_dest_pubkeyhash=hash160(away_key.get_pubkey()))
        elif self.invalid_user_cert == 4:
            # will be processed in update_user_certificate() later
            # another user certificate, not a parent of used user keys (user keys used in minting transaction and given in this certificate are different)
            pass
        elif self.invalid_user_cert == 5:
            # will be processed in update_user_certificate() later
            pass
        elif self.invalid_user_cert in [20, 21, 22, 23]:
            invalid_signature = self.invalid_user_cert
        else:
            assert (0)

        if utxo_cert_ca3 is not None:
            if user_keys is None:
                user_keys = self.create_other_keys(params['keys_count_total'], 'user_key', 'fake_ca3_cert')
            if ben_key is None:
                ben_key = self.create_key('ben_key', 'fake_ca3_cert')
            if time_ca3 is None:
                node0 = self.nodes[0]
                node0.generate(1)
                self.test_node.sync_with_ping()
                best_hash = node0.getbestblockhash()
                last_block = node0.getblock(best_hash)
                time_ca3 = last_block['time']
            self.log.debug('create_user_certificate, invalid_user_cert: {}, utxo_cert_ca3: {}, time_ca3: {}'.format(self.invalid_user_cert, utxo_cert_ca3, time_ca3))
            return (user_keys, ben_key, utxo_cert_ca3, time_ca3)

        #
        # now regular workflow:
        #

        # Script pays to address CA3_PKH:
        (utxo_coins_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()),
                                                  ca3certamount + burn + fee,
                                                  self.gen_block_after_cert, 'create_user_cert')

        # Скрипт переводит с адреса CA3_PKH на этот же адрес некоторую сумму, например 10 mPLC, активируя User_PKH ключи.
        (user_keys, _, ben_key, utxo_cert_ca3, time_ca3) = self.create_cert(utxo_coins_ca3, ca3certamount,
                                                                            ca3_key, params['keys_count_total'], self.keys_count_required,
                                                                            self.green_flag_in_user_cert, True,
                                                                            self.ben_enabled, self.sivler_hoof, 'ca3_cert',
                                                                            user_keys_to_use,
                                                                            exp_date_offset=self.exp_date_offset,
                                                                            minting_limit=self.minting_limit,
                                                                            daily_limit=self.daily_limit,
                                                                            free_ben_enabled=self.free_ben_enabled,
                                                                            invalid_signature=invalid_signature)
        assert_equal(len(user_keys), params['keys_count_total'] if self.multisig else 1)
        if self.separate_white:
            self.user_keys_m = user_keys
            user_keys = self.create_other_keys(len(user_keys), 'white')
        return (user_keys, ben_key, utxo_cert_ca3, time_ca3)


    def update_user_certificate(self, params, utxo_cert_ca3, ca3_key, time_ca3):
        ca3certamount = ToCoins(params['ca3certamount'])
        (burn1, burn2) = GetBurnedValue(ca3certamount)
        burn = burn1 + burn2
        fee = ToCoins('0.01')

        if self.revoke_user_cert:
            self.spend_utxo(utxo_cert_ca3, ca3_key, self.gen_block_after_cert, 'revoke_user_cert')
            self.log.debug('update_user_certificate: revoke_user_cert == True, spending {}'.format(utxo_cert_ca3))

        if self.invalid_user_cert == 4:
            # another user certificate, not a parent of used user keys (user keys used in minting transaction and given in this certificate are different)
            (utxo_coins_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()),
                                                      ca3certamount + burn + fee,
                                                      self.gen_block_after_cert)
            (_, _, _, utxo_cert_ca3, time_ca3) = self.create_cert(utxo_coins_ca3, ca3certamount, ca3_key,
                                                                  params['keys_count_total'], self.keys_count_required,
                                                                  self.green_flag_in_user_cert, True,
                                                                  self.ben_enabled, self.sivler_hoof, 'ca3_cert_2',
                                                                  exp_date_offset=self.exp_date_offset,
                                                                  minting_limit=self.minting_limit,
                                                                  daily_limit=self.daily_limit,
                                                                  free_ben_enabled=self.free_ben_enabled)
            self.log.debug('update_user_certificate: invalid_user_cert: {}, utxo_cert_ca3: {}'.format(self.invalid_user_cert, utxo_cert_ca3))
        if self.invalid_user_cert == 5:
            # invalid user coins (not mentioned in CA3 certificate), but valid user keys for signing moneybox outputs in minting tx
            self.spend_utxo(utxo_cert_ca3, ca3_key, self.gen_block_after_cert, 'invalid_user_cert == 5')
            (utxo_coins_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()),
                                                      ca3certamount + burn + fee,
                                                      self.gen_block_after_cert)
            (self.user_keys_m, _, self.ben_key, utxo_cert_ca3, time_ca3) = self.create_cert(utxo_coins_ca3, ca3certamount,
                                                                                            ca3_key, params['keys_count_total'], self.keys_count_required,
                                                                                            self.green_flag_in_user_cert, True,
                                                                                            self.ben_enabled, self.sivler_hoof, 'ca3_cert_m',
                                                                                            exp_date_offset=self.exp_date_offset,
                                                                                            minting_limit=self.minting_limit,
                                                                                            daily_limit=self.daily_limit,
                                                                                            free_ben_enabled=self.free_ben_enabled)
            self.log.debug('update_user_certificate: invalid_user_cert: {}, utxo_cert_ca3: {}'.format(self.invalid_user_cert, utxo_cert_ca3))

        return (utxo_cert_ca3, time_ca3)


    def create_user_coins(self, user_keys, params):
        useramount = params['useramount']
        if isinstance(useramount, tuple):
            user_amounts = list(useramount)
        else:
            user_amounts = [useramount]
        if len(user_amounts) == 0 or (len(user_amounts) == 1 and ToSatoshi(user_amounts[0]) == 0):
            # no user inputs:
            return ([], self.nodes[0].getblock(self.nodes[0].getbestblockhash())['time'], 0)
        user_outputs = []
        total_amount = 0
        gen_block_after_fill_user = params['gen_block_after_fill_user'] if 'gen_block_after_fill_user' in params else True
        for i, a in enumerate(user_amounts):
            last_iteration = (i + 1 == len(user_amounts)) and gen_block_after_fill_user
            assert_greater_than(ToSatoshi(a), 0)
            if self.multisig:
                (user_output, time_usermoney) = self.pay_to_multisig_address(user_keys, ToCoins(a),
                                                                             self.keys_count_used,
                                                                             last_iteration,
                                                                             'create_user_coins')
            else:
                (user_output, time_usermoney) = self.pay_to_address(AddressFromPubkey(user_keys[0].get_pubkey()),
                                                                    ToCoins(a), last_iteration,
                                                                    'create_user_coins')
            user_outputs.append(user_output)
            total_amount += ToSatoshi(a)
        return (user_outputs, time_usermoney, total_amount)


    def check_spent_amount_in_cert(self, outpoint, params, minting_limit_amount_expected, daily_limit_amount_expected):
        minting_limit_exists = self.minting_limit is not None
        daily_limit_exists = self.daily_limit is not None
        txid_hex = '%064x' % (outpoint.hash)
        txout = self.nodes[0].gettxout(txid_hex, outpoint.n)
        zero_minting_limit = (not minting_limit_exists or minting_limit_amount_expected == 0)
        zero_daily_limit = (not daily_limit_exists or daily_limit_amount_expected == 0)
        if zero_minting_limit and zero_daily_limit and (txout is None or 'storage' not in txout):
            return
        storage_bin = hex_str_to_bytes(txout['storage'])
        assert_greater_than_or_equal(len(storage_bin), 4)
        version = struct.unpack("<I", storage_bin[0:4])[0]
        offset = 4
        COINS_STORAGE_MINTING_LIMITS  = 0x00000002
        COINS_STORAGE_DAILY_LIMITS    = 0x00000004
        self.log.debug('storage ({}): {}, version: {}, minting_limit_exists: {}, daily_limit_exists: {}, minting_limit_amount_expected: {}, daily_limit_amount_expected: {}'.format(
            len(storage_bin), bytes_to_hex_str(storage_bin), version, minting_limit_exists, daily_limit_exists, minting_limit_amount_expected, daily_limit_amount_expected))
        minting_limit_amount_got = 0
        daily_limit_amount_got = 0
        if version & COINS_STORAGE_MINTING_LIMITS:
            assert_greater_than_or_equal(len(storage_bin), offset + 12)
            minting_limit_amount_got = struct.unpack("<q", storage_bin[offset + 4:offset + 12])[0]
            offset += 12
        if version & COINS_STORAGE_DAILY_LIMITS:
            assert_greater_than_or_equal(len(storage_bin), offset + 12)
            daily_limit_amount_got = struct.unpack("<q", storage_bin[offset + 4:offset + 12])[0]
            offset += 12
        if minting_limit_exists:
            assert(version & COINS_STORAGE_MINTING_LIMITS)
            assert_equal(minting_limit_amount_expected, minting_limit_amount_got)
        if daily_limit_exists:
            assert(version & COINS_STORAGE_DAILY_LIMITS)
            assert_equal(daily_limit_amount_expected, daily_limit_amount_got)


    def spend_reward(self, params):
        spend_addr = params['spend_reward'] if 'spend_reward' in params else None
        if not spend_addr:
            return

        spend_reward_wait = params['spend_reward_wait'] if 'spend_reward_wait' in params else 0
        if spend_reward_wait:
            self.emulate_fast_wait(spend_reward_wait, params, None, 'spend_reward for {}'.format(spend_addr))

        key_recepient = self.create_key('key_spend_reward_recepient')
        keys_to_sign_spend_reward = None
        index = 0
        index_ab = 'A'
        use_locktime = False
        if len(spend_addr) > 3 and spend_addr[-3] == '[' and spend_addr[-1] == ']':
            index = int(spend_addr[-2])
            spend_addr = spend_addr[:-3]
        if len(spend_addr) > 3 and (spend_addr[-3:] == '[a]' or spend_addr[-3:] == '[A]'):
            index_ab = 'A'
            spend_addr = spend_addr[:-3]
        if len(spend_addr) > 3 and (spend_addr[-3:] == '[b]' or spend_addr[-3:] == '[B]'):
            index_ab = 'B'
            spend_addr = spend_addr[:-3]
        if spend_addr == 'ben':
            keys_to_sign_spend_reward = [self.ben_key]
            hint = self.reward_hints[spend_addr][index]
        elif spend_addr == 'ben_locked' or ((spend_addr == 'ben_ab' or spend_addr == 'ben_ab_locked') and index_ab == 'A'):
            keys_to_sign_spend_reward = [self.ben_key]
            hint = self.reward_hints[spend_addr][index]
            use_locktime = True
        elif (spend_addr == 'ben_ab' or spend_addr == 'ben_ab_locked') and index_ab == 'B':
            keys_to_sign_spend_reward = [self.ben_key, self.fund_project_key]
            hint = self.reward_hints[spend_addr][index]
        else:
            self.log.debug('unknown spend_addr: {}'.format(spend_addr))
            assert (0) # not implemented or forbidden

        utxo_coins = COutPoint(int(hint[0], 16), hint[1])
        amount = hint[2]
        prevScriptPubKey = hint[3]

        tx5 = CTransaction()
        seq = 0xfffffffe if self.locked_outputs else 0xffffffff
        tx5.vin.append(CTxIn(utxo_coins, b"", seq))
        self.log.debug('tx5 vin[0] {} input: {} (from {}:{})'.format(spend_addr, amount, hint[0], hint[1]))
        tx5.vout.append(CTxOut(ToSatoshi(amount) - 100000, GetP2PKHScript(hash160(key_recepient.get_pubkey()))))
        self.log.debug('tx5 vout[0] output: {}'.format(ToCoins(tx5.vout[-1].nValue)))
        if use_locktime:
            now = int(time.time())
            mediantime = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())['mediantime']
            assert_greater_than(now + self.virtual_cur_time_offset, mediantime)
            tx5.nLockTime = mediantime - 1
            self.log.debug('set tx5.nLockTime: {}'.format(tx5.nLockTime))

        (sig_hash, err) = SignatureHash(prevScriptPubKey, tx5, 0, SIGHASH_ALL)
        assert (err is None)
        if len(keys_to_sign_spend_reward) == 1:
            parent_key = keys_to_sign_spend_reward[0]
            signature = parent_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
            tx5.vin[0].scriptSig = CScript([signature, parent_key.get_pubkey()])
        elif len(keys_to_sign_spend_reward) == 2:
            parent_key0 = keys_to_sign_spend_reward[0]
            parent_key1 = keys_to_sign_spend_reward[1]
            signature0 = parent_key0.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
            signature1 = parent_key1.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
            tx5.vin[0].scriptSig = CScript([OP_0, signature0, signature1, OP_2, parent_key0.get_pubkey(), parent_key1.get_pubkey()])
        else:
            assert (0) # impossible

        tx5.rehash()
        tx_message = msg_tx(tx5)
        tx_message_bytes = tx_message.serialize()
        self.log.debug('tx5.hash: {}, hex tx5 ({}): {}'.format(tx5.hash, len(tx_message_bytes), bytes_to_hex_str(tx_message_bytes)))

        self.test_node.send_message(tx_message)
        self.test_node.sync_with_ping()

        if self.test_node.reject_message is not None:
            self.log.debug('got reject message: {}'.format(self.test_node.reject_message))

        # Ensure our transaction is accepted by the node and is included into mempool:
        mempool = self.nodes[0].getrawmempool()
        spend_reward_accepted = params['spend_reward_accepted']
        assert_equal(tx5.hash in mempool, spend_reward_accepted)

        if not spend_reward_accepted:
            self.check_error(self.test_node.reject_message, params)
            self.test_node.reject_message = None


    def run_testcase(self, params):
        node0 = self.nodes[0]
        self.test_node.sync_with_ping()
        total_rewardamount = 0

        if 'blockchain_height' in params:
            blockchain_height = params['blockchain_height']
            current_height = node0.getblockcount()
            self.log.debug('required blockchain_height: {}, current_height: {}'.format(blockchain_height, current_height))
            if current_height < blockchain_height:
                generate_many_blocks(node0, blockchain_height - current_height)
                self.test_node.sync_with_ping()
                self.sync_all()

        if 'spend_reward' in params and params['spend_reward'] == 'fixed':
            self.pay_to_fixed_key()

        # Create root certificate:
        (utxo_cert_root, ca3_key) = self.create_root_certificate(params)
        utxo_cert_root = self.update_root_certificate(params, utxo_cert_root)

        if self.ca3_age > self.usermoney_age:
            # User certificate is older than user money, create it first:

            # Create user certificate:
            (self.user_keys, self.ben_key, utxo_cert_ca3, time_ca3) = self.create_user_certificate(params, ca3_key)
            (utxo_cert_ca3, time_ca3) = self.update_user_certificate(params, utxo_cert_ca3, ca3_key, time_ca3)

            # Wait:
            delta_age = self.ca3_age - self.usermoney_age
            self.emulate_fast_wait(delta_age, params, time_ca3, 'delta_age (ca3_age - usermoney_age)')

            # Script pays to user address (singlesig or multisig):
            (user_outputs, time_usermoney, total_user_amount) = self.create_user_coins(self.user_keys, params)

            # Wait:
            self.emulate_fast_wait(self.usermoney_age, params, time_usermoney, 'usermoney_age')

        elif self.ca3_age < self.usermoney_age:
            assert_equal(self.separate_white, False)  # not implemented for this branch
            # User money is older than user certificate, create it first:

            # Script pays to user address (singlesig or multisig):
            self.user_keys = self.create_other_keys(params['keys_count_total'] if self.multisig else 1, 'user_key', 'ca3_cert')
            (user_outputs, time_usermoney, total_user_amount) = self.create_user_coins(self.user_keys, params)

            # Wait:
            delta_age = self.usermoney_age - self.ca3_age
            self.emulate_fast_wait(delta_age, params, time_usermoney, 'delta_age (usermoney_age - ca3_age)')

            # Create user certificate:
            (self.user_keys, self.ben_key, utxo_cert_ca3, time_ca3) = self.create_user_certificate(params, ca3_key, self.user_keys)
            (utxo_cert_ca3, time_ca3) = self.update_user_certificate(params, utxo_cert_ca3, ca3_key, time_ca3)

            # Wait:
            self.emulate_fast_wait(self.ca3_age, params, time_ca3, 'ca3_age')
        else:
            # User certificate and user money are of equal age:

            # Create user certificate:
            (self.user_keys, self.ben_key, utxo_cert_ca3, time_ca3) = self.create_user_certificate(params, ca3_key)
            (utxo_cert_ca3, time_ca3) = self.update_user_certificate(params, utxo_cert_ca3, ca3_key, time_ca3)

            # Script pays to user address (singlesig or multisig):
            (user_outputs, time_usermoney, total_user_amount) = self.create_user_coins(self.user_keys, params)

            # Wait:
            wait_timefrom = max(time_ca3, time_usermoney) if time_usermoney is not None else None
            self.emulate_fast_wait(self.usermoney_age, params, wait_timefrom, 'ca3_and_usermoney_age')

        if params['name'].startswith('special_'):
            self.run_special_testcase(params, {
                'user_outputs': user_outputs,
                'utxo_cert_root': utxo_cert_root,
                'utxo_cert_ca3': utxo_cert_ca3,
            })
            return

        # step8
        # Скрипт начисляет проценты на положенную сумму из копилки, соблюдая гранулярность аутпутов из копилки,
        # в соответствии с флагом greenFlag, возрастом user-сертификата, возрастом пользовательских денег
        # на адресе User_PKH, на которые начисляются проценты, и процентной ставкой из user-сертификата
        (mint_txid, mint_user_outputs_indexes, spent, reward_payed) = self.mint(user_outputs, utxo_cert_root, utxo_cert_ca3,
                                                                                params, take_moneybox_inputs_from_cache=True)
        # amount is counted after generating a block, now must be zero in any case:
        self.check_spent_amount_in_cert(utxo_cert_ca3, params, 0, 0)

        # step9
        # Проверка пополнения копилки на сумму, которая была потрачена.
        if params['accepted']:
            self.refill_moneybox(spent, params)
            total_rewardamount += reward_payed
            self.check_spent_amount_in_cert(utxo_cert_ca3, params, total_rewardamount, total_user_amount)

        self.spend_reward(params)

        if 'step2_enabled' in params and params['step2_enabled'] == True:
            self.log.info('Will run step2...')
            # update user_outputs: now they are user outputs from previous mint tx:
            user_outputs = [COutPoint(int(mint_txid, 16), i) for i in mint_user_outputs_indexes]
            if 'step2_daily_limit_used' in params:
                total_user_amount = params['step2_daily_limit_used']
            # user output amount from prev step now is user input amount:
            total_user_amount += ToSatoshi(get_tx_output_amount(self.txmap[mint_txid], mint_user_outputs_indexes))
            last_block_time = node0.getblock(node0.getbestblockhash())['time']
            self.emulate_fast_wait(params['step2_wait_interval'], params, last_block_time, 'step2_wait_interval')
            self.step = 2
            (mint_txid, mint_user_outputs_indexes, spent, reward_payed) = self.mint(user_outputs, utxo_cert_root, utxo_cert_ca3, params)
            if params['step2_accepted']:
                self.refill_moneybox(spent, params)
                total_rewardamount += reward_payed
                self.check_spent_amount_in_cert(utxo_cert_ca3, params, total_rewardamount, total_user_amount)

        if 'step3_enabled' in params and params['step3_enabled'] == True:
            self.log.info('Will run step3...')
            # update user_outputs: now they are user outputs from previous mint tx:
            user_outputs = [COutPoint(int(mint_txid, 16), i) for i in mint_user_outputs_indexes]
            if 'step3_daily_limit_used' in params:
                total_user_amount = params['step3_daily_limit_used']
            # user output amount from prev step now is user input amount:
            total_user_amount += ToSatoshi(get_tx_output_amount(self.txmap[mint_txid], mint_user_outputs_indexes))
            self.txmap[mint_txid] = node0.getrawtransaction(mint_txid, True)
            last_block_time = node0.getblock(node0.getbestblockhash())['time']
            self.emulate_fast_wait(params['step3_wait_interval'], params, last_block_time, 'step3_wait_interval')
            self.step = 3
            (mint_txid, mint_user_outputs_indexes, spent, reward_payed) = self.mint(user_outputs, utxo_cert_root, utxo_cert_ca3, params)
            if params['step3_accepted']:
                self.refill_moneybox(spent, params)
                total_rewardamount += reward_payed
                self.check_spent_amount_in_cert(utxo_cert_ca3, params, total_rewardamount, total_user_amount)


    def run_special_testcase(self, params, args):
        if params['name'] == 'special_minting_limit_mempool' or params['name'] == 'special_daily_limit_mempool':
            return self.run_special_limit_mempool(params, args)
        if params['name'] == 'special_minting_limit_fork_blocks' or params['name'] == 'special_daily_limit_fork_blocks':
            return self.run_special_limit_fork_blocks(params, args)
        if params['name'].startswith('special_use_immature_moneybox'):
            return self.run_special_use_immature_moneybox(params, args)
        assert(0) # unknown special testcase


    def run_special_limit_mempool(self, params, args):
        user_outputs = args['user_outputs']
        utxo_cert_root = args['utxo_cert_root']
        utxo_cert_ca3 = args['utxo_cert_ca3']
        useramounts = list(params['useramount'])
        useramount0 = ToSatoshi(useramounts[0])
        useramount1 = ToSatoshi(useramounts[1])
        useramount2 = ToSatoshi(useramounts[2])
        rewardamount_orig = params['rewardamount']

        assert_equal(len(user_outputs), 3)
        assert_equal(params['accepted'], True)
        assert (self.minting_limit is not None or self.daily_limit is not None)
        if self.minting_limit is not None:
            assert_greater_than(self.minting_limit, 0)
            assert_equal(ToSatoshi(self.minting_limit), ToSatoshi(rewardamount_orig))
        if self.daily_limit is not None:
            assert_greater_than(self.daily_limit, 0)
            assert_equal(ToSatoshi(self.daily_limit), useramount0)
        assert_equal(useramount0, useramount1)
        assert_equal(useramount0, useramount2)

        # first try to mint all outputs at once in 1 transaction, must be rejected (limit exceeded):
        self.log.info('Will run reject step...')
        assert (params['error'] is not None)
        params['rewardamount'] = rewardamount_orig * 3
        params['accepted'] = False
        (_, _, spent, _) = self.mint(user_outputs, utxo_cert_root, utxo_cert_ca3, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, params, 0, 0)  # tx was rejected, nothing was counted

        # and now mint one by one, must be accepted:
        total_spent = 0
        total_rewardamount = 0
        for i, user_output in enumerate(user_outputs):
            self.log.info('will run step {}...'.format(i))
            params['rewardamount'] = rewardamount_orig
            params['accepted'] = True
            (_, _, spent, reward_payed) = self.mint([user_output], utxo_cert_root, utxo_cert_ca3, params)
            total_spent += spent
            total_rewardamount += reward_payed
            self.check_spent_amount_in_cert(utxo_cert_ca3, params, 0, 0)  # amount is counted only after generating a block, now zero

        self.refill_moneybox(total_spent, params)
        total_user_amount = useramount0 + useramount1 + useramount2
        self.check_spent_amount_in_cert(utxo_cert_ca3, params, total_rewardamount, total_user_amount)


    def run_special_limit_fork_blocks(self, params, args):
        user_outputs = args['user_outputs']
        utxo_cert_root = args['utxo_cert_root']
        utxo_cert_ca3 = args['utxo_cert_ca3']
        useramounts = list(params['useramount'])
        useramount0 = ToSatoshi(useramounts[0])
        useramount1 = ToSatoshi(useramounts[1])
        useramount2 = ToSatoshi(useramounts[2])

        assert_equal(len(user_outputs), 3)
        assert_equal(params['accepted'], True)
        assert (self.minting_limit is not None or self.daily_limit is not None)
        if self.minting_limit is not None:
            assert_greater_than(self.minting_limit, 0)
            assert_equal(ToSatoshi(self.minting_limit), ToSatoshi(params['rewardamount']) * 2)
        if self.daily_limit is not None:
            assert_greater_than(self.daily_limit, 0)
            assert_equal(ToSatoshi(self.daily_limit), useramount0 * 2)
        assert_equal(useramount0, useramount1)
        assert_equal(useramount0, useramount2)
        assert_equal(params['refill_moneybox'], 'script')
        assert_equal(self.refill_moneybox_accepted, True)

        # blocks: --> B1
        self.log.info('Will run step B1...')
        hash_b0 = self.nodes[0].getbestblockhash()
        self.log.debug('hash_b0: {}'.format(hash_b0))
        (_, _, spent_b1, reward_payed_b1) = self.mint([user_outputs[0]], utxo_cert_root, utxo_cert_ca3, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, params, 0, 0)  # amount is counted only after generating a block, now zero
        hash_b1 = self.refill_moneybox(spent_b1, params)
        self.log.debug('hash_b1: {}'.format(hash_b1))
        self.check_spent_amount_in_cert(utxo_cert_ca3, params, reward_payed_b1, useramount0)

        # blocks: --> B1
        #         \-> B2
        self.log.info('Will run step B2...')
        (mint2_txid, _, spent_b2, reward_payed_b2) = self.mint([user_outputs[1]], utxo_cert_root, utxo_cert_ca3, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, params, reward_payed_b1, useramount0)  # nothing was changed - new block hasn't been generated yet
        self.refill_moneybox_accepted = False
        hash_b2 = self.refill_moneybox(spent_b2, params, hash_b0)
        self.log.debug('hash_b2: {}'.format(hash_b2))
        self.check_spent_amount_in_cert(utxo_cert_ca3, params, reward_payed_b1, useramount0)  # nothing was changed - this block wasn't accepted

        # blocks: --> B1
        #         \-> B2 --> B3
        self.log.info('Will run step B3...')
        (_, _, spent_b3, reward_payed_b3) = self.mint([user_outputs[2]], utxo_cert_root, utxo_cert_ca3, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, params, reward_payed_b1, useramount0)  # nothing was changed - new block hasn't been generated yet
        self.refill_moneybox_accepted = True
        block_b0 = self.nodes[0].getblock(hash_b0)
        block_b2 = { 'version': block_b0['version'], 'bits': block_b0['bits'], 'hash': hash_b2, 'height': block_b0['height'] + 1, 'time': block_b0['time'] + 1 }
        self.refill_moneybox(spent_b3, params, hash_b2, block_b2, skip_transactions=[mint2_txid]) # mint2_txid is in block B2, but before accepting block B3 it is still in mempool
        self.check_spent_amount_in_cert(utxo_cert_ca3, params, reward_payed_b2 + reward_payed_b3, useramount1 + useramount2)  # B1 went off, now B2 + B3

        if self.minting_limit is not None:
            assert_equal(ToSatoshi(self.minting_limit), reward_payed_b2 + reward_payed_b3)


    def run_special_use_immature_moneybox(self, params, args):
        node0 = self.nodes[0]
        user_outputs = args['user_outputs']
        utxo_cert_root = args['utxo_cert_root']
        utxo_cert_ca3 = args['utxo_cert_ca3']
        rewardamount_4coins = 4 * COIN
        accepted_orig = params['accepted']
        name = params['name']
        assert_greater_than(len(user_outputs), 2)
        last_user_output = user_outputs.pop()
        MONEYBOX_AMOUNT = 10000 * COIN
        assert_equal(MONEYBOX_AMOUNT % len(user_outputs), 0)
        reward_exhaust_moneybox = MONEYBOX_AMOUNT // len(user_outputs)
        assert_greater_than(reward_exhaust_moneybox, rewardamount_4coins)
        spent_total = 0
        refill_blockhash = None

        # spend entire moneybox in several iterations, leave rewardamount_4coins as change in the last one:
        for i, out in enumerate(user_outputs):
            self.log.info('Will run step {} from {}...'.format(i, len(user_outputs)))
            last_iteration = (i + 1 == len(user_outputs))
            params['rewardamount'] = reward_exhaust_moneybox - rewardamount_4coins if last_iteration else reward_exhaust_moneybox
            params['accepted'] = True
            (_, _, spent_now, _) = self.mint([out], utxo_cert_root, utxo_cert_ca3, params)
            spent_total += spent_now
        generate_block = 1 if (name != 'special_use_immature_moneybox_mempool') else 0
        if generate_block:
            refill_blockhash = self.refill_moneybox(spent_total, params)

        # Now moneybox is exhausted, except the single output with change rewardamount_4coins,
        # which is either in the mempool or in the last block:
        assert_equal(len(self.get_utxo(MoneyboxP2SHAddress(), 0, 0)), 1 - generate_block)
        assert_equal(len(self.get_utxo(MoneyboxP2SHAddress(), 1, 1)), generate_block)
        assert_equal(len(self.get_utxo(MoneyboxP2SHAddress(), 2, 10)), 0)

        # last step: try to mint using immature moneybox inputs:
        self.log.info('Will run last step...')
        if name == 'special_use_immature_moneybox_change':
            immature_moneybox_inputs = self.get_utxo(MoneyboxP2SHAddress(), 1, 1)
        elif name == 'special_use_immature_moneybox_mempool':
            immature_moneybox_inputs = self.get_utxo(MoneyboxP2SHAddress(), 0, 0)
        elif name == 'special_use_immature_moneybox_coinbase':
            immature_moneybox_inputs = []
            refill_block = node0.getblock(refill_blockhash)
            txid0 = refill_block['tx'][0]
            txraw0 = node0.getrawtransaction(txid0)
            tx0 = node0.decoderawtransaction(txraw0)
            moneybox_script_hex = bytes_to_hex_str(GetP2SHMoneyboxScript())
            for i, vout in enumerate(tx0['vout']):
                scriptPubKey = vout['scriptPubKey']['hex']
                if i == 0:
                    assert (scriptPubKey != moneybox_script_hex)
                    continue
                if hex_str_to_bytes(scriptPubKey)[0] == int(OP_RETURN):
                    continue
                if i != 0:
                    assert_equal(scriptPubKey, moneybox_script_hex)
                    assert_equal(vout['n'], i)
                    immature_moneybox_inputs = [{'txid': txid0, 'vout': i, 'scriptPubKey': scriptPubKey, 'amount': vout['value']}]
                    break
        else:
            assert(0) # unknown scenario

        self.log.debug('immature_moneybox_inputs ({}): {}'.format(len(immature_moneybox_inputs), immature_moneybox_inputs))
        assert_equal(len(immature_moneybox_inputs), 1)
        params['rewardamount'] = rewardamount_4coins
        params['accepted'] = accepted_orig
        (_, _, _, _) = self.mint([last_user_output], utxo_cert_root, utxo_cert_ca3, params, more_moneybox_inputs=immature_moneybox_inputs)


    def run_test(self):
        name = self.options.runtestcase
        if name is None:
            # minting.py without parameters - ignore it
            return
        testcase = get_minting_testcases()[name]
        assert (testcase is not None)

        self.log.info('Running testcase {} ...'.format(name))
        self.log.debug('Parameters:\n{}'.format(json.dumps(testcase, indent=4, sort_keys=True)))
        self.check_parameters(testcase)
        self.log.info('Updated parameters:\n{}'.format(json.dumps(testcase, indent=4, sort_keys=True)))
        self.run_testcase(testcase)
        self.log.info('End of testcase {}'.format(name))


if __name__ == '__main__':
    MintingTest().main()
