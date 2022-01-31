#!/usr/bin/env python3
# Copyright (c) 2021 The PLC Ultima Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.util import *
from test_framework.script import *
from test_framework.key import CECKey, create_key, sign_compact
from test_framework.blocktools import create_coinbase, create_block

'''
certs.py
'''

logger=logging.getLogger("TestFramework.certs")

HAS_DEVICE_KEY         = 0x00000001
HAS_BEN_KEY            = 0x00000002
HAS_EXPIRATION_DATE    = 0x00000004
HAS_MINTING_LIMIT      = 0x00000008
HAS_DAILY_LIMIT        = 0x00000010
HAS_OTHER_DATA         = 0x00000800
FAST_MINTING           = 0x00010000
FREE_BEN               = 0x00020000
SILVER_HOOF            = 0x00040000
SUPER_TX               = 0x00080000
TOTAL_PUBKEYS_COUNT_MASK     = 0x0000f000
REQUIRED_PUBKEYS_COUNT_MASK  = 0xf0000000

GENESIS_PRIV_KEYS = \
[
    'AwSa6ksSR1RzDuT3xNqJfPnPm4ZbMQyBU4tp9btbTmn6EUHe9EECCGv',
    'AwSa3tMyJVjeNLgZYt3NtDZ8vkNxURV5BZ9VUCGhzuoy56GHeEJVR2Z',
    'AwSa2scm66ftUDqEYMT1uUjpnjBYeGxTrUVjJzgpeZD8VKrRpTyaqpk',
    'AwSa7XXatjN7yHw86gCN1XXsKv9wB9ForvbNSipLxoqx6bNJaAvLgU7',
    'AwSa7GBV6qqN3EXs3avRP3a8zi6UfinBgVQocgDAgbqKpg4nsEVGUNK',
    'AwSa8j9EvpcGyyVzFMP86kZK69AW1xmfgVae9i6tvrnWVTg1sgQRmqs',
    'AwSa5gcNMJNkMRL21vXkx9adnTxTevG2Pedht8wW1SMK4t1zVg2UWVe',
    'AwSa8idLz74DFfT9bEfN7NceLTCXvLSCUGJchhXKG26YDUjShR9dDDc',
    'AwSa7vuZU9RhaBZHWe24MAjFzEG6F1aKtPMG8sGLZ39xMKH4VE5aQMx',
    'AwSa9p7cFYTYwWXBZqyFwcar17B7qe2DNycBCBqz9u4pLhTzaoDpuW9',
]
GENESIS_PRIV_KEY0_BIN = Base58ToSecretBytes(GENESIS_PRIV_KEYS[0])
GENESIS_PRIV_KEY0_HEX = bytes_to_hex_str(GENESIS_PRIV_KEY0_BIN)
assert_equal(len(GENESIS_PRIV_KEYS), 10)
assert_equal(GENESIS_PRIV_KEY0_HEX, '9546a59bb22c64b20c55c33c4a24b8b794e771c96f65387f45e529bbee400b5c01')


def flag_to_str(flag):
    flags = {
        HAS_DEVICE_KEY: 'HAS_DEVICE_KEY',
        HAS_BEN_KEY: 'HAS_BEN_KEY',
        HAS_EXPIRATION_DATE: 'HAS_EXPIRATION_DATE',
        HAS_MINTING_LIMIT: 'HAS_MINTING_LIMIT',
        HAS_DAILY_LIMIT: 'HAS_DAILY_LIMIT',
        HAS_OTHER_DATA: 'HAS_OTHER_DATA',
        FAST_MINTING: 'FAST_MINTING',
        FREE_BEN: 'FREE_BEN',
        SILVER_HOOF: 'SILVER_HOOF',
        SUPER_TX: 'SUPER_TX',
    }
    if flag in flags:
        return flags[flag]
    logger.debug(f'unknownw flag: {flag}')
    assert (0)
    # return 'unknown'


def flags_to_str(flags):
    flagsss = []
    for i in range(32):
        next_bit = (1 << i)
        if (next_bit & TOTAL_PUBKEYS_COUNT_MASK) or (next_bit & REQUIRED_PUBKEYS_COUNT_MASK):
            continue
        if flags & next_bit:
            flagsss.append(flag_to_str(next_bit))
    return ' | '.join(flagsss)


def process_reject_message(test_node, reject_reason, accepted):
    if not accepted and reject_reason:
        assert_startswith(test_node.reject_message.reason.decode('ascii'), reject_reason)
    test_node.reject_message = None


def send_tx(node, test_node, tx, accepted, reject_reason=None, try_mine_in_block=True):
    # for input in tx.vin:
    #     txid_hex = '%064x' % (input.prevout.hash)
    #     logger.debug(f'parent tx: {node.getrawtransaction(txid_hex, 1)}')
    # tx_hex = bytes_to_hex_str(tx.serialize())
    # logger.debug(f'this tx: {node.decoderawtransaction(tx_hex)}')

    tx_message = msg_tx(tx)
    test_node.send_message(tx_message)
    test_node.sync_with_ping()

    if accepted and test_node.reject_message is not None:
        logger.error(f'got reject message: {test_node.reject_message}')

    # Ensure our transaction is accepted by the node and is included into mempool:
    assert_equal(tx.hash in node.getrawmempool(), accepted)

    process_reject_message(test_node, reject_reason, accepted)

    if not accepted and try_mine_in_block:
        # Try to create a block with a bad tx, and ensure the node will not accept it too:
        bestblockhash_before = node.getbestblockhash()
        block_time = node.getblock(bestblockhash_before)['time'] + 1
        height = node.getblockcount() + 1
        block = create_block(int(bestblockhash_before, 16), create_coinbase(height), block_time)
        block.nVersion = VB_TOP_BITS
        block.vtx.extend([tx])
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        block_message = msg_block(block)
        logger.debug('Sending block {}: {}'.format(block.hash, bytes_to_hex_str(block_message.serialize())))
        test_node.send_message(block_message)
        test_node.sync_with_ping()
        assert_equal(bestblockhash_before, node.getbestblockhash())
        process_reject_message(test_node, reject_reason, accepted)
    return tx.hash if accepted else None


def generate_outpoints(node, count, amount, address):
    logger.debug(f'generate_outpoints: count: {count}, amount: {amount}, address: {address}, balance: {node.getbalance()}')
    outpoints = []
    fee_sum = 0
    for i in range(count):
        txid = node.sendtoaddress(address, amount)
        outpoints.append(COutPoint(int(txid, 16), find_output(node, txid, amount)))
        fee_sum += node.gettransaction(txid)['fee']
    return (outpoints, fee_sum)


def compose_cert_tx(utxo_coins, amount, parent_key, name=None, flags = HAS_DEVICE_KEY | SILVER_HOOF,
                    child_key=None, prev_scriptpubkey=None, block1a=None, block2a=None, block1_hash=None, parent_key_for_block2=None):
    parent_pubkey_bin = parent_key.get_pubkey()
    pubkeyhash = hash160(parent_pubkey_bin)
    child_key = child_key if child_key else create_key()
    print_key_verbose(child_key, 'child_key in ' + str(name))
    block1 = bytearray(struct.pack(b"<I", flags))
    user_pubkeyhash = hash160(child_key.get_pubkey())
    block1.extend(user_pubkeyhash)
    if flags & HAS_DEVICE_KEY:
        dev_key = create_key()
        block1.extend(hash160(dev_key.get_pubkey()))
    if block1a is not None:
        block1 = block1a
    block1_hash = block1_hash if block1_hash else hash256(block1)
    parent_key_for_block2 = parent_key_for_block2 if parent_key_for_block2 else parent_key
    block2 = block2a if block2a is not None else sign_compact(block1_hash, parent_key_for_block2.get_secret())

    scriptOutPKH = CScript([block1, block2, OP_2DROP, OP_DUP, OP_HASH160, pubkeyhash, OP_EQUALVERIFY, OP_CHECKSIG])
    (burn1, burn2) = GetBurnedValue(amount)
    tx2 = CTransaction()
    tx2.vin.append(CTxIn(utxo_coins, b"", 0xffffffff))
    tx2.vout.append(CTxOut(ToSatoshi(amount), scriptOutPKH))
    tx2.vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
    tx2.vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))

    scriptPubKey = prev_scriptpubkey if prev_scriptpubkey else GetP2PKHScript(pubkeyhash)
    (sig_hash, err) = SignatureHash(scriptPubKey, tx2, 0, SIGHASH_ALL)
    assert (err is None)
    signature = parent_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
    tx2.vin[0].scriptSig = CScript([signature, parent_pubkey_bin])
    tx2.rehash()
    return (tx2, child_key)


def compose_mint_tx(user_utxos, moneybox_utxos, utxo_cert_root, utxo_cert_ca3, user_key, user_amount, lock_timepoint, reward_amount, reward_change, use_burn):
    tx3 = CTransaction()
    reward_amount = ToCoins(reward_amount)

    for user_utxo in user_utxos:
        tx3.vin.append(CTxIn(user_utxo, GetP2PKHScript(hash160(user_key.get_pubkey())), 0xffffffff))
    for moneybox_utxo in moneybox_utxos:
        tx3.vin.append(CTxIn(moneybox_utxo, GetP2SHMoneyboxScript(), 0xffffffff))

    # append user_outputs to tx:
    tx3.vout.append(CTxOut(ToSatoshi(user_amount), GetP2PKHScriptWithTimeLock(hash160(user_key.get_pubkey()), lock_timepoint)))

    # append reward_outputs to tx:
    (burn1, burn2, reward_payed) = BurnedAndChangeAmount(reward_amount) if reward_amount > 0 and use_burn else (0, 0, reward_amount)
    other_key = create_key()
    tx3.vout.append(CTxOut(ToSatoshi(reward_payed), GetP2PKHScript(hash160(other_key.get_pubkey()))))
    if burn1 > 0:
        tx3.vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
    if burn2 > 0:
        tx3.vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))

    # append moneybox_outputs to tx:
    if reward_change:
        tx3.vout.append(CTxOut(ToSatoshi(reward_change), GetP2SHMoneyboxScript()))

    for i in range(len(user_utxos)):
        (sig_hash, err) = SignatureHash(CScript(tx3.vin[i].scriptSig), tx3, i, SIGHASH_ALL)
        assert (err is None)
        signature = user_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx3.vin[i].scriptSig = CScript([signature, user_key.get_pubkey()])

    for i in range(len(user_utxos), len(tx3.vin)):
        # There are no common rules of composing signature for p2sh transaction inputs,
        # we made agreement to replace scriptSig with inner script (CScript(OP_CHECKREWARD)), not
        # with the public key script of the referenced transaction output
        # (excluding all occurences of OP CODESEPARATOR in it), as for p2pkh transactions:
        scriptSig = CScript([OP_CHECKREWARD])
        (sig_hash, err) = SignatureHash(scriptSig, tx3, i, SIGHASH_ALL)
        assert (err is None)
        signatures_and_keys = []

        signature = user_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        signatures_and_keys.append(signature)
        signatures_and_keys.append(user_key.get_pubkey())
        tx3.vin[i].scriptSig = CScript(signatures_and_keys +
                                       [ ser_uint256(utxo_cert_root.hash), utxo_cert_root.n,
                                         ser_uint256(utxo_cert_ca3.hash), utxo_cert_ca3.n,
                                         CScript([OP_CHECKREWARD])])
    tx3.rehash()
    return (tx3, reward_payed)


