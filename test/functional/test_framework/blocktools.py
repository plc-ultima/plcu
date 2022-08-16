#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utilities for manipulating blocks and transactions."""

from .mininode import *
from .script import *
from .util import *
import binascii


def get_moneybox_granularity(height=None):
    return 100 * COIN

# Create a block (with regtest difficulty)
def create_block(hashprev, coinbase, nTime=None, bits=None, version=None, tx_list=[]):
    block = CBlock()
    block.nVersion = version if version else 1
    if nTime is None:
        import time
        block.nTime = int(time.time()+90)
    else:
        block.nTime = nTime
    block.hashPrevBlock = hashprev
    block.nBits = bits if bits else 0x1f7fffff  # Will break after a difficulty adjustment...
    block.vtx.append(coinbase)
    block.vtx.extend(tx_list)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.calc_sha256()
    return block

# From BIP141
WITNESS_COMMITMENT_HEADER = b"\xaa\x21\xa9\xed"


def get_witness_script(witness_root, witness_nonce):
    witness_commitment = uint256_from_str(hash256(ser_uint256(witness_root)+ser_uint256(witness_nonce)))
    output_data = WITNESS_COMMITMENT_HEADER + ser_uint256(witness_commitment)
    return CScript([OP_RETURN, output_data])


# According to BIP141, blocks with witness rules active must commit to the
# hash of all in-block transactions including witness.
def add_witness_commitment(block, nonce=0):
    # First calculate the merkle root of the block's
    # transactions, with witnesses.
    witness_nonce = nonce
    witness_root = block.calc_witness_merkle_root()
    # witness_nonce should go to coinbase witness.
    block.vtx[0].wit.vtxinwit = [CTxInWitness()]
    block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ser_uint256(witness_nonce)]

    # witness commitment is the last OP_RETURN output in coinbase
    block.vtx[0].vout.append(CTxOut(0, get_witness_script(witness_root, witness_nonce)))
    block.vtx[0].rehash()
    block.hashMerkleRoot = block.calc_merkle_root()
    block.rehash()


def serialize_script_num(value):
    r = bytearray(0)
    if value == 0:
        return r
    neg = value < 0
    absvalue = -value if neg else value
    while (absvalue):
        r.append(int(absvalue & 0xff))
        absvalue >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0)
    elif neg:
        r[-1] |= 0x80
    return r


def get_subsidy(height, minerfees, network = 'regtest'):
    next_height = {
        'regtest': 2000,
        'testnet': 119000,
        'main': 25000,
    }
    if height <= 100:
        return int(BASE_CB_AMOUNT * COIN)
    elif height <= next_height[network]:
        return max(500000, int(minerfees / 2))  # int(0.005*COIN)
    return max(5000, int(minerfees / 2))  # int(0.00005*COIN)


def get_plc_award(height, refill_moneybox_amount, granularity):
    if height <= 100:
        return [granularity] * 10
    outputs = [granularity] * (refill_moneybox_amount // granularity)
    if (refill_moneybox_amount % granularity) > 0:
        outputs.append(refill_moneybox_amount % granularity)
    return outputs


# Create a coinbase transaction.
# If pubkey is passed in, the coinbase output will be a P2PK output;
# otherwise an anyone-can-spend output.
def create_coinbase(height, pubkey=None, minerfees=0, refill_moneybox_amount=0, granularity=None,
                    moneyboxscript=GetP2SHMoneyboxScript(), total_bc_amount=None):
    if granularity is None:
        granularity = get_moneybox_granularity(height)
    if total_bc_amount is None:
        total_bc_amount = get_total_expected(height)
    coinbase = CTransaction()
    coinbase.vin.append(CTxIn(COutPoint(0, TXIN_MARKER_COINBASE), ser_string(serialize_script_num(height)), 0xffffffff))
    if total_bc_amount != -1:
        coinbase.vin.append(CTxIn(COutPoint(0, TXIN_MARKER_TOTAL_AMOUNT), ser_string(serialize_script_num(ToSatoshi(total_bc_amount))), 0xffffffff))
    coinbase.vout = []

    subsidy = CTxOut()
    subsidy.nValue = get_subsidy(height, minerfees)
    if (pubkey != None):
        subsidy.scriptPubKey = CScript([pubkey, OP_CHECKSIG])
    else:
        subsidy.scriptPubKey = CScript([OP_TRUE])

    if (subsidy.nValue > 0):
        coinbase.vout.append(subsidy)

    for elem in get_plc_award(height, refill_moneybox_amount, granularity):
        plcaward = CTxOut()
        plcaward.nValue = elem
        plcaward.scriptPubKey = moneyboxscript
        coinbase.vout.append(plcaward)

    coinbase.calc_sha256()
    return coinbase


# Create a transaction.
# If the scriptPubKey is not specified, make it anyone-can-spend.
def create_transaction(prevtx, n, sig, value, scriptPubKey=CScript()):
    tx = CTransaction()
    assert(n < len(prevtx.vout))
    (burn1, burn2, rest) = BurnedAndChangeAmount(ToCoins(value))
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), sig, 0xffffffff))
    tx.vout.append(CTxOut(ToSatoshi(rest), scriptPubKey))
    if burn1:
        tx.vout.append(CTxOut(ToSatoshi(burn1), GraveScript1()))
    if burn2:
        tx.vout.append(CTxOut(ToSatoshi(burn2), GraveScript2()))
    tx.calc_sha256()
    return tx

def get_legacy_sigopcount_block(block, fAccurate=True):
    count = 0
    for tx in block.vtx:
        count += get_legacy_sigopcount_tx(tx, fAccurate)
    return count

def get_legacy_sigopcount_tx(tx, fAccurate=True):
    count = 0
    for i in tx.vout:
        count += i.scriptPubKey.GetSigOpCount(fAccurate)
    for j in tx.vin:
        # scriptSig might be of type bytes, so convert to CScript for the moment
        count += CScript(j.scriptSig).GetSigOpCount(fAccurate)
    return count

def get_tx_output_amount(tx, output_indexes):
    amount_sum = 0
    for index in output_indexes:
        assert_greater_than(len(tx['vout']), index)
    for i, out in enumerate(tx['vout']):
        assert_equal(i, out['n'])
        if i in output_indexes:
            amount_sum += out['value']
    return amount_sum

def get_total_expected(height):
    return (BASE_CB_AMOUNT + ToCoins(get_moneybox_granularity(height) * 10)) * min(height, 100)
