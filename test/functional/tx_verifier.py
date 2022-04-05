#!/usr/bin/env python3
# Copyright (c) 2020 The PLC Ultima Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from datetime import datetime
from test_framework.mininode import *
from test_framework.util import *
from test_framework.script import *
from test_framework.key import *
from test_framework.blocktools import get_subsidy
from test_framework.certs import *


RPC_USER = 'xyu'
RPC_PASSW = 'xyu'
RPC_URL = 'http://127.0.0.1:9556/'

TESTNET = None  # will be determined automatically
genezis_pubkey0 = None

MONEYBOX_GRAN_MAIN = {
    0: 100,
}
MONEYBOX_GRAN_TESTNET = {
    0: 100,
}

exclude_transactions = set(
    [
        'e932fafc1044f0ac390d27539cf5c6560603ee950267c6c43cee0d7d06789b68', # testnet, invalid compact signature in certificate
        'ec5c421228f95b2e51505c44e526465dd164ce1e5b5a2bbc7413dfc89b67e94e', # testnet, invalid compact signature size in certificate
        '3398e19b729de1dbf4bc6089e61fad3c5d422162249da4128e43663f5a01ebc3', # -//-
        'dde8371ab284b377965b12be223c6a29b4ba3b6e919056e5bb02bdfcc6cbc6af', # -//-
        '1ff34fe2f20b659a6efdf19bd8535586f829da5d2e60ddfe3ad9130bde9ecb48', # -//-
        '42f32077c67dbddf2b336afab13c0d9aed1f3adfd7f1c6c75910f77a521d8928', # -//-
        '01c84f0194c62496fbf3e948cb067b79968d4ac3f22cc8d41da8b2c8a2329c00', # -//-
        'e71ab65a77edb3bab1eb7159f00328c8ea46f67606c08567c1cc6736d20fb810', # -//-
        'dcb0ed15d7d881aa795a710518c2eb30475b91710558e31f07e42eb51fa573aa', # -//-
        '757d0600e43b77426dfb1c97a711eb4c35d1e344cd755841322dce84fa873508', # -//-
        '54cb75c44b9189f25d166903a9dde3ac53124889ea1dbc4aa2996fff5788de13', # main, bad burn
        '28b799300c7fde2cd5e0c44581155235e63e23e8aea0ba69877803708da63f90', # main, bad burn
        'c3d0b129fb6c628fcb066640cdfa6243686d94d6aea4fd4d9eff0c9312a29159', # main, bad burn
        '33c7b71543f9b3e70bb45f71925e15adeb137c7d35c9fd1028014d3b609c8593', # main, bad burn
        '45316835cb1f6a8feda6484d2902862204097339a5e91323b45b0049738409cc', # main, bad burn
        '61cefcd16382a64b3a39c8c849a2a9367a8953de5f763556c84575e49a59ec75', # main, bad burn
        '35b94bd12780dd23a324560e89abb2b8fdea3dfff432ee0f673c65f0d69de12a', # main, bad burn
        '5ecbd3305b5bdb50a53b3bf899d7915d435043e27a363832977d3ea72e0e15b8', # main, bad burn
        'de94fd3fccbe8e1b1ac9b47b08a589ecca7134f07b2d0134a9666470c23ba9c5', # main, bad burn
        '6ac35e317c84685271f945886389bb5abf3710052b10a267cabd47a68e564803', # main, bad burn
        'ea8a4d0171deabf442518206af0ae919210ad1dcfd09adf99a7f93f39aad2876', # main, bad burn
        '937916a4f507adf04fef5d22d154ec676fc57a30ac236bd97e5d119fab2301fa', # main, bad burn
        '516df4f8ddb9ad9a038ad972e57cdd6ff3ad0ccaa79c7d7c74cb09c9a783acd7', # main, bad burn
        'adabc94f2322fef194ef4c64cb24156146f7a72c6278d6be04cae8ebdfc2cf5a', # main, bad burn
        'fef87257bbe89d22b67bb2f9884e5313ddb838832087a28de90250580881554a', # main, bad burn
        '372b1a62d4f93b5436ec31a7dbe76cca0df88053c1e7045112a3bec26acee69b', # main, bad burn
        'dd04613103d206dc2015a194d9860fa1d1335c32707afa02d96e1193d687e9f7', # main, bad burn
        '009476084032c5f844eab33b1a94917d06212f925e014135e0a749f26d1326a9', # main, bad burn
        'fee9c9dfcce2391c9685852f2a4c2356144bb22899ade138ddc0c2a81edf7935', # main, bad burn
    ]
)

# RULES_VERSION:
RULES_VERSION = 4
# 4: reward is calculated for 1 locked user output with max amount, reward per transaction
#     * user amount is taken from one locked user output with max amount
#     * percent in certificate is per year; reward must be corrected due to user output lock interval


def IsOp(script, op):
    return len(script) == 1 and script[0] == op


def spaces(indent):
    return ' ' * indent * 2


class AddrInfo:
    addr_type = None
    addresses = []
    lock_timepoint = None

    def __init__(self, addr_type = None, addresses = [], lock_timepoint = None):
        self.addr_type = addr_type
        self.addresses = addresses
        self.lock_timepoint = lock_timepoint


def GetAddressInfo(scriptPubKey):
    if len(scriptPubKey) == 0:
        return AddrInfo('empty')

    def is_grave_pkh(pkh):
        grave_pkh = GRAVE_1_PKH_TESTNET if TESTNET else GRAVE_1_PKH_MAINNET
        return pkh == grave_pkh

    def suffix(lock_timepoint, cert, burn):
        return ('_locked' if lock_timepoint else '') + (' certificate' if cert else '') + (' burn' if burn else '')

    script = CScript(scriptPubKey)
    ops = ExtractAllFromScript(script)
    lock_timepoint = None
    cert = False

    if len(ops) > 3 and \
            IsOp(ops[1], OP_CHECKLOCKTIMEVERIFY) and \
            IsOp(ops[2], OP_DROP):
        lock_timepoint = struct.unpack("<I", ops[0])[0]
        ops = ops[3:]

    if len(ops) > 3 and \
            len(ops[0]) >= 24 and \
            len(ops[1]) == 65 and \
            IsOp(ops[2], OP_2DROP):
        cert = True
        ops = ops[3:]

    if len(ops) == 2 and \
            len(ops[0]) == 33 and \
            IsOp(ops[1], OP_CHECKSIG):
        return AddrInfo('p2pk' + suffix(lock_timepoint, cert, is_grave_pkh(hash160(ops[0]))), [ops[0]], lock_timepoint)

    if len(ops) == 5 and \
            IsOp(ops[0], OP_DUP) and \
            IsOp(ops[1], OP_HASH160) and \
            len(ops[2]) == 20 and \
            IsOp(ops[3], OP_EQUALVERIFY) and \
            IsOp(ops[4], OP_CHECKSIG):
        return AddrInfo('p2pkh' + suffix(lock_timepoint, cert, is_grave_pkh(ops[2])), [ops[2]], lock_timepoint)

    if len(ops) == 3 and \
            IsOp(ops[0], OP_HASH160) and \
            len(ops[1]) == 20 and \
            IsOp(ops[2], OP_EQUAL):
        if ops[1] == hash160(bytearray([int(OP_CHECKREWARD)])):
            return AddrInfo('p2sh_moneybox' + suffix(lock_timepoint, cert, False), [ops[1]], lock_timepoint)
        else:
            return AddrInfo('p2sh' + suffix(lock_timepoint, cert, ops[1] == GRAVE_2_SH), [ops[1]], lock_timepoint)

    if len(ops) >= 1 and \
            IsOp(ops[0], OP_RETURN):
        return AddrInfo('return', ops[1:], lock_timepoint)

    if len(ops) >= 4 and \
            IsOp(ops[-1], OP_CHECKMULTISIG):
        M = ops[0][0] - OP_1 + 1
        N = ops[-2][0] - OP_1 + 1
        assert_greater_than_or_equal(N, M)
        assert_equal(len(ops), N + 3)
        pkh_list = []
        for i in range(1, N+1):
            next_pubkey = ops[i]
            assert_equal(len(next_pubkey), 33)
            pkh_list.append(hash160(next_pubkey))
        return AddrInfo('multisig {} of {}'.format(M, N) + suffix(lock_timepoint, cert, False), pkh_list, lock_timepoint)

    if len(ops) == 18 and \
            IsOp(ops[0], OP_DUP) and \
            IsOp(ops[1], OP_HASH160) and \
            len(ops[2]) == 20 and \
            IsOp(ops[3], OP_EQUAL) and \
            IsOp(ops[4], OP_IF) and \
            IsOp(ops[5], OP_CHECKSIG) and \
            IsOp(ops[6], OP_ELSE) and \
            IsOp(ops[7], OP_OVER) and \
            IsOp(ops[8], OP_HASH160) and \
            len(ops[9]) == 20 and \
            IsOp(ops[10], OP_EQUALVERIFY) and \
            IsOp(ops[11], OP_DUP) and \
            IsOp(ops[12], OP_HASH160) and \
            len(ops[13]) == 20 and \
            IsOp(ops[14], OP_EQUALVERIFY) and \
            IsOp(ops[15], OP_2) and \
            IsOp(ops[16], OP_CHECKMULTISIG) and \
            IsOp(ops[17], OP_ENDIF):
        assert_equal(lock_timepoint, None)
        return AddrInfo('funding', [ ops[2], ops[9], ops[13] ])

    if len(ops) == 21 and \
            IsOp(ops[0], OP_DUP) and \
            IsOp(ops[1], OP_HASH160) and \
            len(ops[2]) == 20 and \
            IsOp(ops[3], OP_EQUAL) and \
            IsOp(ops[4], OP_IF) and \
            IsOp(ops[6], OP_CHECKLOCKTIMEVERIFY) and \
            IsOp(ops[7], OP_DROP) and \
            IsOp(ops[8], OP_CHECKSIG) and \
            IsOp(ops[9], OP_ELSE) and \
            IsOp(ops[10], OP_OVER) and \
            IsOp(ops[11], OP_HASH160) and \
            len(ops[12]) == 20 and \
            IsOp(ops[13], OP_EQUALVERIFY) and \
            IsOp(ops[14], OP_DUP) and \
            IsOp(ops[15], OP_HASH160) and \
            len(ops[16]) == 20 and \
            IsOp(ops[17], OP_EQUALVERIFY) and \
            IsOp(ops[18], OP_2) and \
            IsOp(ops[19], OP_CHECKMULTISIG) and \
            IsOp(ops[20], OP_ENDIF):
        assert_equal(lock_timepoint, None)
        lock_timepoint = struct.unpack("<I", ops[5])[0]
        name = 'ab_minting' if ops[2] == ops[12] else 'ab_minting_ex'
        return AddrInfo(name, [ ops[2], ops[12], ops[16] ], lock_timepoint)

    return AddrInfo('other')


def ExtractBlock(script, offset, size):
    if offset + size > len(script):
        raise CScriptInvalidError('ExtractBlock: not enough data in len={} for offset={}, size={}'.format(len(script), offset, size))
    return (script[offset:offset+size], script[offset+size:])

def ExtractNextFromScript(script):
    if len(script) == 0:
        raise CScriptInvalidError('parsing empty script')
    if script[0] == OP_0:
        return (script[0:1], script[1:])
    if script[0] < OP_PUSHDATA1:
        return ExtractBlock(script, 1, script[0])
    if script[0] == OP_PUSHDATA1:
        if len(script) < 2:
            raise CScriptInvalidError('no data after OP_PUSHDATA1')
        return ExtractBlock(script, 2, script[1])
    if script[0] == OP_PUSHDATA2:
        if len(script) < 3:
            raise CScriptInvalidError('no data after OP_PUSHDATA2')
        size = struct.unpack("<H", script[1:3])[0]
        return ExtractBlock(script, 3, size)
    if script[0] == OP_PUSHDATA4:
        if len(script) < 5:
            raise CScriptInvalidError('no data after OP_PUSHDATA4')
        size = struct.unpack("<I", script[1:5])[0]
        return ExtractBlock(script, 5, size)
    return (script[0:1], script[1:])

def ExtractAllFromScript(script):
    all = []
    while True:
        if len(script) == 0:
            break
        (next, script) = ExtractNextFromScript(script)
        all.append(next)
    return all

def ExtractPartFromScript(script, n):
    parts = []
    for i in range(n):
        if len(script) == 0:
            break
        (next, script) = ExtractNextFromScript(script)
        parts.append(next)
    return (parts, script)

def GetOpN(op):
    if op >= OP_1 and op <= OP_16:
        return int(op) - int(OP_1) + 1
    return int(op)

def PKHFromScript(script):
    p = ExtractAllFromScript(script)
    p = p[-5:]
    if (len(p) == 5 and IsOp(p[0], OP_DUP) and IsOp(p[1], OP_HASH160) and len(p[2]) == 20) and IsOp(p[3], OP_EQUALVERIFY) and IsOp(p[4], OP_CHECKSIG):
        return p[2]
    return None

def SHFromScript(script):
    p = ExtractAllFromScript(script)
    if (len(p) == 3 and IsOp(p[0], OP_HASH160) and len(p[1]) == 20) and IsOp(p[2], OP_EQUAL):
        return p[1]
    return None


class VerificationError(Exception):
    pass

def Verify(condition, message):
    if not condition:
        raise VerificationError(message)


def CheckMultisigKeys(keys_got, keys_cert, required_keys_cnt):
    Verify(len(keys_got) >= required_keys_cnt, f'got too few pubkeys ({len(keys_got)}), required_keys_cnt in certificate: {required_keys_cnt}')
    index_got = 0
    index_cert = 0
    reason = 'wrong user keys are provided, not mentioned in certificate, or too few keys, or wrong order; keys_got: {}; keys_cert: {}; required_keys_cnt: {}'.format(
        [bytes_to_hex_str(e) for e in keys_got], [bytes_to_hex_str(e) for e in keys_cert], required_keys_cnt
    )
    for i in range(required_keys_cnt):
        Verify(index_got < len(keys_got), reason + f', cond1, iter {i}')
        Verify(index_cert < len(keys_cert), reason + f', cond2, iter {i}')
        while index_got < len(keys_got) and keys_got[index_got] not in keys_cert[index_cert:]:
            index_got += 1
        Verify(index_got < len(keys_got), reason + f', cond3, iter {i}')
        index_cert += keys_cert[index_cert:].index(keys_got[index_got])
        # OK, keys_got[index_got] == keys_cert[index_cert], go further
        index_got += 1
        index_cert += 1


class CVrfTx(object):
    def __init__(self, txid='', size = 0, time = None):
        self.txid = txid
        self.size = size
        self.time = time if time is not None else get_last_block_time()
        self.inputs = []
        self.outputs = []
        self.cert_txs = []
        self.mint_calculated = False
        self.mined_in_block_num = None

    def __repr__(self):
        out = 'TX {}:\n'.format(self.txid)
        for inp in self.inputs:
            out += str(inp)
            out += '\n'
        for outp in self.outputs:
            out += str(outp)
            out += '\n'
        return out

class CVrfInput(object):
    def __init__(self, txid='', n=-1, scriptSig=b"", nSequence=0, i=-1, amount=Decimal(0), scriptPubKey=b'', is_coinbase=False):
        self.txid = txid
        self.n = n
        self.scriptSig = scriptSig
        self.nSequence = nSequence
        self.i = i                    # number of input in this transaction
        self.is_coinbase = is_coinbase
        self.is_taxfree_cert = False
        self.prev_out = CVrfOutput(n, amount, scriptPubKey)
        if is_coinbase:
            self.prev_out.addr_details = 'coinbase'

    def __repr__(self):
        return 'input {}:{}: seq: {}, is_coinbase: {}, prev: {}'.format(self.txid, self.n, self.nSequence, self.is_coinbase, self.prev_out)


class CVrfOutput(object):
    def __init__(self, n=-1, amount=Decimal(0), scriptPubKey=b''):
        self.n = n
        self.amount = amount
        self.scriptPubKey = scriptPubKey
        self.addr_details = None
        self.spent = None
        self.cert = None
        self.time = None
        if self.scriptPubKey is not None:
            self.addr_info = GetAddressInfo(scriptPubKey)
            self.addr_details = address_details(self.addr_info)

    def __repr__(self):
        return 'output {}: amount: {}, scriptPubKey: {}, spent: {}, {}'.format(self.n, self.amount, bytes_to_hex_str(self.scriptPubKey), self.spent, self.addr_details)

class CVrfCert(object):
    def __init__(self, output, flags=0):
        self.output = output
        self.flags = flags
        self.children = []
        self.ben_pkh = None
        self.exp_date = None
        self.minting_limit = None
        self.daily_limit = None
        self.multisig_sh = None

    def total_keys(self):
        n = self.total_keys_orig()
        return n if n != 0 else 1
    def total_keys_orig(self):
        return (self.flags & TOTAL_PUBKEYS_COUNT_MASK) >> 12
    def required_keys(self):
        n = self.required_keys_orig()
        return n if n != 0 else self.total_keys()
    def required_keys_orig(self):
        return (self.flags & REQUIRED_PUBKEYS_COUNT_MASK) >> 28
    def is_root_cert(self):
        global genezis_pubkey0
        if genezis_pubkey0 is None:
            genezis_pubkey0 = get_root_pubkey()
        return PKHFromScript(self.output.scriptPubKey) == hash160(genezis_pubkey0)


def call_func(method, params):
    id = '%08X' % random.randint(1,0xFFFFFFFF)
    paramss = str(params)
    paramss = paramss.replace("'", '"')
    paramss = paramss.replace('True', 'true')
    paramss = paramss.replace('False', 'false')
    request = 'curl --silent --user {}:{}'.format(RPC_USER, RPC_PASSW) + ' --data-binary \'{"jsonrpc": "1.0", "id":"' + id + '", "method": "' + method + '", "params": ' + paramss + ' }\' -H "content-type: text/plain;" ' + RPC_URL
    result = os.popen(request).read()
    result = json.loads(result)
    if id != result['id'] or result['error'] is not None:
        print('ERROR:')
        print('request: {}'.format(request))
        print('result: {}'.format(result))
    result = result['result']
    return result


def time_str(time):
    return datetime.utcfromtimestamp(time).strftime('%d.%m.%Y %H:%M:%S') if time is not None else 'None'


def get_granularity_for_block(block_num):
    if block_num is None:
        block_num = call_func('getblockcount', [])
    assert (TESTNET is not None)
    gran_map = MONEYBOX_GRAN_TESTNET if TESTNET else MONEYBOX_GRAN_MAIN
    block_from = max([key for key in gran_map.keys() if key <= block_num])
    return gran_map[block_from]


def get_last_block_time():
    best_block_hash = call_func('getbestblockhash', [])
    last_block = call_func('getblock', [best_block_hash])
    return last_block['time']


def fill_input(input):
    assert ((input.txid == '') == (input.n == -1))
    assert ((input.txid == '' or input.n == -1) == input.is_coinbase)
    if input.is_coinbase:
        return
    if input.txid == '0' * 64:
        input.is_taxfree_cert = True
        return
    tx_parent = call_func('getrawtransaction', [input.txid, True])
    Verify(tx_parent is not None, 'parent tx for input {} was not found'.format(input.txid))
    Verify(input.n < len(tx_parent['vout']), 'invalid input {}:{}: index is out of range ({})'.format(input.txid, input.n, len(tx_parent['vout'])))
    vout = tx_parent['vout'][input.n]
    input.prev_out.amount = satoshi_round(str(vout['value']))
    input.prev_out.scriptPubKey = hex_str_to_bytes(vout['scriptPubKey']['hex'])
    input.prev_out.addr_info = GetAddressInfo(input.prev_out.scriptPubKey)
    input.prev_out.addr_details  = address_details(input.prev_out.addr_info)
    assert_equal(input.n, vout['n'])
    txout = call_func('gettxout', [input.txid, input.n, True])
    input.prev_out.spent = txout is None
    if 'time' in tx_parent:
        input.prev_out.time = tx_parent['time']


def address_details(ai):
    Verify(ai.addr_type != 'other', 'unknown tx type')
    if 'p2pkh_locked' in ai.addr_type:
        return 'address: {} ({}, {})'.format(AddressFromPubkeyHash(ai.addresses[0], TESTNET), ai.addr_type, time_str(ai.lock_timepoint))
    elif 'p2pkh' in ai.addr_type:
        return 'address: {} ({})'.format(AddressFromPubkeyHash(ai.addresses[0], TESTNET), ai.addr_type)
    elif 'p2pk_locked' in ai.addr_type:
        return 'address: {} ({}, {})'.format(AddressFromPubkey(ai.addresses[0], TESTNET), ai.addr_type, time_str(ai.lock_timepoint))
    elif 'p2pk' in ai.addr_type:
        return 'address: {} ({})'.format(AddressFromPubkey(ai.addresses[0], TESTNET), ai.addr_type)
    elif 'p2sh_locked' in ai.addr_type:
        return 'address: {} ({}, {})'.format(AddressFromScriptHash(ai.addresses[0], TESTNET), ai.addr_type, time_str(ai.lock_timepoint))
    elif 'p2sh' in ai.addr_type:
        return 'address: {} ({})'.format(AddressFromScriptHash(ai.addresses[0], TESTNET), ai.addr_type)
    elif ai.addr_type == 'funding':
        Verify(len(ai.addresses) == 3, 'Invalid funding structure, got {} keys instead of 3'.format(len(ai.addresses)))
        return 'addresses: {} OR {} + {} ({})'.format(
            AddressFromPubkeyHash(ai.addresses[0], TESTNET),
            AddressFromPubkeyHash(ai.addresses[1], TESTNET),
            AddressFromPubkeyHash(ai.addresses[2], TESTNET),
            ai.addr_type)
    elif ai.addr_type in ['ab_minting', 'ab_minting_ex']:
        Verify(len(ai.addresses) == 3, 'Invalid ab_minting structure, got {} keys instead of 3'.format(len(ai.addresses)))
        return 'addresses: {} since {} OR {} + {} ({})'.format(
            AddressFromPubkeyHash(ai.addresses[0], TESTNET), time_str(ai.lock_timepoint),
            AddressFromPubkeyHash(ai.addresses[1], TESTNET),
            AddressFromPubkeyHash(ai.addresses[2], TESTNET), ai.addr_type)
    elif 'multisig' in ai.addr_type:
        return 'addresses: {} ({})'.format(' | '.join(AddressFromPubkeyHash(a, TESTNET) for a in ai.addresses), ai.addr_type)
    return 'address: {}'.format(ai.addr_type)


def verify_input(input, this_ctransaction, vrftx, indent = 0):
    off1 = indent
    off2 = indent + 1
    off3 = indent + 2
    if input.is_coinbase:
        print(spaces(off1) + 'Input coinbase:')
        print(spaces(off2) + 'nSequence: %08x' % (input.nSequence))
        return
    if input.is_taxfree_cert:
        print(spaces(off1) + 'Input taxfree_cert:')
        print(spaces(off2) + 'nSequence: %08x' % (input.nSequence))
        return
    print(spaces(off1) + 'Input {}:{}:'.format(input.txid, input.n))
    print(spaces(off2) + '{}'.format(input.prev_out.addr_details))
    print(spaces(off2) + 'amount: {}'.format(input.prev_out.amount))
    print(spaces(off2) + 'scriptPubKey: {}'.format(bytes_to_hex_str(input.prev_out.scriptPubKey)))
    print(spaces(off2) + 'scriptSig: {}'.format(bytes_to_hex_str(input.scriptSig)))
    print(spaces(off2) + 'nSequence: %08x' % (input.nSequence))
    print(spaces(off2) + 'time: {} ({})'.format(input.prev_out.time, time_str(input.prev_out.time)))
    print(spaces(off2) + 'input is spent: {}'.format(input.prev_out.spent))
    addr_info = GetAddressInfo(input.prev_out.scriptPubKey)
    txtype = addr_info.addr_type

    if 'p2pkh' in txtype:
        operands = ExtractAllFromScript(input.scriptSig)
        Verify(len(operands) == 2, 'Input {} ({}:{}): p2pkh scriptSig must have 2 operands, got: {}'.format(input.i, input.txid, input.n, len(operands)))
        signature = operands[0]
        pubkey = operands[1]
        hash = addr_info.addresses[0]
        Verify(hash160(pubkey) == hash, 'Input {} ({}:{}): p2pkh wrong pubkey is used'.format(input.i, input.txid, input.n))
        Verify(len(signature) > 0, 'Input {} ({}:{}): p2pkh scriptSig: empty signature'.format(input.i, input.txid, input.n))
        Verify(signature[-1] == SIGHASH_ALL, 'Input {} ({}:{}): p2pkh scriptSig: not SIGHASH_ALL signature (not implemented for other types)'.format(input.i, input.txid, input.n))
        signature = signature[:-1]
        (sig_hash, err) = SignatureHash(CScript(input.prev_out.scriptPubKey), this_ctransaction, input.i, SIGHASH_ALL)
        Verify(err is None, 'SignatureHash error: {}'.format(err))
        key = CECKey()
        key.set_pubkey(pubkey)
        verify_res = key.verify(sig_hash, signature)
        Verify(verify_res, 'Input {} ({}:{}): invalid signature: sig_hash: {}, pubkey ({}): {}, signature ({}): {}'.
               format(input.i, input.txid, input.n, bytes_to_hex_str(sig_hash), len(pubkey), bytes_to_hex_str(pubkey), len(signature), bytes_to_hex_str(signature)))

    elif 'p2pk' in txtype:
        operands = ExtractAllFromScript(input.scriptSig)
        Verify(len(operands) == 1, 'Input {} ({}:{}): p2pk scriptSig must have 1 operand, got: {}'.format(input.i, input.txid, input.n, len(operands)))
        signature = operands[0]
        pubkey = addr_info.addresses[0]
        Verify(len(signature) > 0, 'Input {} ({}:{}): p2pk scriptSig: empty signature'.format(input.i, input.txid, input.n))
        Verify(signature[-1] == SIGHASH_ALL, 'Input {} ({}:{}): p2pk scriptSig: not SIGHASH_ALL signature (not implemented for other types)'.format(input.i, input.txid, input.n))
        signature = signature[:-1]
        (sig_hash, err) = SignatureHash(CScript(input.prev_out.scriptPubKey), this_ctransaction, input.i, SIGHASH_ALL)
        Verify(err is None, 'SignatureHash error: {}'.format(err))
        key = CECKey()
        key.set_pubkey(pubkey)
        verify_res = key.verify(sig_hash, signature)
        Verify(verify_res, 'Input {} ({}:{}): invalid signature: sig_hash: {}, pubkey ({}): {}, signature ({}): {}'.
               format(input.i, input.txid, input.n, bytes_to_hex_str(sig_hash), len(pubkey), bytes_to_hex_str(pubkey), len(signature), bytes_to_hex_str(signature)))

    elif 'moneybox' in input.prev_out.addr_details:
        script_ops = ExtractAllFromScript(input.scriptSig)
        Verify(len(script_ops) >= 7, 'len(moneybox_script) < 7, got {}'.format(len(script_ops)))
        signatures_and_pubkeys = script_ops[:-5]
        Verify(len(signatures_and_pubkeys) % 2 == 0, 'corrupted moneybox_script, len(signatures_and_pubkeys): {}'.format(len(signatures_and_pubkeys)))
        signatures = []
        pubkeys = []
        for item in signatures_and_pubkeys:
            if len(pubkeys) < len(signatures):
                pubkeys.append(item)
            else:
                signatures.append(item)
        root_cert_txid = script_ops[-5]
        root_cert_n = script_ops[-4]
        ca3_cert_txid = script_ops[-3]
        ca3_cert_n = script_ops[-2]
        inner_script = script_ops[-1]
        Verify(len(inner_script) == 1, 'invalid inner_script len: {}, must be 1'.format(len(inner_script)))
        Verify(inner_script[0] == OP_CHECKREWARD, 'invalid inner_script[0]: {}, must be OP_CHECKREWARD'.format(inner_script[0]))
        scriptSig = CScript([OP_CHECKREWARD])
        (sig_hash, err) = SignatureHash(scriptSig, this_ctransaction, input.i, SIGHASH_ALL)
        Verify(err is None, 'SignatureHash error: {}'.format(err))
        for (signature, pubkey) in zip(signatures, pubkeys):
            Verify(len(signature) > 0, 'empty signature')
            Verify(signature[-1] == SIGHASH_ALL, 'implemented only for SIGHASH_ALL, got: {}'.format(signature[-1]))
            signature = signature[:-1]
            key = CECKey()
            key.set_pubkey(pubkey)
            verify_res = key.verify(sig_hash, signature)
            Verify(verify_res, 'Input {} ({}:{}): invalid signature: sig_hash: {}, pubkey ({}): {}, signature ({}): {}'.
               format(input.i, input.txid, input.n, bytes_to_hex_str(sig_hash), len(pubkey), bytes_to_hex_str(pubkey), len(signature), bytes_to_hex_str(signature)))
        root_cert_vrftx = CVrfTx()
        ca3_cert_vrftx = CVrfTx()
        for i, cert in enumerate([(root_cert_txid, root_cert_n, root_cert_vrftx), (ca3_cert_txid, ca3_cert_n, ca3_cert_vrftx)]):
            cert_txid = cert[0]
            cert_n = cert[1]
            cert_vrftx = cert[2]
            cert_txid = reverse(cert_txid)
            Verify(len(cert_txid) == 32, 'invalid txid len in cert{}: {}, must be 32'.format(i, len(cert_txid)))
            Verify(len(cert_n) >= 1, 'zero n len in cert{}'.format(i))
            Verify(len(cert_n) == 1, 'cert{}: not implemented for n len: {}'.format(i, len(cert_n)))
            cert_n = GetOpN(cert_n[0])
            cert_txid = bytes_to_hex_str(cert_txid)
            Verify(len(vrftx.cert_txs) == 0 or (len(vrftx.cert_txs) == 2 and vrftx.cert_txs[i].txid == cert_txid and
                                                vrftx.cert_txs[i].outputs[0].n == cert_n), 'different certificates in moneybox inputs, must be the same')
            if len(vrftx.cert_txs) > 0:
                print(spaces(off2) + 'CERT{} {}:{} was checked earlier, skipping...'.format(i, cert_txid, cert_n))
                continue
            print(spaces(off2) + 'CERT{} {}:{} details:'.format(i, cert_txid, cert_n))
            cert_tx = call_func('getrawtransaction', [cert_txid, True])
            Verify(cert_n < len(cert_tx['vout']), 'cert{}: index {} is out of range: {}'.format(i, cert_n, len(cert_tx['vout'])))
            cert_vout = cert_tx['vout'][cert_n]
            cert_vrftx.txid = cert_txid
            if 'time' in cert_tx:
                cert_vrftx.time = cert_tx['time']
            cert_output = CVrfOutput(cert_n, satoshi_round(str(cert_vout['value'])), hex_str_to_bytes(cert_vout['scriptPubKey']['hex']))
            fill_output(cert_output, cert_vrftx)
            cert_vrftx.outputs.append(cert_output)
            for j, cert_vin in enumerate(cert_tx['vin']):
                Verify('coinbase' not in cert_vin, 'certificate cannot be coinbase tx')
                cert_next_input = CVrfInput(cert_vin['txid'], cert_vin['vout'], hex_str_to_bytes(cert_vin['scriptSig']['hex']), cert_vin['sequence'], j)
                fill_input(cert_next_input)
                cert_vrftx.inputs.append(cert_next_input)
            verify_output(cert_output, cert_vrftx, indent + 2, True)
        if vrftx.mint_calculated:
            this_cert = vrftx.cert_txs[1].outputs[0].cert
            Verify(this_cert.total_keys() == len(this_cert.children), f'corrupted ca3 certificate, len(keys) != N, got: keys: {len(this_cert.children)}, N: {this_cert.total_keys()}')
            CheckMultisigKeys([hash160(k) for k in pubkeys], this_cert.children, this_cert.required_keys())
            return
        root_cert_out = root_cert_vrftx.outputs[0]
        ca3_cert_out = ca3_cert_vrftx.outputs[0]
        # Verify(root_cert_out.spent == False, 'root_cert is spent (revoked)')
        # Verify(ca3_cert_out.spent == False, 'ca3_cert is spent (revoked)')
        Verify(root_cert_out.cert.is_root_cert() == True, 'root_cert is not root cert')
        Verify(ca3_cert_out.cert.is_root_cert() == False, 'ca3_cert is root cert')
        Verify(root_cert_out.cert.total_keys() == 1, 'root cert must have 1 child key, got: {}'.format(root_cert_out.cert.total_keys()))
        Verify(root_cert_out.cert.children[0] == PKHFromScript(ca3_cert_out.scriptPubKey), 'ca3_cert uses another key not provided in root_cert')
        user_pkhs = ca3_cert_out.cert.children
        ben_pkh = ca3_cert_out.cert.ben_pkh
        CheckMultisigKeys([hash160(k) for k in pubkeys], ca3_cert_out.cert.children, ca3_cert_out.cert.required_keys())

        moneybox_inputs = [inp for inp in vrftx.inputs if inp.prev_out.scriptPubKey == GetP2SHMoneyboxScript()]
        moneybox_outputs = [outp for outp in vrftx.outputs if outp.scriptPubKey == GetP2SHMoneyboxScript()]
        Verify(len(moneybox_outputs) <= 1, 'too many change moneybox outputs ({})'.format(len(moneybox_outputs)))
        moneybox_input_amount = sum(inp.prev_out.amount for inp in moneybox_inputs)
        moneybox_output_amount = sum(outp.amount for outp in moneybox_outputs)
        moneybox_granularity = get_granularity_for_block(vrftx.mined_in_block_num)
        Verify(moneybox_output_amount <= moneybox_granularity, 'too high moneybox change granularity for height {}: max_expected: {}, got: {}'.format(vrftx.mined_in_block_num, moneybox_granularity, moneybox_output_amount))
        Verify(moneybox_input_amount > moneybox_output_amount, 'moneybox_input_amount ({}) <= moneybox_output_amount ({})'.format(moneybox_input_amount, moneybox_output_amount))
        percent = ToCoins(min(root_cert_out.amount, ca3_cert_out.amount)) * 10

        minting_3_0 = (ca3_cert_out.cert.flags & SILVER_HOOF)
        if minting_3_0:
            white_inputs = [inp for inp in vrftx.inputs if inp.prev_out.scriptPubKey != GetP2SHMoneyboxScript()]
            white_inputs_count = len(white_inputs)
            Verify(white_inputs_count >= 1, 'no user inputs')
            white_pkh_set = set()
            for input in white_inputs:
                ai = GetAddressInfo(input.prev_out.scriptPubKey)
                if len(ai.addresses) == 1:
                    white_pkh_set.add(ai.addresses[0])
                else:
                    Verify(0, f'Invalid user input (addresses: {ai.addresses})')
            Verify(len(white_pkh_set) == 1, 'missing/different/ambigious user inputs: {}'.format([AddressFromPubkeyHash(h, TESTNET) for h in white_pkh_set]))
            white_pkh = list(white_pkh_set)[0]
            white_locked_outputs = []
            white_change_outputs = []
            other_outputs = []
            white_output_with_max_amount = None
            max_locked_amount = 0
            timepoint_of_max_locked_amount = 0

            for output in vrftx.outputs:
                ai = GetAddressInfo(output.scriptPubKey)
                if ai.addr_type == 'p2sh_moneybox':
                    continue
                if ai.addr_type == 'p2pk' or ai.addr_type == 'p2pkh':
                    if ai.addresses[0] == white_pkh:
                        white_change_outputs.append(output)
                    else:
                        other_outputs.append(output)
                elif ai.addr_type == 'p2pk_locked' or ai.addr_type == 'p2pkh_locked':
                    if ai.addresses[0] == white_pkh:
                        white_locked_outputs.append(output)
                        # if not white_output_with_max_amount or ai.lock_timepoint > max_lock_timepoint:
                        if not white_output_with_max_amount or output.amount > max_locked_amount:
                            max_locked_amount = output.amount
                            timepoint_of_max_locked_amount = ai.lock_timepoint
                    else:
                        other_outputs.append(output)
                else:
                    other_outputs.append(output)

            white_locked_outputs_count = len(white_locked_outputs)
            white_change_outputs_count = len(white_change_outputs)
            Verify(white_locked_outputs_count + white_change_outputs_count >= 1, 'user_locked_outputs_count == user_change_outputs_count == 0')
            white_input_amount = sum(inp.prev_out.amount for inp in white_inputs)
            white_locked_output_amount = sum(outp.amount for outp in white_locked_outputs)
            white_change_output_amount = sum(outp.amount for outp in white_change_outputs)
            other_output_amounts = [outp.amount for outp in other_outputs]
            other_output_amount_sum = sum(other_output_amounts)
            reward_got = other_output_amount_sum
            locked_period = 0

            Verify(RULES_VERSION == 4, f'Invalid RULES_VERSION: {RULES_VERSION}')
            if timepoint_of_max_locked_amount:
                locked_period = timepoint_of_max_locked_amount - vrftx.time
                reward_calc = ToCoins(ToSatoshi(max_locked_amount * percent) * locked_period // 3600 // 24 // 365)
            else:
                reward_calc = 0

            max_fee = Decimal(10)
            print(spaces(off2) + 'Minting 3.0 calculation:')
            print(spaces(off3) + f'RULES_VERSION: {RULES_VERSION}')
            print(spaces(off3) + 'red address: {}'.format(AddressFromPubkeyHash(user_pkhs[0], TESTNET)))
            print(spaces(off3) + 'user address: {}'.format(AddressFromPubkeyHash(white_pkh, TESTNET)))
            print(spaces(off3) + f'user_input_amount: {white_input_amount}')
            print(spaces(off3) + f'user_locked_output_amount: {white_locked_output_amount}')
            print(spaces(off3) + f'user_change_output_amount: {white_change_output_amount}')
            print(spaces(off3) + f'max_locked_user_amount: {max_locked_amount}')
            print(spaces(off3) + 'timepoint_of_max_locked_amount: {}, locked_period: {} ({}d, {}y)'.format(timepoint_of_max_locked_amount, locked_period, round(locked_period/3600/24, 4), round(locked_period/3600/24/365, 4)))
            print(spaces(off3) + f'other_output_amount_sum: {other_output_amount_sum}')
            print(spaces(off3) + f'percent: {percent} (or {percent * 100} %)')
            print(spaces(off3) + f'reward_calc: {reward_calc}')
            print(spaces(off3) + f'reward_got: {reward_got}')
            print(spaces(off3) + 'ratio calculated/got: {}'.format(round(reward_calc / reward_got, 4)))
            print(spaces(off3) + f'moneybox_input_amount: {moneybox_input_amount}')
            print(spaces(off3) + f'moneybox_output_amount: {moneybox_output_amount}')
            print(spaces(off3) + f'moneybox_fee: {moneybox_input_amount - moneybox_output_amount - reward_got}')
            Verify(reward_got <= reward_calc, 'robbery!')
            Verify(moneybox_input_amount - moneybox_output_amount <= reward_got + max_fee, 'moneybox robbery!')
        else:
            Verify(0, 'old minting v1 is removed')
        vrftx.cert_txs.append(root_cert_vrftx)
        vrftx.cert_txs.append(ca3_cert_vrftx)
        vrftx.mint_calculated = True
    elif txtype == 'funding' or txtype == 'ab_minting' or txtype == 'ab_minting_ex':
        ops = ExtractAllFromScript(input.scriptSig)
        Verify(len(ops) == 2 or len(ops) == 6, 'Input {} ({}:{}): invalid scriptSig len when spending {}: {}'.format(input.i, input.txid, input.n, txtype, len(ops)))
        print(spaces(off2) + 'keys count used to spend {}: {}'.format(txtype, 1 if len(ops) == 2 else 2))
        if len(ops) == 2:
            signature = ops[0]
            pubkey = ops[1]
            hash = addr_info.addresses[0]
            Verify(hash160(pubkey) == hash, 'Input {} ({}:{}): {} wrong pubkey is used'.format(input.i, input.txid, input.n, txtype))
            Verify(len(signature) > 0, 'Input {} ({}:{}): {} scriptSig: empty signature'.format(input.i, input.txid, input.n, txtype))
            Verify(signature[-1] == SIGHASH_ALL, 'Input {} ({}:{}): {} scriptSig: not SIGHASH_ALL signature (not implemented for other types)'.format(input.i, input.txid, input.n, txtype))
            signature = signature[:-1]
            (sig_hash, err) = SignatureHash(CScript(input.prev_out.scriptPubKey), this_ctransaction, input.i, SIGHASH_ALL)
            Verify(err is None, 'SignatureHash error: {}'.format(err))
            key = CECKey()
            key.set_pubkey(pubkey)
            verify_res = key.verify(sig_hash, signature)
            Verify(verify_res, 'Input {} ({}:{}): invalid signature when spending {}: sig_hash: {}, pubkey ({}): {}, signature ({}): {}'.
                   format(input.i, input.txid, input.n, txtype, bytes_to_hex_str(sig_hash), len(pubkey), bytes_to_hex_str(pubkey), len(signature), bytes_to_hex_str(signature)))
        else:
            # ops[0] - any operand may be here
            Verify(IsOp(ops[3], OP_2), 'Input {} ({}:{}), {} scriptSig: got {} instead of OP_2'.format(input.i, input.txid, input.n, txtype, ops[3]))
            signatures = [ ops[1], ops[2] ]
            pubkeys = [ ops[4], ops[5] ]
            hashes = [ addr_info.addresses[1], addr_info.addresses[2] ]
            for (signature, pubkey, hash) in zip(signatures, pubkeys, hashes):
                Verify(hash160(pubkey) == hash, 'Input {} ({}:{}): {} wrong pubkey is used'.format(input.i, input.txid, input.n, txtype))
                Verify(len(signature) > 0, 'Input {} ({}:{}): {} scriptSig: empty signature'.format(input.i, input.txid, input.n, txtype))
                Verify(signature[-1] == SIGHASH_ALL, 'Input {} ({}:{}): {} scriptSig: not SIGHASH_ALL signature (not implemented for other types)'.format( input.i, input.txid, input.n, txtype))
                signature = signature[:-1]
                (sig_hash, err) = SignatureHash(CScript(input.prev_out.scriptPubKey), this_ctransaction, input.i, SIGHASH_ALL)
                Verify(err is None, 'SignatureHash error: {}'.format(err))
                key = CECKey()
                key.set_pubkey(pubkey)
                verify_res = key.verify(sig_hash, signature)
                Verify(verify_res, 'Input {} ({}:{}): invalid signature when spending {}: sig_hash: {}, pubkey ({}): {}, signature ({}): {}'.
                       format(input.i, input.txid, input.n, txtype, bytes_to_hex_str(sig_hash), len(pubkey), bytes_to_hex_str(pubkey), len(signature), bytes_to_hex_str(signature)))
    elif txtype == 'p2sh':
        print(spaces(off2) + 'skip check for spending p2sh output')
    elif txtype == 'return':
        Verify(False, 'Forbidden to reference on return output type')
    else:
        Verify(False, f'trying to spend unknown or not implemented output type: {txtype}')


def calc_reward(user_inputs, usermoney_ages, ca3_age, green_flag, percent):
    sum_impulses = 0
    for user_input, usermoney_age in zip(user_inputs, usermoney_ages):
        user_input_amount = user_input.prev_out.amount
        if green_flag:
            if usermoney_age <= 23 * 3600:
                coin_day_weight_temp2 = 0
            elif usermoney_age <= 30 * 24 * 3600:
                coin_day_weight_temp2 = usermoney_age
            else:
                coin_day_weight_temp2 = 30 * 24 * 3600
            coin_day_weight = coin_day_weight_temp2
        else:
            if usermoney_age <= 20 * 24 * 3600:
                coin_day_weight_temp1 = 0
            elif usermoney_age <= 30 * 24 * 3600:
                coin_day_weight_temp1 = usermoney_age
            else:
                coin_day_weight_temp1 = 30 * 24 * 3600
            coin_day_weight = min(coin_day_weight_temp1, ca3_age)
        sum_impulses += user_input_amount * coin_day_weight
    reward = satoshi_round(sum_impulses * percent / 365 / 24 / 3600)
    return reward


def fill_output(output, vrftx):
    txout = call_func('gettxout', [vrftx.txid, output.n, True])
    output.spent = txout is None
    output.time = vrftx.time
    output.txtype = GetAddressInfo(output.scriptPubKey).addr_type


def verify_output(output, vrftx, indent = 0, print_time = False):
    off1 = indent
    off2 = indent + 1
    print(spaces(off1) + f'Output {output.n}:')
    print(spaces(off2) + f'{output.addr_details}')
    if 'certificate' in output.addr_details:
        verify_cert(output, vrftx, indent + 2)
        if output.spent:
            print(spaces(off2) + 'cert is revoked')
    print(spaces(off2) + f'amount: {output.amount}')
    print(spaces(off2) + f'scriptPubKey: {bytes_to_hex_str(output.scriptPubKey)}')
    if print_time:
        print(spaces(off2) + f'time: {vrftx.time} ({time_str(vrftx.time)})')
    print(spaces(off2) + f'output is spent: {output.spent}')


def verify_cert(output, vrftx, indent = 0):
    (parts, rest) = ExtractPartFromScript(output.scriptPubKey, 3)
    if len(parts) != 3:
        print(spaces(indent) + f'invalid certificate structure, less than 3 operands, got: {len(parts)}')
        return
    block1 = parts[0]
    block2 = parts[1]
    block3 = parts[2]
    if len(block1) < 24 or len(block2) != 65 or not IsOp(block3, OP_2DROP):
        print(spaces(indent) + 'invalid certificate structure (step2)')
        return
    ai = GetAddressInfo(rest)
    txtype = ai.addr_type
    hash = ai.addresses[0]
    if txtype != 'p2pkh':
        print(spaces(indent) + 'invalid certificate structure, not p2pkh')
        return
    if not any(PKHFromScript(inp.prev_out.scriptPubKey) == hash for inp in vrftx.inputs):
        print(spaces(indent) + 'output address {} not found in inputs'.format(AddressFromPubkeyHash(hash, TESTNET)))
    flags = struct.unpack("<I", block1[0:4])[0]
    output.cert = CVrfCert(output, flags)
    details = []
    block1_len_expected = 4
    for i in range(output.cert.total_keys()):
        details.append(spaces(indent) + 'child {} address: {}'.format(i, AddressFromPubkeyHash(block1[block1_len_expected:block1_len_expected + 20], TESTNET)))
        output.cert.children.append(block1[block1_len_expected:block1_len_expected + 20])
        block1_len_expected += 20
    if flags & HAS_DEVICE_KEY:
        block1_len_expected += 20
    if flags & HAS_BEN_KEY:
        details.append(spaces(indent) + 'ben address: {}'.format(AddressFromPubkeyHash(block1[block1_len_expected:block1_len_expected+20], TESTNET)))
        output.cert.ben_pkh = block1[block1_len_expected:block1_len_expected + 20]
        block1_len_expected += 20
    if flags & HAS_EXPIRATION_DATE:
        exdate = struct.unpack("<I", block1[block1_len_expected:block1_len_expected+4])[0]
        details.append(spaces(indent) + f'exp date: {exdate} ({time_str(exdate)})')
        output.cert.exp_date = exdate
        block1_len_expected += 4
    if flags & HAS_MINTING_LIMIT:
        limit = struct.unpack("<q", block1[block1_len_expected:block1_len_expected + 8])[0]
        details.append(spaces(indent) + f'minting limit: {ToCoins(limit)}')
        output.cert.minting_limit = limit
        block1_len_expected += 8
    if flags & HAS_DAILY_LIMIT:
        limit = struct.unpack("<q", block1[block1_len_expected:block1_len_expected + 8])[0]
        details.append(spaces(indent) + f'daily limit: {ToCoins(limit)}')
        output.cert.daily_limit = limit
        block1_len_expected += 8
    if flags & HAS_OTHER_DATA:
        block1_len_expected += 36
        output.cert.multisig_sh = block1[block1_len_expected:block1_len_expected + 20]
        if len(output.cert.multisig_sh) > 0:
            details.append(spaces(indent) + 'multisig address: {}'.format(AddressFromScriptHash(output.cert.multisig_sh, TESTNET)))
    print(spaces(indent) + 'flags: %08X (%s)' % (flags, flags_to_str(flags)))
    for d in details:
        print(d)
    print(spaces(indent) + 'keys: N = {} ({}), M = {} ({})'.format(output.cert.total_keys(), output.cert.total_keys_orig(), output.cert.required_keys(), output.cert.required_keys_orig()))
    print(spaces(indent) + f'is root cert: {output.cert.is_root_cert()}')
    Verify(len(block1) >= block1_len_expected, f'block1 invalid structure, expected: {block1_len_expected}, got: {len(block1)}')
    block1_hash = hash256(block1)
    recovered_pubkey = recover_public_key(block1_hash, block2, True)
    Verify(hash160(recovered_pubkey) == hash, 'invalid compact signature in certificate')


def get_root_pubkey():
    blockhash0 = call_func('getblockhash', [0])
    block0 = call_func('getblock', [blockhash0])
    txid0 = block0['tx'][0]
    tx0 = call_func('getrawtransaction', [txid0, 1])
    scrpubk0 = hex_str_to_bytes(tx0['vout'][0]['scriptPubKey']['hex'])
    if len(scrpubk0) > 0:
        (block1, rest) = ExtractNextFromScript(scrpubk0)
        if len(rest) > 0:
            (block2, rest) = ExtractNextFromScript(rest)
            if len(block1) == 1 and block1[0] == OP_RETURN and len(block2) == 33 and len(rest) == 0:
                return block2
    raise VerificationError('Failed to obtain root_pubkey')


def extract_address(full_address):
    fragments = ['(certificate p2pkh)', '(certificate p2pk)', '(p2pkh)', '(p2pk)', '(p2pkh_locked)', '(p2pk_locked)', '(p2sh)', '(p2sh_locked)']
    address = full_address.replace('address: ', '')
    for fr in fragments:
        if fr in address:
            return address.replace(' ' + fr, '')
    return address


def extract_reg_amount(vrftx):
    used_addresses = set()
    amount = ToCoins(0)
    for input in vrftx.inputs:
        Verify('moneybox)' not in input.prev_out.addr_details, 'not regular tx')
        used_addresses.add(extract_address(input.prev_out.addr_details))
    for output in vrftx.outputs:
        address = extract_address(output.addr_details)
        if address not in used_addresses:
            amount += output.amount
    return amount


class StatBC517(object):
    def __init__(self, mint_tx_count = 0, minted_amount = 0, reg_tx_count = 0, reg_amount = 0):
        self.mint_tx_count = mint_tx_count
        self.minted_amount = minted_amount
        self.reg_tx_count = reg_tx_count
        self.reg_amount = reg_amount

    def add(self, other):
        self.mint_tx_count += other.mint_tx_count
        self.minted_amount += other.minted_amount
        self.reg_tx_count += other.reg_tx_count
        self.reg_amount += other.reg_amount

this_block_stat = StatBC517()
this_month_stat = StatBC517()


def ignore_suffixes(str):
    suffixes = ['_locked', ' certificate']
    for suffix in suffixes:
        if str.endswith(suffix):
            str = str[:-len(suffix)]
    return str


def taxed_output(output, inputs):
    if output.scriptPubKey in [GraveScript1(TESTNET), GraveScript2()]:
        return False
    output_type = ignore_suffixes(output.addr_info.addr_type)
    for input in inputs:
        if output_type == ignore_suffixes(
                input.prev_out.addr_info.addr_type) and output.addr_info.addresses == input.prev_out.addr_info.addresses:
            return False
    return True


def verify_tx(tx_id, indent = 0, block_fee = None, block_moneybox_spent = None, print_stat_517 = False, raw_tx = None):
    origin_raw_tx = raw_tx
    tx = None
    if origin_raw_tx is not None:
        tx = call_func('decoderawtransaction', [origin_raw_tx])
    elif tx_id is not None:
        tx = call_func('getrawtransaction', [tx_id, 1])
        origin_raw_tx = call_func('getrawtransaction', [tx_id, 0])
    Verify(tx is not None, 'Invalid tx: getrawtransaction or decoderawtransaction failed')
    print('Will verify tx {} ...'.format(tx['txid']))

    vrfTx = CVrfTx(tx['txid'], tx['size'], tx['time'] if 'time' in tx else None)
    if 'blockhash' in tx:
        vrfTx.mined_in_block_num = call_func('getblockheader', [tx['blockhash']])['height']
    for i, vin in enumerate(tx['vin']):
        if 'coinbase' in vin:
            next_input = CVrfInput(nSequence = vin['sequence'], is_coinbase=True)
        else:
            next_input = CVrfInput(vin['txid'], vin['vout'], hex_str_to_bytes(vin['scriptSig']['hex']), vin['sequence'], i)
        fill_input(next_input)
        vrfTx.inputs.append(next_input)
    for vout in tx['vout']:
        next_output = CVrfOutput(vout['n'], satoshi_round(str(vout['value'])), hex_str_to_bytes(vout['scriptPubKey']['hex']))
        fill_output(next_output, vrfTx)
        vrfTx.outputs.append(next_output)

    ctransaction_from_hex = FromHex(CTransaction(), origin_raw_tx)
    for next_input in vrfTx.inputs:
        verify_input(next_input, ctransaction_from_hex, vrfTx, indent)
    for next_output in vrfTx.outputs:
        verify_output(next_output, vrfTx, indent)
    MIN_FEE = Decimal('0.00001')
    taxfree_cert_inputs_cnt = len([input for input in vrfTx.inputs if input.is_taxfree_cert])
    Verify(taxfree_cert_inputs_cnt in [0, 1], f'invalid taxfree_cert inputs count: {taxfree_cert_inputs_cnt}')
    has_taxfree_cert = (taxfree_cert_inputs_cnt == 1)
    Verify(len(vrfTx.inputs) > 0, 'no inputs')
    Verify(len(vrfTx.outputs) > 0, 'no outputs')
    coinbase_inputs_cnt = sum([inp.is_coinbase == True for inp in vrfTx.inputs])
    Verify(coinbase_inputs_cnt == 0 or len(vrfTx.inputs) == 1, f'coinbase tx must have 1 input, {len(vrfTx.inputs)} got')
    is_coinbase = vrfTx.inputs[0].is_coinbase
    total_amount_in = sum(input.prev_out.amount for input in vrfTx.inputs)
    total_amount_out = sum(output.amount for output in vrfTx.outputs)
    moneybox_amount_in = sum([input.prev_out.amount for input in vrfTx.inputs if input.prev_out.addr_details.endswith('(p2sh_moneybox)')])
    moneybox_amount_out = sum([output.amount for output in vrfTx.outputs if output.addr_details.endswith('(p2sh_moneybox)')])
    Verify(is_coinbase or moneybox_amount_in == 0 or moneybox_amount_in > moneybox_amount_out, 'moneybox_amount_in ({}) <= moneybox_amount_out ({})'.format(moneybox_amount_in, moneybox_amount_out))
    moneybox_spent = moneybox_amount_in - moneybox_amount_out
    fee = total_amount_in - total_amount_out
    print(spaces(indent) + f'Total input amount: {total_amount_in}')
    print(spaces(indent) + f'Total output amount: {total_amount_out}')
    print(spaces(indent) + f'Tx moneybox spent: {moneybox_spent}')
    print(spaces(indent) + 'Tx fee: {}, {} PLCU/KB'.format(fee if not is_coinbase else None, satoshi_round(fee * 1024 / vrfTx.size) if not is_coinbase and vrfTx.size > 0 else None))
    print(spaces(indent) + f'Tx time: {vrfTx.time} ({time_str(vrfTx.time)})')
    print(spaces(indent) + f'Has taxfree_cert: {has_taxfree_cert}')
    Verify(is_coinbase or block_fee is None, f'internal error: invalid usage of block_fee ({block_fee})')
    Verify(is_coinbase or block_moneybox_spent is None, f'internal error: invalid usage of block_moneybox_spent ({block_moneybox_spent})')
    # Verify(is_coinbase or fee >= MIN_FEE, 'Too small fee: {}'.format(fee))
    if not has_taxfree_cert and not is_coinbase:
        taxed_amount_out = sum(output.amount for output in vrfTx.outputs if taxed_output(output, vrfTx.inputs))
        burn1_amount_got = sum(output.amount for output in vrfTx.outputs if output.scriptPubKey == GraveScript1(TESTNET))
        burn2_amount_got = sum(output.amount for output in vrfTx.outputs if output.scriptPubKey == GraveScript2())
        (burn1_amount_calc, burn2_amount_calc) = GetBurnedValue(taxed_amount_out) if taxed_amount_out > 0 else (0,0)
        print(spaces(indent) + f'Total taxed output amount: {taxed_amount_out}')
        print(spaces(indent) + f'burn1_amount_calc: {burn1_amount_calc}')
        print(spaces(indent) + f'burn1_amount_got: {burn1_amount_got}')
        print(spaces(indent) + f'burn1 ratio got/calculated: {round(burn1_amount_got / burn1_amount_calc, 4) if burn1_amount_calc else None}')
        print(spaces(indent) + f'burn2_amount_calc: {burn2_amount_calc}')
        print(spaces(indent) + f'burn2_amount_got: {burn2_amount_got}')
        print(spaces(indent) + f'burn2 ratio got/calculated: {round(burn2_amount_got / burn2_amount_calc, 4) if burn2_amount_calc else None}')
        Verify(burn1_amount_got >= burn1_amount_calc, f'invalid burn1, calc: {burn1_amount_calc}, got: {burn1_amount_got}, taxed_amount_out: {taxed_amount_out}')
        Verify(burn2_amount_got >= burn2_amount_calc, f'invalid burn2, calc: {burn2_amount_calc}, got: {burn2_amount_got}, taxed_amount_out: {taxed_amount_out}')


    # Statistics for BC-517:
    global this_block_stat
    global this_month_stat
    if is_coinbase:
        this_block_stat = StatBC517()
    elif print_stat_517:
        mint_tx_count = 1 if moneybox_amount_in > 0 else 0
        minted_amount = moneybox_spent - fee if mint_tx_count else ToCoins(0)
        reg_tx_count = 1 if moneybox_amount_in == 0 else 0
        reg_amount = extract_reg_amount(vrfTx) if reg_tx_count else ToCoins(0)
        Verify(mint_tx_count + reg_tx_count == 1, 'internal error')
        local_stat = StatBC517(mint_tx_count, minted_amount, reg_tx_count, reg_amount)
        this_block_stat.add(local_stat)
        this_month_stat.add(local_stat)
        print(spaces(indent) + '----------------- This tx ---------------- This block ------------- This month --------')
        print(spaces(indent) + 'Mint tx count:    {:<25}{:<25}{:<25}'.format(local_stat.mint_tx_count, this_block_stat.mint_tx_count, this_month_stat.mint_tx_count))
        print(spaces(indent) + 'Minted amount:    {:<25}{:<25}{:<25}'.format(local_stat.minted_amount, this_block_stat.minted_amount, this_month_stat.minted_amount))
        print(spaces(indent) + 'Regular tx count: {:<25}{:<25}{:<25}'.format(local_stat.reg_tx_count, this_block_stat.reg_tx_count, this_month_stat.reg_tx_count))
        print(spaces(indent) + 'Transfer amount:  {:<25}{:<25}{:<25}'.format(local_stat.reg_amount, this_block_stat.reg_amount, this_month_stat.reg_amount))
        print(spaces(indent) + '---------------------------------------------------------------------------------------')

    if is_coinbase:
        print(spaces(indent) + f'Block moneybox spent: {block_moneybox_spent}')
        print(spaces(indent) + f'Block fee: {block_fee}')
        Verify(moneybox_amount_in == 0, f'non-zero moneybox_amount_in ({moneybox_amount_in}) in coinbase tx')
        if block_moneybox_spent is not None:
            Verify(moneybox_amount_out == block_moneybox_spent, f'moneybox_amount_out ({moneybox_amount_out}) != block_moneybox_spent ({block_moneybox_spent})')
        if block_fee is not None:
            pure_amount_out = total_amount_out - moneybox_amount_out
            subsidy = ToCoins(get_subsidy(vrfTx.mined_in_block_num, ToSatoshi(block_fee), 'testnet' if TESTNET else 'main'))
            Verify(pure_amount_out == subsidy, f'wrong miner reward: block: {vrfTx.mined_in_block_num}, block_fee: {block_fee}, subsidy expected: {subsidy}, pure_amount_out (subsidy got): {pure_amount_out}')
    return (fee, moneybox_spent, moneybox_amount_in == 0)


def walk_over_blocks(start_hash = None, forward = False, print_stat_517 = False):
    nextblockhash_tag = 'nextblockhash' if forward else 'previousblockhash'
    next_hash = start_hash if start_hash else (call_func('getblockhash', [101]) if forward else call_func('getbestblockhash', []))
    prev_tx_month = None
    while True:
        next_block = call_func('getblock', [next_hash])
        time = next_block['time']
        this_tx_month = datetime.utcfromtimestamp(time).strftime('%m') if time else None
        if prev_tx_month and prev_tx_month != this_tx_month:
            print('New month: {} --> {}'.format(prev_tx_month, this_tx_month))
            global this_month_stat
            this_month_stat = StatBC517()
        print('Will try next block {} (height {}, {}, {} transactions)...'.format(next_hash, next_block['height'], time_str(time), len(next_block['tx'])))
        block_fee = 0
        block_moneybox_spent = 0
        skipped = False
        for txid in next_block['tx'][1:]:
            if txid in exclude_transactions:
                print(f'Skip tx {txid}')
                skipped = True
            else:
                (tx_fee, tx_moneybox_spent, ignore_moneybox_spent) = verify_tx(txid, 1, print_stat_517=print_stat_517)
                block_fee += tx_fee
                if not ignore_moneybox_spent:
                    block_moneybox_spent += tx_moneybox_spent
        if not skipped:
            verify_tx(next_block['tx'][0], 1, block_fee=block_fee, block_moneybox_spent=block_moneybox_spent, print_stat_517=print_stat_517)
        else:
            print('Skip coinbase tx {} due to 1 or more skipped tx in the block {}'.format(next_block['tx'][0], next_hash))
        if nextblockhash_tag not in next_block:
            print(f'Completed! No {nextblockhash_tag} tag!')
            break
        prev_tx_month = this_tx_month
        next_hash = next_block[nextblockhash_tag]


def find_block_with_timestamp(timestamp, block_fr, block_to):
    next_hash_fr = call_func('getblockhash', [block_fr])
    next_hash_to = call_func('getblockhash', [block_to])
    next_block_fr = call_func('getblock', [next_hash_fr])
    next_block_to = call_func('getblock', [next_hash_to])
    assert_greater_than(block_to, block_fr)
    assert_greater_than(timestamp, next_block_fr['time'])
    assert_greater_than(next_block_to['time'], timestamp)
    if block_fr + 1 == block_to:
        print('block_fr: {}, {}, time {} {}'.format(block_fr, next_block_fr['hash'], next_block_fr['time'], time_str(next_block_fr['time'])))
        print('block_to: {}, {}, time {} {}'.format(block_to, next_block_to['hash'], next_block_to['time'], time_str(next_block_to['time'])))
        return
    mid = (block_fr + block_to) // 2
    next_hash_mi = call_func('getblockhash', [mid])
    next_block_mi = call_func('getblock', [next_hash_mi])
    time_mi = next_block_mi['time']
    print('mid block {}, {}'.format(mid, time_str(time_mi)))
    if time_mi < timestamp:
        find_block_with_timestamp(timestamp, mid, block_to)
    else:
        find_block_with_timestamp(timestamp, block_fr, mid)


def get_utxo_amount(txid, n):
    tx_parent = call_func('getrawtransaction', [txid, True])
    Verify(tx_parent is not None, 'parent tx for input {} was not found'.format(txid))
    Verify(n < len(tx_parent['vout']), 'invalid input {}:{}: index is out of range ({})'.format(txid, n, len(tx_parent['vout'])))
    vout = tx_parent['vout'][n]
    assert_equal(n, vout['n'])
    amount = satoshi_round(str(vout['value']))
    return amount


def get_coinbase_amount(txid, n):
    tx_parent = call_func('getrawtransaction', [txid, True])
    Verify(tx_parent is not None, 'parent tx for input {} was not found'.format(txid))
    Verify(n < len(tx_parent['vout']), 'invalid input {}:{}: index is out of range ({})'.format(txid, n, len(tx_parent['vout'])))
    vout = tx_parent['vout'][n]
    assert_equal(n, vout['n'])
    amount = satoshi_round(str(vout['value']))
    return amount


def calc_flow_in_tx(tx_id, print_func = print):
    tx = call_func('getrawtransaction', [tx_id, 1])
    Verify(tx is not None, 'Invalid tx: getrawtransaction failed')
    print_func('  Will process tx {} ...'.format(tx['txid']))
    is_coinbase = False
    amount = 0
    for vin in tx['vin']:
        if 'coinbase' in vin:
            Verify(len(tx['vin']) == 1, 'invalid coinbase tx')
            is_coinbase = True
        else:
            next_amount = get_coinbase_amount(vin['txid'], vin['vout'])
            print_func('    {} in {}:{}'.format(next_amount, vin['txid'], vin['vout']))
            amount += next_amount
    if is_coinbase:
        for vout in tx['vout']:
            if hex_str_to_bytes(vout['scriptPubKey']['hex'][0:2])[0] == OP_RETURN:
                continue
            next_amount = satoshi_round(str(vout['value']))
            print_func('    {} in coinbase, vout {}'.format(next_amount, vout['n']))
            amount += next_amount
    print_func(f'    amount in tx: {amount}')
    return amount


def calc_flow_in_block(block_height, print_func = print):
    block_hash = call_func('getblockhash', [block_height])
    block = call_func('getblock', [block_hash])
    print_func('Will process block {}: {}, {}, tx_count: {} ...'.format(block_height, block_hash, time_str(block['time']), len(block['tx'])))
    amount = 0
    for txid in block['tx']:
        amount += calc_flow_in_tx(txid, print_func)
    print_func(f'  amount in block: {amount}')
    return (len(block['tx']), amount)


def calc_flow_in_blocks(block_from, block_to, print_func = print):
    tx_count = 0
    amount = 0
    for i in range(block_from, block_to + 1):
        (this_tx_count, this_amount) = calc_flow_in_block(i, print_func)
        tx_count += this_tx_count
        amount += this_amount
        print_func(f'  summary tx_count: {tx_count}, amount: {amount}')
    print(f'Final result in block range [{block_from},{block_to}]: tx_count = {tx_count}, amount = {amount}')


def determine_testnet():
    blockchaininfo = call_func('getblockchaininfo', [])
    chain = blockchaininfo['chain']
    Verify(chain == 'main' or chain == 'test', f'unknown chain: {chain}')
    global TESTNET
    TESTNET = (chain == 'test')
    print(f'TESTNET: {TESTNET}')


def main():
    determine_testnet()
    args = sys.argv[1:]
    txid = None
    tx_hex = None
    next_block_hash = None
    forward = False
    ARG_TXID='--txid='
    ARG_TXHEX = '--tx='
    ARG_FROM_BLOCK = '--fromblock='
    ARG_FORWARD='--forward'

    def is_hash256_hex(str):
        return (is_hex_str(str) and len(str) == 64)

    for arg in args:
        if arg.startswith(ARG_TXID):
            txid = arg[len(ARG_TXID):]
            if not is_hash256_hex(txid):
                print(f'Invalid txid: {txid}')
                return
        elif arg.startswith(ARG_TXHEX):
            tx_hex = arg[len(ARG_TXHEX):]
            if not is_hex_str(tx_hex) or len(tx_hex) < 64:
                print(f'Invalid tx_hex: {tx_hex}')
                return
        elif arg.startswith(ARG_FROM_BLOCK):
            next_block_hash = arg[len(ARG_FROM_BLOCK):]
            if not is_hash256_hex(next_block_hash):
                print(f'Invalid next_block_hash: {next_block_hash}')
                return
        elif arg == ARG_FORWARD:
            forward = True
        else:
            print(f'Invalid argument: {arg}')
            return
    if (txid is not None) + (tx_hex is not None) + (next_block_hash is not None) > 1:
        print('Invalid arguments combination: txid, tx_hex, fromblock: only one is allowed')
        return
    if txid:
        verify_tx(txid)
    elif tx_hex:
        verify_tx(None, raw_tx=tx_hex)
    else:
        walk_over_blocks(next_block_hash, forward)


if __name__ == '__main__':
    try:
        main()
    except VerificationError as e:
        print(f'FAILED: {e}')
