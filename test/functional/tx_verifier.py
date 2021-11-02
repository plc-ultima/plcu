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
from minting import *
from minting_testcases import ALLOWED_DELTA_REWARD

RPC_USER = 'xyu'
RPC_PASSW = 'xyu'
RPC_URL = 'http://127.0.0.1:8555/'

TESTNET = None  # will be determined automatically
genezis_pubkey0 = None

MONEYBOX_GRAN_MAIN = {
    0: 10,
    895104: 1000,
}
MONEYBOX_GRAN_TESTNET = {
    0: 10,
    600768: 100,
    606816: 1000,
}

exclude_transactions = set(
    [
        '9c1b429f144997afec37ffb4bb86f693bbdb161c0c39fb29296c9d810cf047bf', # testnet, with OP_CHECKDESTINATIONVERIFY (in output, not spent)
        '42c635b1946022d1236ecca461b6a91bcd790a2bd2fa769f7782973a9550d2c8', # testnet, too high fee (moneybox robbery) (Minting 3.0/funding)
        '874a88ec120dbcef5fe53afc4e7a4db9d03ca79801d5c85ac061006bb60c209c', # testnet, robbery (Minting 3.0/funding)
        '736367770f660ef0a42752e975d7a1801105b2bf5803e474acb1ecf3bdccbc12', # testnet, robbery (Minting 3.0/funding)
        '17ed2f81c26ac90c3363baa90df1dd9498263fdfd23c480a308912d3eb47eefe', # testnet, robbery (Minting 3.0/funding)
        '1e511a291cccb5ba5cd12c3dc6e038a5f0d6ff98446c288d9aa6cc76db04fa40', # testnet, tx v3 without active_time
        'ec0fafbf8606a0e4339aa665eb111fd420d1eae411b762a8493096cffd47e29c', # testnet, invalid reward (locked for 3 days)
        '58cc84d4a62509c4a8de7f05dfb9a56cac7d90d9e232bc4181034188396ef42e', # testnet, invalid reward
        'd4209b278e56683fd7568739a0c893a4545fff339a66b2aaf119cf4525fe6157', # testnet, invalid reward
        '8332e300e0b22df021108bd5ffd7fe14d6d987b96410650f6c622ddc8747aff6', # testnet, invalid reward
        '8d0d60aa731f2a4c2b507db937bf453a0c5f30b947e24f39a80ea3d9b05b1250', # testnet, invalid reward
        'd7792b3f143962267b9c8ee503cae7f60c079365a0346a2aee6b56b02ac2256d', # main, only funding inputs
        '7ee60b28737c39d61f70b66d8f9e6a98a81d57f726227a0f8ceb5b41c97eb631', # main, only funding inputs
        '172866f10cc7be9e2f1e66695323ce3da4ab71bf32ff855a5f09b662e983be74', # main, rewadr for 0.5y, locked for 0.49y, needs drift 2.5d
    ]
)

# RULES_VERSION:
# 1: stable branch, reward is calculated for any user outputs, reward per output
# 2: dev branch, reward is calculated for locked user outputs, reward per transaction
# 3: stable branch, (1) with:
#     * user amount is taken from one locked user output with max lock time
#     * percent in certificate is per year; reward must be corrected due to user output lock interval

RULES_VERSION = 3
assert (RULES_VERSION in [1,2,3])

def IsOp(script, op):
    return len(script) == 1 and script[0] == op

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

    def suffix(lock_timepoint, cert):
        return ('_locked' if lock_timepoint else '') + (' certificate' if cert else '')

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
        return AddrInfo('p2pk' + suffix(lock_timepoint, cert), [ops[0]], lock_timepoint)

    if len(ops) == 5 and \
            IsOp(ops[0], OP_DUP) and \
            IsOp(ops[1], OP_HASH160) and \
            len(ops[2]) == 20 and \
            IsOp(ops[3], OP_EQUALVERIFY) and \
            IsOp(ops[4], OP_CHECKSIG):
        return AddrInfo('p2pkh' + suffix(lock_timepoint, cert), [ops[2]], lock_timepoint)

    if len(ops) == 3 and \
            IsOp(ops[0], OP_HASH160) and \
            len(ops[1]) == 20 and \
            IsOp(ops[2], OP_EQUAL):
        if ops[1] == hash160(bytearray([int(OP_CHECKREWARD)])):
            return AddrInfo('p2sh_moneybox' + suffix(lock_timepoint, cert), [ops[1]], lock_timepoint)
        else:
            return AddrInfo('p2sh' + suffix(lock_timepoint, cert), [ops[1]], lock_timepoint)

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
        return AddrInfo('multisig {} of {}'.format(M, N) + suffix(lock_timepoint, cert), pkh_list, lock_timepoint)

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
            self.addr_details = address_details(self.scriptPubKey)

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
    tx_parent = call_func('getrawtransaction', [input.txid, True])
    Verify(tx_parent is not None, 'parent tx for input {} was not found'.format(input.txid))
    Verify(input.n < len(tx_parent['vout']), 'invalid input {}:{}: index is out of range ({})'.format(input.txid, input.n, len(tx_parent['vout'])))
    vout = tx_parent['vout'][input.n]
    input.prev_out.amount = satoshi_round(str(vout['value']))
    input.prev_out.scriptPubKey = hex_str_to_bytes(vout['scriptPubKey']['hex'])
    input.prev_out.addr_details  = address_details(input.prev_out.scriptPubKey)
    assert_equal(input.n, vout['n'])
    txout = call_func('gettxout', [input.txid, input.n, True])
    input.prev_out.spent = txout is None
    if 'time' in tx_parent:
        input.prev_out.time = tx_parent['time']


def address_details(scriptPubKey):
    ai = GetAddressInfo(scriptPubKey)
    Verify(ai.addr_type != 'other', 'unknown tx type, scriptPubKey: {}'.format(bytes_to_hex_str(scriptPubKey)))
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
    indent2 = indent + 1
    if input.is_coinbase:
        print(' ' * indent * 2 + 'Input coinbase:')
        print(' ' * indent2 * 2 + 'nSequence: %08x' % (input.nSequence))
        return
    print(' ' * indent * 2 + 'Input {}:{}:'.format(input.txid, input.n))
    print(' ' * indent2 * 2 + '{}'.format(input.prev_out.addr_details))
    print(' ' * indent2 * 2 + 'amount: {}'.format(input.prev_out.amount))
    print(' ' * indent2 * 2 + 'scriptPubKey: {}'.format(bytes_to_hex_str(input.prev_out.scriptPubKey)))
    print(' ' * indent2 * 2 + 'scriptSig: {}'.format(bytes_to_hex_str(input.scriptSig)))
    print(' ' * indent2 * 2 + 'nSequence: %08x' % (input.nSequence))
    print(' ' * indent2 * 2 + 'time: {} ({})'.format(input.prev_out.time, time_str(input.prev_out.time)))
    print(' ' * indent2 * 2 + 'input is spent: {}'.format(input.prev_out.spent))
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
                print(' ' * indent2 * 2 + 'CERT{} {}:{} was checked earlier, skipping...'.format(i, cert_txid, cert_n))
                continue
            print(' ' * indent2 * 2 + 'CERT{} {}:{} details:'.format(i, cert_txid, cert_n))
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
            verify_output(cert_output, cert_vrftx, indent2 + 1, True)
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
            Verify(white_inputs_count >= 1, 'no user (white) inputs')
            white_pkh_set = set()
            white_pkh_pairs_set = set()
            for input in white_inputs:
                ai = GetAddressInfo(input.prev_out.scriptPubKey)
                if len(ai.addresses) == 1:
                    white_pkh_set.add(ai.addresses[0])
                elif ai.addr_type == 'ab_minting' or ai.addr_type == 'ab_minting_ex':
                    white_pkh_set.add(ai.addresses[0])
                elif ai.addr_type == 'funding':
                    if ai.addresses[1] == ai.addresses[2]:
                        white_pkh_set.add(ai.addresses[0])
                    else:
                        white_pkh_pairs_set.add((ai.addresses[1], ai.addresses[2]))
            Verify(len(white_pkh_set) == 1, 'missing/different/ambigious white inputs: {}'.format([AddressFromPubkeyHash(h, TESTNET) for h in white_pkh_set]))
            white_pkh = list(white_pkh_set)[0]
            for elem in white_pkh_pairs_set:
                Verify(white_pkh in elem, 'different/ambigious white inputs in funding inputs, {}, {}'.format(AddressFromPubkeyHash(white_pkh, TESTNET), [AddressFromPubkeyHash(h, TESTNET) for h in elem]))
            white_locked_outputs = []
            white_change_outputs = []
            other_outputs = []
            white_output_with_max_locktime = None
            max_lock_timepoint = 0

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
                        if not white_output_with_max_locktime or ai.lock_timepoint > max_lock_timepoint:
                            max_lock_timepoint = ai.lock_timepoint
                            white_output_with_max_locktime = output
                    else:
                        other_outputs.append(output)
                elif ai.addr_type == 'funding':
                    if ai.addresses[0] == white_pkh or (ai.addresses[1] == white_pkh and ai.addresses[2] == white_pkh):
                        white_change_outputs.append(output)
                    else:
                        other_outputs.append(output)
                elif ai.addr_type in ['ab_minting', 'ab_minting_ex']:
                    if ai.addresses[0] == white_pkh or (ai.addresses[1] == white_pkh and ai.addresses[2] == white_pkh):
                        white_locked_outputs.append(output)
                        if not white_output_with_max_locktime or ai.lock_timepoint > max_lock_timepoint:
                            max_lock_timepoint = ai.lock_timepoint
                            white_output_with_max_locktime = output
                    else:
                        other_outputs.append(output)
                else:
                    other_outputs.append(output)

            white_locked_outputs_count = len(white_locked_outputs)
            white_change_outputs_count = len(white_change_outputs)
            if RULES_VERSION == 2:
                Verify(white_locked_outputs_count <= white_inputs_count, 'white_locked_outputs_count > white_inputs_count')
                Verify(white_change_outputs_count <= 1, 'white_change_outputs_count > 1')
            else:
                Verify(white_locked_outputs_count + white_change_outputs_count <= white_inputs_count + 2, 'white_outputs_count > white_inputs_count + 2')
            Verify(white_locked_outputs_count + white_change_outputs_count >= 1, 'white_locked_outputs_count == white_change_outputs_count == 0')
            white_input_amount = sum(inp.prev_out.amount for inp in white_inputs)
            white_locked_output_amount = sum(outp.amount for outp in white_locked_outputs)
            white_change_output_amount = sum(outp.amount for outp in white_change_outputs)
            white_output_amount = white_locked_output_amount + white_change_output_amount
            white_amount_with_max_locktime = white_output_with_max_locktime.amount if white_output_with_max_locktime else white_change_output_amount
            other_output_amounts = [outp.amount for outp in other_outputs]
            other_output_amount_sum = sum(other_output_amounts)
            other_output_amount_max = max(other_output_amounts)
            Verify(white_locked_output_amount <= white_input_amount, 'white_locked_output_amount > white_input_amount')

            reward_got = other_output_amount_sum
            locked_period = 0

            if RULES_VERSION == 1:
                reward_calc = ToCoins(white_output_amount * percent)
                Verify(0, 'too old RULES_VERSION!')
            elif RULES_VERSION == 2:
                reward_calc = ToCoins(white_locked_output_amount * percent)
                Verify(0, 'too old RULES_VERSION!')
            elif RULES_VERSION == 3:
                if max_lock_timepoint:
                    locked_period = max_lock_timepoint - vrftx.time
                    reward_calc = ToCoins(ToSatoshi(white_amount_with_max_locktime * percent) * locked_period // 3600 // 24 // 365)
                else:
                    reward_calc = ToCoins(white_amount_with_max_locktime * percent)
                reward_got = other_output_amount_max
            else:
                Verify(0, 'invalid RULES_VERSION')

            max_fee = Decimal(10)
            indent3 = indent2 + 1
            print(' ' * indent2 * 2 + 'Minting 3.0/funding calculation:')
            print(' ' * indent3 * 2 + 'RULES_VERSION: {}'.format(RULES_VERSION))
            print(' ' * indent3 * 2 + 'red address: {}'.format(AddressFromPubkeyHash(user_pkhs[0], TESTNET)))
            print(' ' * indent3 * 2 + 'white address: {}'.format(AddressFromPubkeyHash(white_pkh, TESTNET)))
            print(' ' * indent3 * 2 + 'white_input_amount: {}'.format(white_input_amount))
            print(' ' * indent3 * 2 + 'white_locked_output_amount: {}'.format(white_locked_output_amount))
            print(' ' * indent3 * 2 + 'white_change_output_amount: {}'.format(white_change_output_amount))
            print(' ' * indent3 * 2 + 'white_amount_with_max_locktime: {}'.format(white_amount_with_max_locktime))
            print(' ' * indent3 * 2 + 'max_lock_timepoint: {}, locked_period: {} ({}d, {}y)'.format(max_lock_timepoint, locked_period, round(locked_period/3600/24, 2), round(locked_period/3600/24/365, 2)))
            print(' ' * indent3 * 2 + 'other_output_amount_sum: {}'.format(other_output_amount_sum))
            print(' ' * indent3 * 2 + 'other_output_amount_max: {}'.format(other_output_amount_max))
            print(' ' * indent3 * 2 + 'percent: {} (or {} %)'.format(percent, percent * 100))
            print(' ' * indent3 * 2 + 'reward_calc: {}'.format(reward_calc))
            print(' ' * indent3 * 2 + 'reward_got: {}'.format(reward_got))
            print(' ' * indent3 * 2 + 'ratio calculated/got: {}'.format(round(reward_calc / reward_got, 4)))
            print(' ' * indent3 * 2 + 'moneybox_input_amount: {}'.format(moneybox_input_amount))
            print(' ' * indent3 * 2 + 'moneybox_output_amount: {}'.format(moneybox_output_amount))
            if RULES_VERSION == 3:
                Verify(reward_got <= reward_calc, 'robbery!')
                # print(' ' * indent3 * 2 + 'moneybox_fee: {}'.format(moneybox_input_amount - moneybox_output_amount - reward_got))
                # Verify(moneybox_input_amount - moneybox_output_amount <= reward_got + max_fee, 'moneybox robbery!')
                pass
            else:
                Verify(0, 'bad RULES_VERSION')
        else:
            usermoney_inputs_si = [inp for inp in vrftx.inputs if PKHFromScript(inp.prev_out.scriptPubKey) == user_pkhs[0]]
            usermoney_outputs_si = [outp for outp in vrftx.outputs if PKHFromScript(outp.scriptPubKey) == user_pkhs[0]]
            usermoney_inputs_mu = [inp for inp in vrftx.inputs if ca3_cert_out.cert.multisig_sh and SHFromScript(inp.prev_out.scriptPubKey) == ca3_cert_out.cert.multisig_sh]
            usermoney_outputs_mu = [outp for outp in vrftx.outputs if ca3_cert_out.cert.multisig_sh and SHFromScript(outp.scriptPubKey) == ca3_cert_out.cert.multisig_sh]
            Verify((len(usermoney_inputs_si) > 0) + (len(usermoney_inputs_mu) > 0) == 1, 'no user inputs or both singlesig and multisig user inputs got ({}, {})'.format(len(usermoney_inputs_si), len(usermoney_inputs_mu)))
            Verify((len(usermoney_outputs_si) > 0) + (len(usermoney_outputs_mu) > 0) == 1,'no user outputs or both singlesig and multisig user outputs got')
            Verify((len(usermoney_inputs_si) > 0) + (len(usermoney_outputs_mu) > 0) == 1,'both singlesig and multisig user inputs/outputs got')
            singlesig = len(usermoney_inputs_si) > 0
            usermoney_inputs = usermoney_inputs_si if len(usermoney_inputs_si) > 0 else usermoney_inputs_mu
            usermoney_outputs = usermoney_outputs_si if len(usermoney_outputs_si) > 0 else usermoney_outputs_mu
            usermoney_inputs_cnt = len(usermoney_inputs)
            usermoney_outputs_cnt = len(usermoney_outputs)
            Verify(usermoney_outputs_cnt <= usermoney_inputs_cnt, 'usermoney_outputs ({}) > usermoney_inputs ({})'.format(usermoney_outputs_cnt, usermoney_inputs_cnt))
            Verify(usermoney_outputs_cnt >= 1, 'no usermoney_outputs, tx: {}'.format(vrftx))
            time_now = vrftx.time
            # Calculate reward:
            green_flag = bool(root_cert_out.cert.flags & FAST_MINTING)
            user_input_amount = sum(inp.prev_out.amount for inp in usermoney_inputs)
            user_output_amount = sum(outp.amount for outp in usermoney_outputs)
            Verify(user_output_amount >= user_input_amount, 'user_output_amount ({}) < user_input_amount ({})'.format(user_output_amount, user_input_amount))
            ben_outputs = [outp for outp in vrftx.outputs if ben_pkh is not None and PKHFromScript(outp.scriptPubKey) == ben_pkh]
            other_outputs = [outp for outp in vrftx.outputs if outp not in usermoney_outputs and outp not in moneybox_outputs and outp not in ben_outputs]
            Verify(len(ben_outputs) + len(other_outputs) <= usermoney_outputs_cnt, 'Too many ben and other outputs: {} + {} > {}'.format(len(ben_outputs), len(other_outputs), usermoney_outputs_cnt))
            user_pays_fee = len(other_outputs) > 0
            ben_and_other_outputs = ben_outputs + other_outputs
            ben_amount = sum(outp.amount for outp in ben_outputs)
            other_amount = sum(outp.amount for outp in other_outputs)
            ben_and_other_amount = sum(outp.amount for outp in ben_and_other_outputs)
            for usermoney_input in usermoney_inputs:
                Verify(usermoney_input.prev_out.time is not None, 'missing -txindex or usermoney input transaction not in block')
                Verify(usermoney_input.prev_out.time < time_now, 'invalid age of user input: {} ({}) >= {} ({})'.format(usermoney_input.prev_out.time, time_str(usermoney_input.prev_out.time), time_now, time_str(time_now)))
            usermoney_ages = [time_now - usermoney_input.prev_out.time for usermoney_input in usermoney_inputs]
            Verify(ca3_cert_out.time < time_now, 'invalid age of ca3 cert: {} ({}) >= {} ({})'.format(ca3_cert_out.time, time_str(ca3_cert_out.time), time_now, time_str(time_now)))
            ca3_age = time_now - ca3_cert_out.time
            Verify(ca3_cert_out.cert.exp_date is None or ca3_cert_out.cert.exp_date + 23*3600 >= time_now, 'ca3 cert is expired')
            reward_calc = calc_reward(usermoney_inputs, usermoney_ages, ca3_age, green_flag, percent)
            reward_got = user_output_amount + ben_and_other_amount - user_input_amount
            Verify(ca3_cert_out.cert.minting_limit is None or ca3_cert_out.cert.minting_limit >= reward_got, 'reward_got > minting_limit')
            Verify(ca3_cert_out.cert.daily_limit is None or ca3_cert_out.cert.daily_limit >= user_input_amount, 'user_input_amount > daily_limit')
            indent3 = indent2 + 1
            print(' ' * indent2 * 2 + 'Minting calculation:')
            print(' ' * indent3 * 2 + 'sigmodel: {}'.format('singlesig' if singlesig else 'multisig'))
            print(' ' * indent3 * 2 + 'minting for address: {}'.format(AddressFromPubkeyHash(user_pkhs[0], TESTNET) if singlesig else AddressFromScriptHash(ca3_cert_out.cert.multisig_sh, TESTNET)))
            print(' ' * indent3 * 2 + 'user_input_amount: {}'.format(user_input_amount))
            print(' ' * indent3 * 2 + 'user_output_amount: {}'.format(user_output_amount))
            print(' ' * indent3 * 2 + 'ben_amount: {}'.format(ben_amount))
            print(' ' * indent3 * 2 + 'other_amount: {}'.format(other_amount))
            print(' ' * indent3 * 2 + 'ca3_age: {} (or {} h, or {} days)'.format(ca3_age, round(ca3_age / 3600, 2), round(ca3_age / 3600 / 24, 2)))
            for i, usermoney_age in enumerate(usermoney_ages):
                print(' ' * indent3 * 2 + 'usermoney_age[{}]: {} (or {} h, or {} days)'.format(i, usermoney_age, round(usermoney_age / 3600, 2), round(usermoney_age / 3600 / 24, 2)))
            print(' ' * indent3 * 2 + 'green_flag: {}'.format(green_flag))
            print(' ' * indent3 * 2 + 'percent: {} (or {} %)'.format(percent, percent * 100))
            print(' ' * indent3 * 2 + 'user_pays_fee: {}'.format(user_pays_fee))
            print(' ' * indent3 * 2 + 'reward amount calculated: {}'.format(reward_calc))
            print(' ' * indent3 * 2 + 'reward amount got: {}'.format(reward_got))
            print(' ' * indent3 * 2 + 'reward ratio calculated/got: {}'.format(round(reward_calc / reward_got, 4) if reward_got else 'INDEFINITE'))
            Verify(reward_got <= reward_calc, 'robbery!')
            if reward_calc != reward_got and (not reward_got or reward_calc / reward_got >= 1.1):
                print(' ' * indent3 * 2 + 'too high generosity ratio!!!')
        vrftx.cert_txs.append(root_cert_vrftx)
        vrftx.cert_txs.append(ca3_cert_vrftx)
        vrftx.mint_calculated = True
    elif txtype == 'funding' or txtype == 'ab_minting' or txtype == 'ab_minting_ex':
        ops = ExtractAllFromScript(input.scriptSig)
        Verify(len(ops) == 2 or len(ops) == 6, 'Input {} ({}:{}): invalid scriptSig len when spending {}: {}'.format(input.i, input.txid, input.n, txtype, len(ops)))
        print(' ' * indent2 * 2 + 'keys count used to spend {}: {}'.format(txtype, 1 if len(ops) == 2 else 2))
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
        print(' ' * indent2 * 2 + 'skip check for spending p2sh output')
    elif txtype == 'return':
        Verify(False, 'Forbidden to reference on return output type')
    else:
        Verify(False, 'trying to spend unknown or not implemented output type: {}'.format(txtype))


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
    indent2 = indent + 1
    print('  ' * indent + 'Output {}:'.format(output.n))
    print('  ' * indent2 + '{}'.format(output.addr_details))
    if 'certificate' in output.addr_details:
        verify_cert(output, vrftx, indent2 + 1)
        if output.spent:
            print('  ' * indent2 + 'cert is revoked')
    print('  ' * indent2 + 'amount: {}'.format(output.amount))
    print('  ' * indent2 + 'scriptPubKey: {}'.format(bytes_to_hex_str(output.scriptPubKey)))
    if print_time:
        print('  ' * indent2 + 'time: {} ({})'.format(vrftx.time, time_str(vrftx.time)))
    print('  ' * indent2 + 'output is spent: {}'.format(output.spent))


def verify_cert(output, vrftx, indent = 0):
    (parts, rest) = ExtractPartFromScript(output.scriptPubKey, 3)
    if len(parts) != 3:
        print('  ' * indent + 'invalid certificate structure, less than 3 operands, got: {}'.format(len(parts)))
        return
    block1 = parts[0]
    block2 = parts[1]
    block3 = parts[2]
    if len(block1) < 24 or len(block2) != 65 or not IsOp(block3, OP_2DROP):
        print('  ' * indent + 'invalid certificate structure (step2)')
        return
    ai = GetAddressInfo(rest)
    txtype = ai.addr_type
    hash = ai.addresses[0]
    if txtype != 'p2pkh':
        print('  ' * indent + 'invalid certificate structure, not p2pkh')
        return
    if not any(PKHFromScript(inp.prev_out.scriptPubKey) == hash for inp in vrftx.inputs):
        print('  ' * indent + 'output address {} not found in inputs'.format(AddressFromPubkeyHash(hash, TESTNET)))
    flags = struct.unpack("<I", block1[0:4])[0]
    output.cert = CVrfCert(output, flags)
    details = []
    block1_len_expected = 4
    for i in range(output.cert.total_keys()):
        details.append('  ' * indent + 'child {} address: {}'.format(i, AddressFromPubkeyHash(block1[block1_len_expected:block1_len_expected + 20], TESTNET)))
        output.cert.children.append(block1[block1_len_expected:block1_len_expected + 20])
        block1_len_expected += 20
    if flags & HAS_DEVICE_KEY:
        block1_len_expected += 20
    if flags & HAS_BEN_KEY:
        details.append('  ' * indent + 'ben address: {}'.format(AddressFromPubkeyHash(block1[block1_len_expected:block1_len_expected+20], TESTNET)))
        output.cert.ben_pkh = block1[block1_len_expected:block1_len_expected + 20]
        block1_len_expected += 20
    if flags & HAS_EXPIRATION_DATE:
        exdate = struct.unpack("<I", block1[block1_len_expected:block1_len_expected+4])[0]
        details.append('  ' * indent + 'exp date: {} ({})'.format(exdate, time_str(exdate)))
        output.cert.exp_date = exdate
        block1_len_expected += 4
    if flags & HAS_MINTING_LIMIT:
        limit = struct.unpack("<q", block1[block1_len_expected:block1_len_expected + 8])[0]
        details.append('  ' * indent + 'minting limit: {}'.format(ToCoins(limit)))
        output.cert.minting_limit = limit
        block1_len_expected += 8
    if flags & HAS_DAILY_LIMIT:
        limit = struct.unpack("<q", block1[block1_len_expected:block1_len_expected + 8])[0]
        details.append('  ' * indent + 'daily limit: {}'.format(ToCoins(limit)))
        output.cert.daily_limit = limit
        block1_len_expected += 8
    if flags & HAS_OTHER_DATA:
        block1_len_expected += 36
        output.cert.multisig_sh = block1[block1_len_expected:block1_len_expected + 20]
        if len(output.cert.multisig_sh) > 0:
            details.append('  ' * indent + 'multisig address: {}'.format(AddressFromScriptHash(output.cert.multisig_sh, TESTNET)))
    print('  ' * indent + 'flags: %08X (%s)' % (flags, flags_to_str(flags)))
    for d in details:
        print(d)
    print('  ' * indent + 'keys: N = {} ({}), M = {} ({})'.format(output.cert.total_keys(), output.cert.total_keys_orig(), output.cert.required_keys(), output.cert.required_keys_orig()))
    print('  ' * indent + 'is root cert: {}'.format(output.cert.is_root_cert()))
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


def verify_tx(tx_id, indent = 0, block_fee = None, block_moneybox_spent = None, print_stat_517 = False):
    origin_raw_tx = None

    # some tx:
    #origin_raw_tx = '0200000002f743f57b1d62f68136b4eed6c50365f176e2e2d9d9a3ab2546e7307fb629776f02000000b0473044022051120563679aee53e0cfec9876fec7609ed613a436da670acb930fea49efb69402202f33400806ea6dca133a000bf0f613b066588f6a5727cd5975b85898997902b7012102e3ca9d4377d8afa97f6cda10d0b9398f18a22db0516e604f1c723cfc561d70b820901a1ed334bb6046b501ef0722b1943af800af7d7aa5eecc30e354b8bc6feb6c51205e306d312a9a992b9309e93d8d0df0f529fed7117145a4cce031f57caa80670d5101c0ffffffff1689e40d040b1a330ecd0ea11f7bca5d80a5a99fbf631c1989685a9514e0acac000000006a47304402202ae9bbfe8ebec7088eda24841316308fd385d183cf92909c6f8c4dc61c949f550220123d3d9551b396be9002205c533258da5d5468d7fc9cb29989a1e883fa62ec22012102e3ca9d4377d8afa97f6cda10d0b9398f18a22db0516e604f1c723cfc561d70b8ffffffff03004e7253000000001976a91415c9c6621ff988129c51ca6b46f396fd06631e4a88ac0a679200000000001976a9142dee4de7a3fffde26e0dc6f075b149eb51c1ade988ac50feb3320000000017a9140d37a6fe661c22c9a39e0404dc0306afefec75bd8700000000'

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
    Verify(len(vrfTx.inputs) > 0, 'no inputs')
    Verify(len(vrfTx.outputs) > 0, 'no outputs')
    coinbase_inputs_cnt = sum([inp.is_coinbase == True for inp in vrfTx.inputs])
    Verify(coinbase_inputs_cnt == 0 or len(vrfTx.inputs) == 1, 'coinbase tx must have 1 input, {} got'.format(len(vrfTx.inputs)))
    is_coinbase = vrfTx.inputs[0].is_coinbase
    total_amount_in = sum(input.prev_out.amount for input in vrfTx.inputs)
    total_amount_out = sum(output.amount for output in vrfTx.outputs)
    moneybox_amount_in = sum([input.prev_out.amount for input in vrfTx.inputs if input.prev_out.addr_details.endswith('(p2sh_moneybox)')])
    moneybox_amount_out = sum([output.amount for output in vrfTx.outputs if output.addr_details.endswith('(p2sh_moneybox)')])
    Verify(is_coinbase or moneybox_amount_in == 0 or moneybox_amount_in > moneybox_amount_out, 'moneybox_amount_in ({}) <= moneybox_amount_out ({})'.format(moneybox_amount_in, moneybox_amount_out))
    moneybox_spent = moneybox_amount_in - moneybox_amount_out
    fee = total_amount_in - total_amount_out
    print('  ' * indent + 'Total input amount: {}'.format(total_amount_in))
    print('  ' * indent + 'Total output amount: {}'.format(total_amount_out))
    print('  ' * indent + 'Tx moneybox spent: {}'.format(moneybox_spent))
    print('  ' * indent + 'Tx fee: {}, {} PLCU/KB'.format(fee if not is_coinbase else None, satoshi_round(fee * 1024 / vrfTx.size) if not is_coinbase and vrfTx.size > 0 else None))
    print('  ' * indent + 'Tx time: {} ({})'.format(vrfTx.time, time_str(vrfTx.time)))
    Verify(is_coinbase or block_fee is None, 'internal error: invalid usage of block_fee ({})'.format(block_fee))
    Verify(is_coinbase or block_moneybox_spent is None, 'internal error: invalid usage of block_moneybox_spent ({})'.format(block_moneybox_spent))
    # Verify(is_coinbase or fee >= MIN_FEE, 'Too small fee: {}'.format(fee))

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
        print('  ' * indent + '----------------- This tx ---------------- This block ------------- This month --------')
        print('  ' * indent + 'Mint tx count:    {:<25}{:<25}{:<25}'.format(local_stat.mint_tx_count, this_block_stat.mint_tx_count, this_month_stat.mint_tx_count))
        print('  ' * indent + 'Minted amount:    {:<25}{:<25}{:<25}'.format(local_stat.minted_amount, this_block_stat.minted_amount, this_month_stat.minted_amount))
        print('  ' * indent + 'Regular tx count: {:<25}{:<25}{:<25}'.format(local_stat.reg_tx_count, this_block_stat.reg_tx_count, this_month_stat.reg_tx_count))
        print('  ' * indent + 'Transfer amount:  {:<25}{:<25}{:<25}'.format(local_stat.reg_amount, this_block_stat.reg_amount, this_month_stat.reg_amount))
        print('  ' * indent + '---------------------------------------------------------------------------------------')

    if is_coinbase:
        print('  ' * indent + 'Block moneybox spent: {}'.format(block_moneybox_spent))
        print('  ' * indent + 'Block fee: {}'.format(block_fee))
        Verify(moneybox_amount_in == 0, 'non-zero moneybox_amount_in ({}) in coinbase tx'.format(moneybox_amount_in))
        if block_moneybox_spent is not None:
            Verify(moneybox_amount_out == block_moneybox_spent, 'moneybox_amount_out ({}) != block_moneybox_spent ({})'.format(moneybox_amount_out, block_moneybox_spent))
        if block_fee is not None:
            pure_amount_out = total_amount_out - moneybox_amount_out
            Verify(pure_amount_out == max(Decimal('0.005'), satoshi_round(block_fee / 2)), 'wrong miner reward: block_fee: {}, pure_amount_out: {}'.format(block_fee, pure_amount_out))
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
                print('Skip tx {}'.format(txid))
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
            print('Completed! No {} tag!'.format(nextblockhash_tag))
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
    print_func('    amount in tx: {}'.format(amount))
    return amount


def calc_flow_in_block(block_height, print_func = print):
    block_hash = call_func('getblockhash', [block_height])
    block = call_func('getblock', [block_hash])
    print_func('Will process block {}: {}, {}, tx_count: {} ...'.format(block_height, block_hash, time_str(block['time']), len(block['tx'])))
    amount = 0
    for txid in block['tx']:
        amount += calc_flow_in_tx(txid, print_func)
    print_func('  amount in block: {}'.format(amount))
    return (len(block['tx']), amount)


def calc_flow_in_blocks(block_from, block_to, print_func = print):
    tx_count = 0
    amount = 0
    for i in range(block_from, block_to + 1):
        (this_tx_count, this_amount) = calc_flow_in_block(i, print_func)
        tx_count += this_tx_count
        amount += this_amount
        print_func('  summary tx_count: {}, amount: {}'.format(tx_count, amount))
    print('Final result in block range [{},{}]: tx_count = {}, amount = {}'.format(block_from, block_to, tx_count, amount))


def determine_testnet():
    block_hash_0 = call_func('getblockhash', [0])
    BLOCKHASH0_TEST = '37a749bbaddeb18e1abd1a86c2087152f2b399a62c47d14fbd75cbc7b24c27af'
    BLOCKHASH0_PROD = '4769e9264d0c9214e2bd1c741a22dad2bc099d989441dccc2a31a7a8dee2ac9c'
    assert (block_hash_0 == BLOCKHASH0_TEST or block_hash_0 == BLOCKHASH0_PROD)
    global TESTNET
    TESTNET = (block_hash_0 == BLOCKHASH0_TEST)
    print('TESTNET: {}'.format(TESTNET))


def main():
    determine_testnet()

    # calc_flow_in_blocks(736176,764605) # 1 Apr - 1 May 2020
    # calc_flow_in_blocks(764606, 789406)  # 1 May - 26 May 2020
    # calc_flow_in_blocks(764606, 794417)  # 1 May - 1 June 2020
    # return

    # TIMESTAMP = 1577836800  # 1 Jan 2020
    # TIMESTAMP = 1580515200  # 1 Feb 2020
    # TIMESTAMP = 1585699200  # 1 Apr 2020
    # TIMESTAMP = 1588291200  # 1 May 2020
    # TIMESTAMP = 1590969600  # 1 Jun 2020
    # TIMESTAMP = 1598918400  # 1 Sep 2020
    # find_block_with_timestamp(TIMESTAMP, 100, call_func('getblockcount', []))
    # return

    # pure multisig:
    # verify_tx('767e51ddf1c417111c90229e71c029b70c10ce8497a21ed883a152ab4ddc9239')
    # 2 user inputs:
    # verify_tx('70319012a9bcb63e1ab3544dbde0e23eb6c9736498004eef3dd27094ad9d41e6')
    # p2pk:
    # verify_tx('08d379d00b9910e47a24abb201b128d0e7358870c2ffb00c0fcd766d2a02d89d')
    # too high generosity ratio:
    # verify_tx('5be43fb5cad539f0d8e3cc290e459149ef5270b604e721e4f3e0ff55b3fc6380')
    # Funding example tx from https://confluence.global-fintech.com/display/BLOC/Funding+TX
    # verify_tx('9b6f25bf7d935e9b3ff51785950a99be71a0142108e85a678d7de160d3fd33fc')
    # Funding tx:
    # verify_tx('672765bc90b219383a3e7adf33c9aea3f2e750374457bf119d19800a4e3e9066')
    # With blacklist:
    # verify_tx('b1bfb021c5ad45053323952175e0cbf738d42721e897822fc98c1577ca583c47')
    # p2sh output
    # verify_tx('50f8a0e5425d79222dcf521699e0d8e292548c55b819c5f20f06b57c31c13b7e')
    # spending p2sh output, minting multisig:
    # verify_tx('ec25e75ae1126ff35985b876690dd46835f46692e0736980f540cf63331e5291')
    # spending funding_multisig
    # verify_tx('01b545dd1c4249992f9b2f2ef976f9388bb792bf3ffac5314466f9edcb683127')
    # mainnet, user pays fee:
    # verify_tx('3a583a5f0515c5e6744243e6fa80540248acc6d02babe5de6f41831e5314b42d', print_stat_517=True)
    # verify_tx('64ce2dc9c6135b809c13518d07e1a2f6c742f7a4c980c408f008ea316ea35e07')  # testnet, ab-minting
    # verify_tx('8b6792d79cac30fb7c9776ce362007aec7ee7a8c0803179a66d189eecb3acd25')  # user-multisig
    # verify_tx('ec326a1f7dcb3da570c411481c8643b03882730da473a294c35f500d80952dda')  # funding
    # verify_tx('f4f0122a5fd7ac2a481829bff7b7f27a94549d7920e20f5c9cbd827b0b674603') # main, ab_minting input
    # verify_tx('56256f3ff46ca96940fbd0c766eafc8f8c088cc1c87f90047d5fb05f3d2a895f') # main, ab_minting_ex input
    # verify_tx('2e827ffa1a5959eb6ebdf160ee53c706ef047bfe530cdf86009cc6d6e126d72d') # main, funding input
    # verify_tx('d7792b3f143962267b9c8ee503cae7f60c079365a0346a2aee6b56b02ac2256d') # main, only funding inputs


    # next_hash = 'f42cca790d62a14eba00ed4dd282b5f8d97cc8d94762dda96566fbdb3d993c49' # mainnet, the first block Jan 2020
    # next_hash = 'c5d15c286b5aa22b8467f3dd15c97e3201219a78fc067a62f44e5c19f085a5a6' # mainnet, the first block Feb 2020
    # next_hash = '57b3fd679279b143de7814192471863caebd147ec5973241845f5f2a1df2e88f' # mainnet, the first block Jun 2020
    # next_hash = 'b962c886850f599984dde9708801ed2e952b0a4fd401ffb2859f436b454723fa' # mainnet, the first block Sep 2020
    next_hash = None
    walk_over_blocks(next_hash)


if __name__ == '__main__':
    try:
        main()
    except VerificationError as e:
        print('FAILED: {}'.format(e))
