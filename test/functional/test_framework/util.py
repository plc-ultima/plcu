#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpful routines for regression testing."""

from base64 import b64encode
from binascii import hexlify, unhexlify
from decimal import Decimal, ROUND_DOWN
import hashlib
import json
import logging
import os
import random
import re
from subprocess import CalledProcessError
import time
import string
import struct

from . import coverage
from .authproxy import AuthServiceProxy, JSONRPCException


COIN = 100000000 # 1 PLCU in satoshis
BASE_CB_AMOUNT = Decimal(15000)
CB_AMOUNT_AFTER_BLOCK_100 = Decimal('0.00005000')
MONEYBOX_GRANULARITY = Decimal(0)
DUST_OUTPUT_THRESHOLD = 54000
DEFAULT_TX_CONFIRM_TARGET = 6
GRAVE_ADDRESS_1_TESTNET = 'U1xtDNR5B9ik8qbMZETkH3jtfKp8BGPaHYSAD'  # P2PKH
GRAVE_ADDRESS_2_TESTNET = 'U1xtnGBTcBGqF44Fc2y316rrEEeg7wbDyD6Ne'  # P2SH(OP_INVALIDOPCODE)
GRAVE_ADDRESS_1_MAINNET = 'U1xPtGsuNviccXWGkTbERTxVAUd8RWtJ6243a'  # P2PKH
GRAVE_ADDRESS_2_MAINNET = 'U1xpMYYdQu72FxRFqW1mPSMWrEzka7DPwXkFM'  # P2SH(OP_INVALIDOPCODE)
VB_TOP_BITS = 0x20000000
TXIN_MARKER_COINBASE = 0xFFFFFFFF  # TxInMarkerType::coinbase in cpp
TXIN_MARKER_SUPERTX = 0  # TxInMarkerType::supertransaction in cpp
TXIN_MARKER_TOTAL_AMOUNT = 1  # TxInMarkerType::totalAmount in cpp
START_TOTAL_NG_BLOCK = 550  # consensus.startTotalNgBlock in cpp
CLTV_HEIGHT = 1351
MAX_FEE = Decimal('0.001')

GRAVE_ADDRESS_1 = GRAVE_ADDRESS_1_TESTNET
GRAVE_ADDRESS_2 = GRAVE_ADDRESS_2_TESTNET

ONE_HOUR = 3600
ONE_DAY = ONE_HOUR * 24
ONE_MONTH = ONE_DAY * 30
ONE_YEAR = ONE_DAY * 365

TOTAL_EMISSION_LIMIT = Decimal(2000000)

logger = logging.getLogger("TestFramework.utils")

# Assert functions
##################

def assert_fee_amount(fee, tx_size, fee_per_kB):
    """Assert the fee was in range"""
    target_fee = satoshi_round(tx_size * fee_per_kB / 1000)
    if fee < target_fee:
        raise AssertionError("Fee of %s PLCU too low! (Should be %s PLCU)" % (str(fee), str(target_fee)))
    # allow the wallet's estimation to be at most 2 bytes off
    if fee > (tx_size + 2) * fee_per_kB / 1000:
        raise AssertionError("Fee of %s PLCU too high! (Should be %s PLCU)" % (str(fee), str(target_fee)))

def assert_equal(thing1, thing2, *args):
    if thing1 != thing2 or any(thing1 != arg for arg in args):
        raise AssertionError("not(%s)" % " == ".join(str(arg) for arg in (thing1, thing2) + args))

def assert_almost_equal(thing1, thing2, epsilon):
    if abs(thing1 - thing2) > epsilon:
        raise AssertionError(f'{thing1} != {thing2} with epsilon {epsilon}')

def assert_greater_than(thing1, thing2):
    if thing1 <= thing2:
        raise AssertionError("%s <= %s" % (str(thing1), str(thing2)))

def assert_greater_than_or_equal(thing1, thing2):
    if thing1 < thing2:
        raise AssertionError("%s < %s" % (str(thing1), str(thing2)))

def assert_in(thing, container):
    if thing not in container:
        raise AssertionError('{} is not in {}'.format(thing, container))

def assert_not_in(thing, container):
    if thing in container:
        raise AssertionError('{} is in {}'.format(thing, container))

def assert_startswith(full_string, fragment):
    if not full_string.startswith(fragment):
        raise AssertionError('"{}" not starts with "{}"'.format(full_string, fragment))

def assert_raises(exc, fun, *args, **kwds):
    assert_raises_message(exc, None, fun, *args, **kwds)

def assert_raises_message(exc, message, fun, *args, **kwds):
    try:
        fun(*args, **kwds)
    except JSONRPCException:
        raise AssertionError("Use assert_raises_rpc_error() to test RPC failures")
    except exc as e:
        if message is not None and message not in e.error['message']:
            raise AssertionError("Expected substring not found, expected: {}, got: {}".format(message, e.error['message']))
    except Exception as e:
        raise AssertionError("Unexpected exception raised: " + type(e).__name__)
    else:
        raise AssertionError("No exception raised")

def assert_raises_process_error(returncode, output, fun, *args, **kwds):
    """Execute a process and asserts the process return code and output.

    Calls function `fun` with arguments `args` and `kwds`. Catches a CalledProcessError
    and verifies that the return code and output are as expected. Throws AssertionError if
    no CalledProcessError was raised or if the return code and output are not as expected.

    Args:
        returncode (int): the process return code.
        output (string): [a substring of] the process output.
        fun (function): the function to call. This should execute a process.
        args*: positional arguments for the function.
        kwds**: named arguments for the function.
    """
    try:
        fun(*args, **kwds)
    except CalledProcessError as e:
        if returncode != e.returncode:
            raise AssertionError("Unexpected returncode %i" % e.returncode)
        if output not in e.output:
            raise AssertionError("Expected substring not found, expected: {}, got: {}".format(output, e.output))
    else:
        raise AssertionError("No exception raised")

def assert_raises_rpc_error(code, message, fun, *args, **kwds):
    """Run an RPC and verify that a specific JSONRPC exception code and message is raised.

    Calls function `fun` with arguments `args` and `kwds`. Catches a JSONRPCException
    and verifies that the error code and message are as expected. Throws AssertionError if
    no JSONRPCException was raised or if the error code/message are not as expected.

    Args:
        code (int), optional: the error code returned by the RPC call (defined
            in src/rpc/protocol.h). Set to None if checking the error code is not required.
        message (string), optional: [a substring of] the error string returned by the
            RPC call. Set to None if checking the error string is not required.
        fun (function): the function to call. This should be the name of an RPC.
        args*: positional arguments for the function.
        kwds**: named arguments for the function.
    """
    if type(code) == list or type(message) == list:
        assert try_rpc_ex(code, message, fun, *args, **kwds), "No exception raised"
    else:
        assert try_rpc(code, message, fun, *args, **kwds), "No exception raised"

def try_rpc(code, message, fun, *args, **kwds):
    """Tries to run an rpc command.

    Test against error code and message if the rpc fails.
    Returns whether a JSONRPCException was raised."""
    try:
        fun(*args, **kwds)
    except JSONRPCException as e:
        # JSONRPCException was thrown as expected. Check the code and message values are correct.
        if (code is not None) and (code != e.error["code"]):
            raise AssertionError("Unexpected JSONRPC error code %i" % e.error["code"])
        if (message is not None) and (message not in e.error['message']):
            raise AssertionError("Expected substring not found, expected: {}, got: {}".format(message, e.error['message']))
        return True
    except Exception as e:
        raise AssertionError("Unexpected exception raised: " + type(e).__name__)
    else:
        return False

def try_rpc_ex(codes, messages, fun, *args, **kwds):
    """Tries to run an rpc command.

    Test against error codes and messages if the rpc fails.
    Returns whether a JSONRPCException was raised."""
    try:
        fun(*args, **kwds)
    except JSONRPCException as e:
        # JSONRPCException was thrown as expected. Check the code and message values are correct.
        received_code = e.error['code']
        received_message = e.error['message']
        if codes and received_code not in codes:
            raise AssertionError(f'Unexpected JSONRPC error code, got: {received_code}, expected: {codes}')
        if messages:
            found = False
            for message in messages:
                if not message or message in received_message:
                    found = True
                    break
            if not found:
                raise AssertionError(f'Expected substring not found, got: {received_message}, expected: {messages}')
        return True
    except Exception as e:
        raise AssertionError('Unexpected exception raised: ' + type(e).__name__)
    else:
        return False

def assert_is_hex_string(string):
    try:
        int(string, 16)
    except Exception as e:
        raise AssertionError(
            "Couldn't interpret %r as hexadecimal; raised: %s" % (string, e))

def assert_is_hash_string(string, length=64):
    if not isinstance(string, str):
        raise AssertionError("Expected a string, got type %r" % type(string))
    elif length and len(string) != length:
        raise AssertionError(
            "String of length %d expected; got %d" % (length, len(string)))
    elif not re.match('[abcdef0-9]+$', string):
        raise AssertionError(
            "String %r contains invalid characters for a hash." % string)

def reverse(s):
    return s[::-1]

def is_hex_str(s):
    return all(c in string.hexdigits for c in s)

def assert_array_result(object_array, to_match, expected, should_not_find=False):
    """
        Pass in array of JSON objects, a dictionary with key/value pairs
        to match against, and another dictionary with expected key/value
        pairs.
        If the should_not_find flag is true, to_match should not be found
        in object_array
        """
    if should_not_find:
        assert_equal(expected, {})
    num_matched = 0
    for item in object_array:
        all_match = True
        for key, value in to_match.items():
            if item[key] != value:
                all_match = False
        if not all_match:
            continue
        elif should_not_find:
            num_matched = num_matched + 1
        for key, value in expected.items():
            if item[key] != value:
                raise AssertionError("%s : expected %s=%s" % (str(item), str(key), str(value)))
            num_matched = num_matched + 1
    if num_matched == 0 and not should_not_find:
        raise AssertionError("No objects matched %s" % (str(to_match)))
    if num_matched > 0 and should_not_find:
        raise AssertionError("Objects were found %s" % (str(to_match)))

# Utility functions
###################

def check_json_precision():
    """Make sure json library being used does not lose precision converting PLCU values"""
    n = Decimal("20000000.00000003")
    satoshis = int(json.loads(json.dumps(float(n))) * 1.0e8)
    if satoshis != 2000000000000003:
        raise RuntimeError("JSON encode/decode loses precision")

def count_bytes(hex_string):
    return len(bytearray.fromhex(hex_string))

def bytes_to_hex_str(byte_str):
    return hexlify(byte_str).decode('ascii')

def hex_str_to_bytes(hex_str):
    return unhexlify(hex_str.encode('ascii'))

def str_to_b64str(string):
    return b64encode(string.encode('utf-8')).decode('ascii')

def satoshi_round(amount):
    return Decimal(amount).quantize(Decimal('0.00000001'), rounding=ROUND_DOWN)

def wait_until(predicate, *, attempts=float('inf'), timeout=float('inf'), lock=None, print_func=None):
    if attempts == float('inf') and timeout == float('inf'):
        timeout = 120
    attempt = 0
    timeout += time.time()

    while attempt < attempts and time.time() < timeout:
        if lock:
            with lock:
                if predicate():
                    return
        else:
            if predicate():
                return
        attempt += 1
        time.sleep(0.05)

    if print_func:
        logger.debug(print_func())

    # Print the cause of the timeout
    assert_greater_than(attempts, attempt)
    assert_greater_than(timeout, time.time())
    raise RuntimeError('Unreachable')

# RPC/P2P connection constants and functions
############################################

# The maximum number of nodes a single test can spawn
MAX_NODES = 8
# Don't assign rpc or p2p ports lower than this
PORT_MIN = 11000
# The number of ports to "reserve" for p2p and rpc, each
PORT_RANGE = 5000

class PortSeed:
    # Must be initialized with a unique integer for each process
    n = None

def get_rpc_proxy(url, node_number, timeout=None, coveragedir=None):
    """
    Args:
        url (str): URL of the RPC server to call
        node_number (int): the node number (or id) that this calls to

    Kwargs:
        timeout (int): HTTP timeout in seconds

    Returns:
        AuthServiceProxy. convenience object for making RPC calls.

    """
    proxy_kwargs = {}
    if timeout is not None:
        proxy_kwargs['timeout'] = timeout

    proxy = AuthServiceProxy(url, **proxy_kwargs)
    proxy.url = url  # store URL on proxy for info

    coverage_logfile = coverage.get_filename(
        coveragedir, node_number) if coveragedir else None

    return coverage.AuthServiceProxyWrapper(proxy, coverage_logfile)

def p2p_port(n):
    assert(n <= MAX_NODES)
    return PORT_MIN + n + (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)

def rpc_port(n):
    return PORT_MIN + PORT_RANGE + n + (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)

def rpc_url(datadir, i, rpchost=None):
    rpc_u, rpc_p = get_auth_cookie(datadir)
    host = '127.0.0.1'
    port = rpc_port(i)
    if rpchost:
        parts = rpchost.split(':')
        if len(parts) == 2:
            host, port = parts
        else:
            host = rpchost
    return "http://%s:%s@%s:%d" % (rpc_u, rpc_p, host, int(port))

# Node functions
################

def initialize_datadir(dirname, n):
    datadir = os.path.join(dirname, "node" + str(n))
    if not os.path.isdir(datadir):
        os.makedirs(datadir)
    with open(os.path.join(datadir, "plcultima.conf"), 'w', encoding='utf8') as f:
        f.write("regtest=1\n")
        f.write("port=" + str(p2p_port(n)) + "\n")
        f.write("rpcport=" + str(rpc_port(n)) + "\n")
        f.write("listenonion=0\n")
    return datadir

def get_datadir_path(dirname, n):
    return os.path.join(dirname, "node" + str(n))

def get_auth_cookie(datadir):
    user = None
    password = None
    if os.path.isfile(os.path.join(datadir, "plcultima.conf")):
        with open(os.path.join(datadir, "plcultima.conf"), 'r', encoding='utf8') as f:
            for line in f:
                if line.startswith("rpcuser="):
                    assert user is None  # Ensure that there is only one rpcuser line
                    user = line.split("=")[1].strip("\n")
                if line.startswith("rpcpassword="):
                    assert password is None  # Ensure that there is only one rpcpassword line
                    password = line.split("=")[1].strip("\n")
    if os.path.isfile(os.path.join(datadir, "regtest", ".cookie")):
        with open(os.path.join(datadir, "regtest", ".cookie"), 'r') as f:
            userpass = f.read()
            split_userpass = userpass.split(':')
            user = split_userpass[0]
            password = split_userpass[1]
    if user is None or password is None:
        raise ValueError("No RPC credentials")
    return user, password

def log_filename(dirname, n_node, logname):
    return os.path.join(dirname, "node" + str(n_node), "regtest", logname)

def get_bip9_status(node, key):
    info = node.getblockchaininfo()
    return info['bip9_softforks'][key]

def set_node_times(nodes, t):
    for node in nodes:
        node.setmocktime(t)

def disconnect_nodes(from_connection, node_num):
    for peer_id in [peer['id'] for peer in from_connection.getpeerinfo() if "testnode%d" % node_num in peer['subver']]:
        from_connection.disconnectnode(nodeid=peer_id)

    for _ in range(50):
        if [peer['id'] for peer in from_connection.getpeerinfo() if "testnode%d" % node_num in peer['subver']] == []:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("timed out waiting for disconnect")

def connect_nodes(from_connection, node_num):
    ip_port = "127.0.0.1:" + str(p2p_port(node_num))
    from_connection.addnode(ip_port, "onetry")
    # poll until version handshake complete to avoid race conditions
    # with transaction relaying
    while any(peer['version'] == 0 for peer in from_connection.getpeerinfo()):
        time.sleep(0.1)

def connect_nodes_bi(nodes, a, b):
    connect_nodes(nodes[a], b)
    connect_nodes(nodes[b], a)

def sync_blocks(rpc_connections, *, wait=1, timeout=60):
    """
    Wait until everybody has the same tip.

    sync_blocks needs to be called with an rpc_connections set that has least
    one node already synced to the latest, stable tip, otherwise there's a
    chance it might return before all nodes are stably synced.
    """
    # Use getblockcount() instead of waitforblockheight() to determine the
    # initial max height because the two RPCs look at different internal global
    # variables (chainActive vs latestBlock) and the former gets updated
    # earlier.
    maxheight = max(x.getblockcount() for x in rpc_connections)
    start_time = cur_time = time.time()
    while cur_time <= start_time + timeout:
        tips = [r.waitforblockheight(maxheight, int(wait * 1000)) for r in rpc_connections]
        if all(t["height"] == maxheight for t in tips):
            if all(t["hash"] == tips[0]["hash"] for t in tips):
                return
            raise AssertionError("Block sync failed, mismatched block hashes:{}".format(
                                 "".join("\n  {!r}".format(tip) for tip in tips)))
        cur_time = time.time()
    raise AssertionError("Block sync to height {} timed out:{}".format(
                         maxheight, "".join("\n  {!r}".format(tip) for tip in tips)))

def sync_chain(rpc_connections, *, wait=1, timeout=60):
    """
    Wait until everybody has the same best block
    """
    while timeout > 0:
        best_hash = [x.getbestblockhash() for x in rpc_connections]
        if best_hash == [best_hash[0]] * len(best_hash):
            return
        time.sleep(wait)
        timeout -= wait
    raise AssertionError("Chain sync failed: Best block hashes don't match")

def sync_mempools(rpc_connections, *, wait=1, timeout=60):
    """
    Wait until everybody has the same transactions in their memory
    pools
    """
    while timeout > 0:
        pool = set(rpc_connections[0].getrawmempool())
        num_match = 1
        for i in range(1, len(rpc_connections)):
            if set(rpc_connections[i].getrawmempool()) == pool:
                num_match = num_match + 1
        if num_match == len(rpc_connections):
            return
        time.sleep(wait)
        timeout -= wait
    logger.info('mempools: ' + ','.join([str(len(conn.getrawmempool())) for conn in rpc_connections]))
    raise AssertionError("Mempool sync failed")

# Transaction/Block functions
#############################

def find_output(node, txid, amount, tx_json=None):
    """
    Return index to output of txid with value amount
    Raises exception if there is none.
    """
    txdata = tx_json if tx_json else node.getrawtransaction(txid, 1)
    for i in range(len(txdata["vout"])):
        if txdata["vout"][i]["value"] == amount:
            return i
    raise RuntimeError("find_output txid %s : %s not found" % (txid, str(amount)))

def find_output_by_address(node, address, txid=None, tx_raw=None):
    """
    Return index to output of txid with address
    Raises exception if there is none.
    """
    assert txid or tx_raw
    txdata = tx_raw if tx_raw else node.getrawtransaction(txid, 1)
    for i in range(len(txdata["vout"])):
        addresses = txdata["vout"][i]["scriptPubKey"]['addresses']
        if len(addresses) == 1 and addresses[0] == address:
            return i
    raise RuntimeError("find_output_by_address txid %s : %s not found" % (txid, address))

def gather_inputs(from_node, amount_needed, confirmations_required=1):
    """
    Return a random set of unspent txouts that are enough to pay amount_needed
    """
    assert(confirmations_required >= 0)
    utxo = from_node.listunspent(confirmations_required)
    random.shuffle(utxo)
    inputs = []
    total_in = Decimal("0.00000000")
    while total_in < amount_needed and len(utxo) > 0:
        t = utxo.pop()
        total_in += t["amount"]
        inputs.append({"txid": t["txid"], "vout": t["vout"], "address": t["address"]})
    if total_in < amount_needed:
        raise RuntimeError("Insufficient funds: need %d, have %d" % (amount_needed, total_in))
    return (total_in, inputs)

def make_change(from_node, amount_in, amount_out, fee):
    """
    Create change output(s), return them
    """
    outputs = {}
    amount = amount_out + fee
    change = amount_in - amount
    if change > amount * 2:
        # Create an extra change output to break up big inputs
        change_address = from_node.getnewaddress()
        # Split change in two, being careful of rounding:
        outputs[change_address] = Decimal(change / 2).quantize(Decimal('0.00000001'), rounding=ROUND_DOWN)
        change = amount_in - amount - outputs[change_address]
    if change > 0:
        outputs[from_node.getnewaddress()] = change
    return outputs

def random_transaction(nodes, amount, min_fee, fee_increment, fee_variants):
    """
    Create a random transaction.
    Returns (txid, hex-encoded-transaction-data, fee)
    """
    from_node = random.choice(nodes)
    to_node = random.choice(nodes)
    fee = min_fee + fee_increment * random.randint(0, fee_variants)

    (total_in, inputs) = gather_inputs(from_node, amount + fee)
    (burn1, burn2, rest) = BurnedAndChangeAmount(total_in - fee, amount)
    outputs = make_change(from_node, total_in - burn1 - burn2, amount, fee)
    outputs[to_node.getnewaddress()] = float(amount)
    outputs[GRAVE_ADDRESS_1] = burn1
    outputs[GRAVE_ADDRESS_2] = burn2

    rawtx = from_node.createrawtransaction(inputs, outputs)
    signresult = from_node.signrawtransaction(rawtx)
    txid = from_node.sendrawtransaction(signresult["hex"], True)

    return (txid, signresult["hex"], fee)

# Helper to create at least "count" utxos
# Pass in a fee that is sufficient for relay and mining new transactions.
def create_confirmed_utxos(fee, node, count, min_amount=None, gen_blocks_first=True):
    to_generate = (int(0.5 * count) + 101) if gen_blocks_first else 0
    while to_generate > 0:
        node.generate(min(25, to_generate))
        to_generate -= 25
    utxos = node_listunspent(node, minimumAmount=min_amount)
    iterations = count - len(utxos)
    addr1 = node.getnewaddress()
    addr2 = node.getnewaddress()
    if iterations <= 0:
        return utxos
    for i in range(iterations):
        if len(utxos) == 0:
            while (node.getmempoolinfo()['size'] > 0):
                node.generate(1)
            utxos = node_listunspent(node, minimumAmount=min_amount)
        t = utxos.pop()
        inputs = []
        inputs.append({"txid": t["txid"], "vout": t["vout"]})
        outputs = {}
        (burn1, burn2, send_value) = BurnedAndChangeAmount(t['amount'] - fee)
        send_value = satoshi_round(send_value / 2)
        outputs[addr1] = send_value
        outputs[addr2] = send_value
        outputs[GRAVE_ADDRESS_1] = burn1
        outputs[GRAVE_ADDRESS_2] = burn2
        raw_tx = node.createrawtransaction(inputs, outputs)
        signed_tx = node.signrawtransaction(raw_tx)["hex"]
        node.sendrawtransaction(signed_tx)

    while (node.getmempoolinfo()['size'] > 0):
        node.generate(1)

    utxos = node_listunspent(node, minimumAmount=min_amount)
    assert_greater_than_or_equal(len(utxos), count)
    return utxos

# Create large OP_RETURN txouts that can be appended to a transaction
# to make it large (helper for constructing large transactions).
def gen_return_txouts():
    # Some pre-processing to create a bunch of OP_RETURN txouts to insert into transactions we create
    # So we have big transactions (and therefore can't fit very many into each block)
    # create one script_pubkey
    script_pubkey = "6a4d0200"  # OP_RETURN OP_PUSH2 512 bytes
    for i in range(512):
        script_pubkey = script_pubkey + "01"
    # concatenate 128 txouts of above script_pubkey which we'll insert before the txout for change
    txouts = "83" # hex(128) + 2 (burn) + 1 (change)
    for k in range(128):
        # add txout value
        txouts = txouts + "0000000000000000"
        # add length of script_pubkey
        txouts = txouts + "fd0402"
        # add script_pubkey
        txouts = txouts + script_pubkey
    return txouts

def create_tx(node, coinbase, to_address, amount):
    (burn1, burn2, rest) = BurnedAndChangeAmount(amount)
    inputs = [{"txid": coinbase, "vout": 0}]
    outputs = {to_address: rest, GRAVE_ADDRESS_1: burn1, GRAVE_ADDRESS_2: burn2}
    rawtx = node.createrawtransaction(inputs, outputs)
    signresult = node.signrawtransaction(rawtx)
    assert_equal(signresult["complete"], True)
    return signresult["hex"]

# Create a spend of each passed-in utxo, splicing in "txouts" to each raw
# transaction to make it large.  See gen_return_txouts() above.
def create_lots_of_big_transactions(node, txouts, utxos, num, fee):
    addr = node.getnewaddress()
    txids = []
    while len(txids) < num:
        t = utxos.pop()
        inputs = [{"txid": t["txid"], "vout": t["vout"]}]
        outputs = {}
        if t['amount'] < fee + ToCoins(DUST_OUTPUT_THRESHOLD):
            continue
        (burn1, burn2, change) = BurnedAndChangeAmount(t['amount'] - fee)
        outputs[addr] = change
        outputs[GRAVE_ADDRESS_1] = burn1
        outputs[GRAVE_ADDRESS_2] = burn2
        rawtx = node.createrawtransaction(inputs, outputs)
        newtx = rawtx[0:92]
        newtx = newtx + txouts
        newtx = newtx + rawtx[94:]
        signresult = node.signrawtransaction(newtx, None, None, "NONE")
        txid = node.sendrawtransaction(signresult["hex"], True)
        txids.append(txid)
    return txids

def mine_large_block(node, utxos=None):
    # generate a 66k transaction,
    # and 14 of them is close to the 1MB block limit
    num = 14
    txouts = gen_return_txouts()
    utxos = utxos if utxos is not None else []
    if len(utxos) < num:
        utxos.clear()
        utxos.extend(node.listunspent())
    fee = 100 * node.getnetworkinfo()["relayfee"]
    create_lots_of_big_transactions(node, txouts, utxos, num, fee=fee)
    node.generate(1)

def hashToHex(hash):
    return format(hash, '064x')

def getVarIntLen(value):
    if value >= 0x100000000:
        return 9
    elif value >= 0x10000:
        return 5
    elif value >= 0x100 - 3:
        return 3
    elif value >= 0:
        return 1
    else:
        assert (0) # invalid value

def ToCoins(amount):
    if type(amount) == type(''):
        amount = Decimal(amount)
    if type(amount) == type(Decimal(0)):
        return amount.quantize(Decimal('.00000001'), rounding=ROUND_DOWN)
    if type(amount) == type(int(0)):
        return Decimal(amount) / COIN
    print('amount: {}, type: {}'.format(amount, type(amount)))
    assert(0)

def ToSatoshi(amount):
    if type(amount) == type(''):
        amount = Decimal(amount)
    if type(amount) == type(int(0)):
        return amount
    if type(amount) == type(Decimal(0)):
        return int(amount * COIN)
    print('amount: {}, type: {}'.format(amount, type(amount)))
    assert(0)

def generate_many_blocks(node, count, limit_per_call = 100):
    logger.debug(f'Will generate {count} blocks: {node.getblockcount()} --> {node.getblockcount() + count}')
    assert_greater_than(count, 0)
    assert_greater_than(limit_per_call, 0)
    blocks = []
    while count > 0:
        next_portion = min(count, limit_per_call)
        count -= next_portion
        blocks.extend(node.generate(next_portion))
    return blocks

def node_listunspent(node, minconf=1, maxconf=9999999, addresses=[], include_unsafe=True, minimumAmount=None, maximumAmount=None, maximumCount=None, minimumSumAmount=None):
    query_options = {}
    if minimumAmount is not None:
        query_options['minimumAmount'] = minimumAmount
    if maximumAmount is not None:
        query_options['maximumAmount'] = maximumAmount
    if maximumCount is not None:
        query_options['maximumCount'] = maximumCount
    if minimumSumAmount is not None:
        query_options['minimumSumAmount'] = minimumSumAmount
    return node.listunspent(minconf, maxconf, addresses, include_unsafe, query_options)

def find_burned_amount_in_tx(tx, burn_exists=True):
    burned = 0
    outputs = 0
    for detail in tx['details']:
        if detail['address'] == GRAVE_ADDRESS_1 or detail['address'] == GRAVE_ADDRESS_2:
            burned += detail['amount']
            outputs += 1
    if burn_exists:
        assert_greater_than(abs(burned), 0)
        assert_equal(outputs, 2)
    elif burn_exists is not None:
        assert_equal(burned, 0)
        assert_equal(outputs, 0)
    return burned

# total_out_amount == input_amount - fee
def BurnedAndChangeAmount(total_out_amount, dest_amount = 0, keep_sum = True):
    if total_out_amount == 0:
        return (0, 0, 0)
    assert_greater_than(total_out_amount, dest_amount)
    assert_greater_than_or_equal(dest_amount, 0)
    # percent = 0.03
    # change = total_out_amount / (1 + percent) - dest_amount
    # burn = total_out_amount * percent / (1 + percent)
    change = ToCoins(total_out_amount * 100 / 103 - dest_amount)
    burn_total = total_out_amount * 3 / 103
    burn1 = satoshi_round(ToCoins(burn_total * 2 / 3))
    burn2 = satoshi_round(ToCoins(burn_total / 3))
    if keep_sum:
        if change + burn1 + burn2 < total_out_amount - dest_amount and change == 0:
            change += Decimal('0.00000001')
        if change + burn1 + burn2 < total_out_amount - dest_amount:
            burn1 += Decimal('0.00000001')
        if change + burn1 + burn2 < total_out_amount - dest_amount:
            burn2 += Decimal('0.00000001')
        assert_equal(change + burn1 + burn2, total_out_amount - dest_amount)
    assert_greater_than(change, 0)
    return (burn1, burn2, change)

def GetBurnedValue(pure_received_amount):
    assert_greater_than(pure_received_amount, 0)
    return (satoshi_round(ToCoins(pure_received_amount) * 2 / 100), satoshi_round(ToCoins(pure_received_amount) / 100))

def skip_spam_from_tx(tx_json):
    del tx_json['hex']
    vout = tx_json['vout']
    vout[:] = [x for x in vout if x['scriptPubKey']['type'] != 'nulldata']

def print_tx_verbose(node, txid=None, tx_hex=None, tx_json=None, indent=0, skip_spam=False, skip_parents=False, comment=None):
    assert txid or tx_hex or tx_json
    tx_json = tx_json if tx_json else (node.decoderawtransaction(tx_hex) if tx_hex else node.getrawtransaction(txid, 1))
    if comment:
        logger.debug(comment)
    for input in tx_json['vin']:
        parent_tx_id = input["txid"]
        if skip_parents:
            logger.debug(f'{" " * indent}parent tx {parent_tx_id}: skipped')
        elif int(input["txid"], 16):
            logger.debug(f'{" " * indent}parent tx: {node.getrawtransaction(parent_tx_id, 1)}')
        else:
            logger.debug(f'{" " * indent}parent tx {parent_tx_id}: zero input')
    if skip_spam:
        skip_spam_from_tx(tx_json)
    logger.debug(f'{" " * indent}this tx: {tx_json}')

def print_block_verbose(node, block_num=None, hash=None, indent=0):
    assert block_num or hash
    hash = hash if hash else node.getblockhash(block_num)
    block = node.getblock(hash, 1)
    logger.debug(f'{" "*indent}block {block_num}: {block}')
    tx_cb = node.getrawtransaction(block['tx'][0], 1)
    logger.debug(f'{" " * (indent+2)}coinbase tx: {tx_cb}')
    for txid in block['tx'][1:]:
        print_tx_verbose(node, txid=txid, indent=indent+2)
        logger.debug(f'{" " * (indent+2)}---')
    logger.debug(f'{" " * indent}----- block {block_num}')

def print_mempool_verbose(node, indent=0):
    mempool = node.getrawmempool()
    logger.debug(f'{" "*indent}mempool: {mempool}')
    for txid in mempool:
        print_tx_verbose(node, txid=txid, indent=indent+2)
        logger.debug(f'{" " * (indent+2)}---')
    logger.debug(f'{" " * indent}----- mempool')

def verify_tx_sent(node, txid):
    assert_in(txid, node.getrawmempool())
    fee = -node.gettransaction(txid)['fee']
    assert_greater_than(fee, 0)
    assert_greater_than(MAX_FEE, fee)

def read_uint_from_buffer(buffer):
    buf_len = len(buffer)
    if buf_len == 0:
        value = 0
    elif buf_len == 1:
        value = struct.unpack('<B', buffer)[0]
    elif buf_len == 2:
        value = struct.unpack('<H', buffer)[0]
    elif buf_len <= 4:
        buffer += b'\x00' * (4 - buf_len)
        value = struct.unpack('<I', buffer)[0]
    elif buf_len <= 8:
        buffer += b'\x00' * (8 - buf_len)
        value = struct.unpack('<Q', buffer)[0]
    else:
        assert 0, f'invalid buf_len: {buf_len}'
    return value

def extract_total_amount_from_scriptsig(scriptsig_bin):
    data_len = int(scriptsig_bin[0])
    data = scriptsig_bin[1:]
    assert_equal(data_len, len(data))
    value = read_uint_from_buffer(data)
    return value
