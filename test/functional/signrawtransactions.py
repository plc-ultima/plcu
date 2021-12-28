#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test transaction signing using the signrawtransaction RPC."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.key import *
from test_framework.script import *


def scriptPubKeyHexForSecret(secret):
    key = CECKey()
    key.set_secretbytes(hex_str_to_bytes(secret))
    key.set_compressed(True)
    return bytes_to_hex_str(GetP2PKHScript(hash160(key.get_pubkey())))


class SignRawTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def successful_signing_test(self):
        """Create and sign a valid raw transaction with one input.

        Expected results:

        1) The transaction has a complete set of signatures
        2) No script verification error occurred"""
        privKeys = ['AwSa5beJfAQFnX8pK4rMJvxcnGsvioLw6UobCPgPvFLsyoDSRwUue5z', 'AwSa53S4TqqVghsKaALZ3W4AMsG9a5qWWtuQ1WCk7Rmd6a2xvkRgMQ1']
        secrets = ['72b12fd1d01ff094544466fe41856a2ec21b38e2eb3d57f8af1e3a6427bf76d1', '621f1bca43fa20752612dd3250ad3265082d7f461a9ae749b6544c30f0745d40']

        inputs = [
            # Valid pay-to-pubkey scripts
            {'txid': 'f73ab7aa5c3ffae730f5b11f16550a7cebfe5bb69ff0e7a297f17f799173e574', 'vout': 0,
             'scriptPubKey': scriptPubKeyHexForSecret(secrets[0])},
            {'txid': '55638c2c3fe245f8d3ffee872fdf3aab2f919e6f814e043d85b86f1630153195', 'vout': 0,
             'scriptPubKey': scriptPubKeyHexForSecret(secrets[1])},
        ]

        outputs = {'U2xFhgz9URQx5HEqXTr6ytHhCpRWTBjzvdGpm': 0.1}

        rawTx = self.nodes[0].createrawtransaction(inputs, outputs)
        rawTxSigned = self.nodes[0].signrawtransaction(rawTx, inputs, privKeys)

        # 1) The transaction has a complete set of signatures
        assert 'complete' in rawTxSigned
        assert_equal(rawTxSigned['complete'], True)

        # 2) No script verification error occurred
        assert 'errors' not in rawTxSigned

    def script_verification_error_test(self):
        """Create and sign a raw transaction with valid (vin 0), invalid (vin 1) and one missing (vin 2) input script.

        Expected results:

        3) The transaction has no complete set of signatures
        4) Two script verification errors occurred
        5) Script verification errors have certain properties ("txid", "vout", "scriptSig", "sequence", "error")
        6) The verification errors refer to the invalid (vin 1) and missing input (vin 2)"""
        privKeys = ['AwSa5beJfAQFnX8pK4rMJvxcnGsvioLw6UobCPgPvFLsyoDSRwUue5z']
        secrets = ['72b12fd1d01ff094544466fe41856a2ec21b38e2eb3d57f8af1e3a6427bf76d1']

        inputs = [
            # Valid pay-to-pubkey script
            {'txid': 'f73ab7aa5c3ffae730f5b11f16550a7cebfe5bb69ff0e7a297f17f799173e574', 'vout': 0},
            # Invalid script
            {'txid': 'f22bf6c5a22b7eac44ab29be0cb24c44f308087924063ec7292ac5ca46078020', 'vout': 7},
            # Missing scriptPubKey
            {'txid': 'f73ab7aa5c3ffae730f5b11f16550a7cebfe5bb69ff0e7a297f17f799173e574', 'vout': 1},
        ]

        scripts = [
            # Valid pay-to-pubkey script
            {'txid': 'f73ab7aa5c3ffae730f5b11f16550a7cebfe5bb69ff0e7a297f17f799173e574', 'vout': 0,
             'scriptPubKey': scriptPubKeyHexForSecret(secrets[0])},
            # Invalid script
            {'txid': 'f22bf6c5a22b7eac44ab29be0cb24c44f308087924063ec7292ac5ca46078020', 'vout': 7,
             'scriptPubKey': 'badbadbadbad'}
        ]

        outputs = {'U2xFhgz9URQx5HEqXTr6ytHhCpRWTBjzvdGpm': 0.1}

        rawTx = self.nodes[0].createrawtransaction(inputs, outputs)

        # Make sure decoderawtransaction is at least marginally sane
        decodedRawTx = self.nodes[0].decoderawtransaction(rawTx)
        for i, inp in enumerate(inputs):
            assert_equal(decodedRawTx["vin"][i]["txid"], inp["txid"])
            assert_equal(decodedRawTx["vin"][i]["vout"], inp["vout"])

        # Make sure decoderawtransaction throws if there is extra data
        assert_raises_rpc_error(-22, "TX decode failed", self.nodes[0].decoderawtransaction, rawTx + "00")

        rawTxSigned = self.nodes[0].signrawtransaction(rawTx, scripts, privKeys)

        # 3) The transaction has no complete set of signatures
        assert 'complete' in rawTxSigned
        assert_equal(rawTxSigned['complete'], False)

        # 4) Two script verification errors occurred
        assert 'errors' in rawTxSigned
        assert_equal(len(rawTxSigned['errors']), 2)

        # 5) Script verification errors have certain properties
        assert 'txid' in rawTxSigned['errors'][0]
        assert 'vout' in rawTxSigned['errors'][0]
        assert 'witness' in rawTxSigned['errors'][0]
        assert 'scriptSig' in rawTxSigned['errors'][0]
        assert 'sequence' in rawTxSigned['errors'][0]
        assert 'error' in rawTxSigned['errors'][0]

        # 6) The verification errors refer to the invalid (vin 1) and missing input (vin 2)
        assert_equal(rawTxSigned['errors'][0]['txid'], inputs[1]['txid'])
        assert_equal(rawTxSigned['errors'][0]['vout'], inputs[1]['vout'])
        assert_equal(rawTxSigned['errors'][1]['txid'], inputs[2]['txid'])
        assert_equal(rawTxSigned['errors'][1]['vout'], inputs[2]['vout'])
        assert not rawTxSigned['errors'][0]['witness']

        # Now test signing failure for transaction with input witnesses
        p2wpkh_raw_tx = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"

        rawTxSigned = self.nodes[0].signrawtransaction(p2wpkh_raw_tx)

        # 7) The transaction has no complete set of signatures
        assert 'complete' in rawTxSigned
        assert_equal(rawTxSigned['complete'], False)

        # 8) Two script verification errors occurred
        assert 'errors' in rawTxSigned
        assert_equal(len(rawTxSigned['errors']), 2)

        # 9) Script verification errors have certain properties
        assert 'txid' in rawTxSigned['errors'][0]
        assert 'vout' in rawTxSigned['errors'][0]
        assert 'witness' in rawTxSigned['errors'][0]
        assert 'scriptSig' in rawTxSigned['errors'][0]
        assert 'sequence' in rawTxSigned['errors'][0]
        assert 'error' in rawTxSigned['errors'][0]

        # Non-empty witness checked here
        assert_equal(rawTxSigned['errors'][1]['witness'], ["304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01", "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"])
        assert not rawTxSigned['errors'][0]['witness']

    def run_test(self):
        self.successful_signing_test()
        self.script_verification_error_test()


if __name__ == '__main__':
    SignRawTransactionsTest().main()
