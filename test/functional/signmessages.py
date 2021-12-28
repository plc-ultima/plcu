#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPC commands for signing and verifying messages."""

from base64 import b64encode, b64decode
from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import *
from test_framework.util import *
from test_framework.key import CECKey, sign_compact, recover_public_key


class SignMessagesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        strMessageMagic = "PLC Ultima Signed Message:\n"
        message = 'This is just a test message'

        self.log.info('test signing with priv_key')
        priv_key_b58 = 'AwSa9YNVSy7Htw6ovCVp9cuB5jNUPv2isdjGMjYD7c9T8qzGf5yjYwg'
        priv_key_bin = b58decode_chk(priv_key_b58)[3:]
        key = CECKey()
        key.set_secretbytes(priv_key_bin)
        if not key.is_compressed():
            key.set_compressed(True)
        address = AddressFromPubkey(key.get_pubkey())
        part1 = struct.pack("<B", len(strMessageMagic)) + bytes(strMessageMagic, 'utf-8')
        part2 = struct.pack("<B", len(message)) + bytes(message, 'utf-8')
        hash = hash256(part1 + part2)
        signature_my_bin = sign_compact(hash, priv_key_bin)
        signature_my_b64 = b64encode(signature_my_bin).decode('ascii')
        self.log.debug('hash: {}, signature_my_bin: {}, signature_my_b64: {}, privkey: {}, pkh: {}, address: {}'.format(
            bytes_to_hex_str(hash), bytes_to_hex_str(signature_my_bin), signature_my_b64, bytes_to_hex_str(priv_key_bin),
            bytes_to_hex_str(reverse(hash160(key.get_pubkey()))), address))
        signature_got_b64 = self.nodes[0].signmessagewithprivkey(priv_key_b58, message)
        signature_got_bin = b64decode(signature_got_b64)
        self.log.debug(('signature_got_bin: {}'.format(bytes_to_hex_str(signature_got_bin))))

        # assert_equal(signature_my_b64, signature_got_b64)  # no, signatures are different signing the same hash each time
        assert(self.nodes[0].verifymessage(address, signature_got_b64, message))
        assert(self.nodes[0].verifymessage(address, signature_my_b64, message))

        pub1 = recover_public_key(hash, signature_got_bin, True)
        pub2 = recover_public_key(hash, signature_my_bin, True)
        assert_equal(key.get_pubkey(), pub1)
        assert_equal(key.get_pubkey(), pub2)

        self.log.info('test signing with an address with wallet')
        address = self.nodes[0].getnewaddress()
        signature = self.nodes[0].signmessage(address, message)
        assert(self.nodes[0].verifymessage(address, signature, message))

        self.log.info('test verifying with another address should not work')
        other_address = self.nodes[0].getnewaddress()
        other_signature = self.nodes[0].signmessage(other_address, message)
        assert(not self.nodes[0].verifymessage(other_address, signature, message))
        assert(not self.nodes[0].verifymessage(address, other_signature, message))

if __name__ == '__main__':
    SignMessagesTest().main()
