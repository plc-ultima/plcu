#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a node with the -disablewallet option.

- Test that validateaddress RPC works when running with -disablewallet
- Test that it is not possible to mine to an invalid address.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import AddressFromPubkey

class DisableWalletTest (BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-disablewallet"]]

    def run_test (self):
        # Make sure wallet is really disabled
        assert_raises_rpc_error(-32601, 'Method not found', self.nodes[0].getwalletinfo)
        valid_address = AddressFromPubkey(b'pubkey1')
        invalid_address = AddressFromPubkey(b'pubkey1', testnet=False)
        self.log.debug(f'valid_address: {valid_address}, invalid_address: {invalid_address}')
        x = self.nodes[0].validateaddress(invalid_address)
        assert(x['isvalid'] == False)
        x = self.nodes[0].validateaddress(valid_address)
        assert(x['isvalid'] == True)

        # Checking mining to an address without a wallet. Generating to a valid address should succeed
        # but generating to an invalid address will fail.
        # Note: now both of them fail
        # self.nodes[0].generatetoaddress(1, valid_address)
        assert_raises_rpc_error(-32601, "Method not found (wallet method is disabled because no wallet is loaded)", self.nodes[0].generatetoaddress, 1, valid_address)
        assert_raises_rpc_error(-32601, "Method not found (wallet method is disabled because no wallet is loaded)", self.nodes[0].generatetoaddress, 1, invalid_address)

if __name__ == '__main__':
    DisableWalletTest ().main ()
