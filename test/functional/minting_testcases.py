#!/usr/bin/env python3
# Copyright (c) 2019-2021 The PLC Ultima Core developers

import copy
from random import randint, choice
from test_framework.util import COIN, DUST_OUTPUT_THRESHOLD

BAD_REWARD_COMMON                = 'non-mandatory-script-verify-flag (Bad reward'
BAD_PLC_CERTIFICATE              = 'non-mandatory-script-verify-flag (Bad plc certificate'
BAD_REWARD_ROBBERY               = 'non-mandatory-script-verify-flag (Bad reward. Everybody be cool, this is a robbery!!!)'
BAD_REWARD_NOT_MATURE            = 'non-mandatory-script-verify-flag (Bad reward, not matured)'
BAD_REWARD_BEN_AMOUNT_TOO_HIGH   = 'non-mandatory-script-verify-flag (Bad reward, BIG BEN)'
BAD_REWARD_LIMIT_EXCEEDED        = 'non-mandatory-script-verify-flag (Bad reward, limit exceeded)'
BAD_REWARD_DAILY_LIMIT_EXCEEDED  = 'non-mandatory-script-verify-flag (Bad reward, daily limit exceeded)'
BAD_REWARD_CERT_EXPIRED          = 'non-mandatory-script-verify-flag (Bad reward, cert expired)'
BAD_REWARD_MANY_MONEYBOX_INPUTS  = 'non-mandatory-script-verify-flag (Bad reward, too many moneybox inputs)'
BAD_REWARD_MANY_MONEYBOX_OUTPUTS = 'non-mandatory-script-verify-flag (Bad reward, too many moneybox outputs)'
BAD_REWARD_MANY_USER_OUTPUTS     = 'non-mandatory-script-verify-flag (Bad reward, too many user outputs)'
BAD_REWARD_MANY_BEN_OUTPUTS      = 'non-mandatory-script-verify-flag (Bad reward, too many beneficiary outputs)'
BAD_REWARD_SCRIPT                = 'non-mandatory-script-verify-flag (Bad script)'
BAD_REWARD_INV_USER_ADDRESS      = 'non-mandatory-script-verify-flag (Bad reward, incorrect user address)'
BAD_REWARD_INV_SIGNATURE         = 'non-mandatory-script-verify-flag (Bad plc signatures)'
NON_CANONICAL_SIGNATURE          = 'non-mandatory-script-verify-flag (Non-canonical DER signature)'
BIG_FEE                          = 'non-mandatory-script-verify-flag (Big fee)'
BAD_LOCKTIME_REQUIREMENT         = 'non-mandatory-script-verify-flag (Locktime requirement not satisfied)'
PREMATURE_SPEND_OF_COINBASE      = 'bad-txns-premature-spend-of-coinbase'
DUST                             = 'dust'

DUST_OUTPUT_THRESHOLD = 54000
ALLOWED_DELTA_REWARD = 5

'''
Parameters description:

'name': 'any_name',                 # name of testcase, string. May be used to run testcase with this name: 'minting.py --runtestcase=name'
'rootcertamount': 1 * COIN,         # amount to transfer in root certificate, int in satoshi, string or Decimal in coins
'greenflag': True,                  # greenflag, True or False 
'ca3certamount': 1000000,           # amount to transfer in ca3 certificate, int in satoshi, string or Decimal in coins, 1000000 means 10 percent
'ben_enabled': False,               # beneficiary pubkey enabled, True/False; default False
'ca3_age': 22 * 60 * 60,            # age of ca3 certificate, in seconds; default 0
'usermoney_age': 24 * 60 * 60,      # age of user money, in seconds; default 0
'useramount': 100 * COIN,           # amount of user money, int in satoshi, string or Decimal in coins
'useramount': (100,200,300),        # alternative syntax for user amount, several user inputs, int in satoshi, string or Decimal in coins
'reward_to': 'ben+other'            # destination where reward outputs will be sent to in mint transaction, string, see @destination_type@ below
                                    #   for 'user', 'user_locked': by default reward amount will be added to user amount, without creating separate output (can be changed with 'join_user_reward_to_user_outputs' parameter) 
'rewardamount': COIN // 365,        # reward amount, int in satoshi, string or Decimal in coins
'fee_total': 'auto',                # total fee in minting transaction, int in satoshi, string or Decimal in coins, or may be 'auto'; default 'auto'
'fee_user_percent': 0,              # what percent of fee_total user will pay, must be int 0 <= x <= 100, or may be 'auto'
'refill_moneybox': 'node',          # who will refill moneybox, may be one of: 'node', 'script', 'random'; default 'random'
'keys_count_total': randint(1,15),  # total keys count in user multisig P2SH address in M of N scheme (keys_count_total == N), int, 1 <= x <= 15 (actual only if 'sig_model' == 'multisig', otherwise is ignored); default randint(1,12)
'keys_count_required': 5,           # required keys count in user multisig P2SH address in M of N scheme (keys_count_required == M), int (actual only if 'sig_model' == 'multisig', otherwise is ignored); default 'random'
                                    # in regular workflow is (1 <= x <= keys_count_total), also may be None, 0 or 'random'
                                    #     None or 0 means that this field is not set in certificate, this means (keys_count_required == keys_count_total) by default
                                    #     'random' means random value in range (1 <= x <= keys_count_total)
'keys_count_used': 'auto',          # used keys count in user multisig P2SH address in M of N scheme, in regular workflow is (keys_count_used == keys_count_required), int, may be 'auto'; default 'auto'
                                    #     (actual only if 'sig_model' == 'multisig', otherwise is ignored)
                                    #     'auto' means (keys_count_used == keys_count_required)
'accepted': True,                   # whether minting transaction is valid and will be accepted by the node, True or False

'revoke_root_cert': True,           # Root certificate is revoked, True or False, default False
'revoke_user_cert': False,          # User certificate is revoked, True or False, default False
'invalid_root_cert': 1,             # Invalid root certificate (or reference to root certificate) in mint transaction, int, possible values:
                                    #   1: non-existing transaction (certificate) 
                                    #   2: regular P2PKH transaction, not certificate
                                    #   3: invalid certificate: transfers money to another P2PKH address, not to itself
                                    #   4: another root certificate, not a parent of user certificate (CA3 keys in root and user certificates are different)
                                    #   5: invalid root certificate, with unknown root key not mentioned in genezis block
                                    #   6: root certificate with root key mentioned in genezis block, but not in the first entry (in the second entry)
                                    #   20: invalid signature of block1 in scriptPubKey [block1 signature(block1) OP_2DROP ...] (invalid sig_hash)
                                    #   21: invalid signature of block1 in scriptPubKey [block1 signature(block1) OP_2DROP ...] (signed with another key)
                                    #   22: invalid signature of block1 in scriptPubKey [block1 signature(block1) OP_2DROP ...] (corrupted signature)
                                    #   23: missing signature of block1 in scriptPubKey (empty block instead of signature)
'invalid_user_cert': 1,             # Invalid user certificate (or reference to user certificate) in mint transaction, int, possible values:
                                    #   1: non-existing transaction (certificate)
                                    #   2: regular P2PKH transaction, not certificate
                                    #   3: invalid certificate: transfers money to another P2PKH address, not to itself
                                    #   4: another user certificate, not a parent of used user keys (user keys used in minting transaction and given in this certificate are different)
                                    #   5: invalid user coins (not mentioned in CA3 certificate), but valid user keys for signing moneybox outputs in minting tx. In other words, user tries to mint coins from another address using correct certificate.
                                    #   20: invalid signature of block1 in scriptPubKey [block1 signature(block1) OP_2DROP ...] (invalid sig_hash)
                                    #   21: invalid signature of block1 in scriptPubKey [block1 signature(block1) OP_2DROP ...] (signed with another key)
                                    #   22: invalid signature of block1 in scriptPubKey [block1 signature(block1) OP_2DROP ...] (corrupted signature)
                                    #   23: missing signature of block1 in scriptPubKey (empty block instead of signature)
'invalid_refill_moneybox': 1        # Refill moneybox in invalid way, int, possible values:
                                    #   1: Don't refill moneybox
                                    #   2: Refill moneybox on 1 satoshi less than required
                                    #   3: Refill moneybox on 1 satoshi more than required
                                    #   4: Refill moneybox with too low granularity: number of outputs is more than (sum/gran + 1)
                                    #   5: Refill moneybox with too high granularity (more than moneybox granularity for current height)
'refill_moneybox_dest': 'user'      # Destination where moneybox outputs will be sent when refilling moneybox, string, see @destination_type@ below; default 'moneybox'
'refill_moneybox_accepted': False   # Result of acceptance of a new block when refilling moneybox, True or False, default True 
'green_flag_in_user_cert': True     # Set up green flag in user certificate (in regular workflow it is always False), True or False
'extra_moneybox_inputs_count': 2    # Number of extra moneybox inputs count (besides those that are needed to cover required amount), in regular workflow must be 0, int
'moneybox_change_dest': 'user+ben'  # Destination where moneybox change outputs will be sent to in mint transaction, string, see @destination_type@ below; default 'moneybox'
'user_outputs_dest': 'ben'          # Destination where user outputs will be sent to in mint transaction, string, see @destination_type@ below; default 'user'
'ca3_expiration_offset': 3600       # Expiration date offset in ca3 certificate due to block timestamp this certificate is mined in, int, in seconds
                                    # If None, no expiration date field presents in certificate. Default None.
                                    #    'ca3_expiration_offset' < 0: expiration date is X seconds less than the block timestamp (expires before the block this certificate is mined in)
                                    #    'ca3_expiration_offset' == 0: expiration date is equal to the block timestamp
                                    #    'ca3_expiration_offset' > 0: expiration date is X seconds more than the block timestamp 
'ca3_minting_limit': 10 * COIN,     # Minting limit in ca3 certificate, int in satoshi, string or Decimal in coins, None means that it is not set, default None.
                                    #    It limits the sum of all rewards with usage of this certificate during all the life time.
'ca3_daily_limit': 1000 * COIN,     # Daily limit in ca3 certificate, int in satoshi, string or Decimal in coins, None means that it is not set, default None.
                                    #    It limits the sum of all user coins used for minting with usage of this certificate during 24 hours.
'free_ben_enabled': True,           # Beneficiary reward can be sent to any number of any addresses, True or False, default False
'invalid_signature': 201,           # Invalid signature in mint tx, int, possible values (default None):
                                    #   100: missing signatures in user inputs in mint tx,
                                    #   101: invalid signatures in user inputs in mint tx (invalid sig_hash),
                                    #   102: invalid signatures in user inputs in mint tx (signed with another keys),
                                    #   110: invalid signatures in user inputs in mint tx (corrupted signatures),
                                    #   111: invalid signatures in user inputs in mint tx (signed with the same key twice in multisig scheme), must be 'sig_model' == 'multisig'
                                    #   112: invalid signatures in user inputs in mint tx (signed with the same key repeatedly instead of different M keys in multisig scheme), must be 'sig_model' == 'multisig'
                                    #   200: missing signatures and pubkeys in moneybox inputs in mint tx,
                                    #   201: invalid signatures in moneybox inputs in mint tx (invalid sig_hash),
                                    #   202: invalid signatures in moneybox inputs in mint tx (signed with another keys, original pubkeys are passed),
                                    #   203: invalid signatures in moneybox inputs in mint tx (signed with another keys, another pubkeys are passed),
                                    #   204: signatures are valid, but don't correspond to pubkeys in moneybox inputs in mint tx (signatures and pubkeys are shuffled), must be 'sig_model' == 'multisig'
                                    #   210: invalid signatures in moneybox inputs in mint tx (corrupted signatures),
                                    #   211: invalid signatures in moneybox inputs in mint tx (signed with the same key twice in multisig scheme), must be 'sig_model' == 'multisig'
                                    #   212: invalid signatures in moneybox inputs in mint tx (signed with the same key repeatedly instead of different M keys in multisig scheme), must be 'sig_model' == 'multisig'
'alt_behavior': 10,                 # Alternative behavior in mint tx, not an error, int, possible values (default None):
                                    #   10: different user keys are used to sign user inputs and moneybox inputs (another M of N keys), must be 'sig_model' == 'multisig' 
                                    #       example: 2 of 3, total keys [K1,K2,K3], used to sign user inputs [K1,K3], used to sign moneybox inputs [K1,K2] 
                                    #   11: different key order is used to sign user inputs and moneybox inputs (the same user keys, but in wrong order), must be 'sig_model' == 'multisig'
                                    #       example: 2 of 3, total keys [K1,K2,K3], used to sign user inputs [K1,K3], used to sign moneybox inputs [K3,K1]
'blockchain_height': 500,           # Total blockchain height before sending minting transaction (if less, required amount of blocks will be generated), default None.
'zero_change_to_moneybox': 1,       # Create N change outputs to moneybox with zero amount, int, default None.
'acceptnonstdtxn': 0,               # Pass this option to node, int, 0 or 1, default 0.
'drop_moneybox_dust_change': False, # Drop moneybox dust change outputs, True/False, default True
'max_blocks_in_wait_cycle': 100,    # max blocks in wait cycle, default 30
'sivler_hoof': True,                # Silver hoof (minting 3.0) is enabled, True/False, default False
'join_user_reward_to_user_outputs': False, # Join reward to user outputs, if it goes to 'user', 'user_locked', True/False, default True
                                           # In minting v1 reward to user must be joined to user output(s);
                                           # In minting v3 reward to user must be as separate output(s);
'sig_model': 'multisig',            # Signature model, may be one of: 'singlesig', 'multisig', 'random'; default 'random'
'lock_interval_min': 3600,          # Min value of time interval in seconds to lock outputs, sent to *_locked destination (user_locked, ben_locked, other_locked, etc), default 3600
'lock_interval_max': 3600 * 24,     # Max value of time interval in seconds to lock outputs, sent to *_locked destination (user_locked, ben_locked, other_locked, etc), default 3600 * 24 * 365
'lock_intervals': (3600,7200),      # Lock intervals for each output, instead of lock_interval_min/lock_interval_max
'gen_block_after_fill_user': False, # Generate block after fill up user's address, True/False (when false and no wait time, user inputs in mint tx will be from mempool), default True
'gen_block_after_cert': False,      # Generate block after creating certificate(s), True/False (when false and no wait time, certificate inputs in mint tx will be from mempool), default True
'separate_white': True,             # User PKH (in minting 3.0 is called white) is not mentioned in user certificate, True/False, default False
'ben_percent': '0.01',              # Certificate contains flag 0x00000020 (hasBenefitiaryPercent) and amount indicating this percent, is used in funding; int in satoshi, string or Decimal in coins, default None
'free_ben_percent': '0.02',         # Certificate contains flag 0x00000040 (hasFreeBenPercent) and amount indicating this percent, is used in funding; int in satoshi, string or Decimal in coins, default None
'spend_reward': 'ben_ab[a][0]',     # Spend reward output from mint tx, [a] (means a key with timelock) or [b] (means multisig a+b), [i] means reward output index - which exactly reward output
'spend_reward_wait': 3600,          # Wait before spending reward output, int, in seconds, default 0  
'spend_reward_accepted': False,     # spend_reward_accepted, True/False
'tx_version': 3,                    # Version of transaction, int, default random [1,2]; was introduces for tx version 3, later this functionality was removed
'skip_test': True,                  # Skip test, bool, default False

'step2_enabled': True,              # Step 2 is enabled (compose and send one more minting transaction), True/False, default False
'step2_wait_interval': 23*60*60,    # Step 2: wait interval, in seconds
'step2_rewardamount': COIN // 365,  # Step 2: reward amount, int in satoshi, string or Decimal in coins
'step2_reward_to': 'user',          # Step 2: destination where reward outputs will be sent to in mint transaction, string, see @destination_type@ below
'step2_accepted': True,             # Step 2: whether minting transaction is valid and will be accepted by the node, True or False
'step2_daily_limit_used': 0,        # Step 2: Summary used daily limit before executing step2. May differ from default because of too long wait time (daily limit counter may be reset to zero)
'step2_user_outputs_dest': 'user'   # Step 2: user_outputs_dest on step2
'step2_spend_inputs_with_proj_key': (0,1,2)  # Step 2: spend given inputs with 2 keys (user+project) instead of only user; actual only for ab-minting; default None 

'step3_enabled': True,              # Step 3 is enabled (compose and send one more minting transaction), True/False, default False
'step3_wait_interval': 0,           # Step 3: wait interval, in seconds
'step3_rewardamount': COIN // 365,  # Step 3: reward amount, int in satoshi, string or Decimal in coins
'step3_reward_to': 'user',          # Step 3: destination where reward outputs will be sent to in mint transaction, string, see @destination_type@ below
'step3_accepted': True,             # Step 3: whether minting transaction is valid and will be accepted by the node, True or False
'step3_daily_limit_used': 0,        # Step 3: Summary used daily limit before executing step3. May differ from default because of too long wait time (daily limit counter may be reset to zero)
'step3_user_outputs_dest': 'user'   # Step 3: user_outputs_dest on step3

'error': (64, 'error-message'),     # Error code and error message, any value from this pair may be None. Actual only when 'accepted' == False, otherwise is ignored.
                                    #     Ensures that received error code is equal to this one (if not None), 
                                    #     and received error message starts with the given string (if not None).
'error': (64, ['msg1','msg2']),     # Alternative format, there may be array of error messages, received error message must start with any of the given strings.

'@destination_type@': 'user+ben'    # Destination where outputs will be sent, string, may be expression with '+' and given values:
                                    #   'user': to user singlesig/multisig address (regular user address)
                                    #   'user_locked': to locked user address [time, OP_CHECKLOCKTIMEVERIFY, OP_DROP, ...], works only for 'sig_model' == 'singlesig'
                                    #   'user_shuffled': to user multisig P2SH address, but user keys are in wrong order (must be 'keys_count' > 1 and 'sig_model' == 'multisig')
                                    #   'user_pure_multisig': to user pure multisig address, not P2SH 
                                    #   'ben': to ben P2PKH address ('ben_enabled' parameter must be True)
                                    #   'ben_locked': to locked ben address ('ben_enabled' parameter must be True)
                                    #   'moneybox': to moneybox P2SH address
                                    #   'other_p2pkh' or 'other': random P2PKH address
                                    #   'other_locked': locked random P2PKH address 
                                    #   'other_p2sh': random P2SH address
                                    #   'op_true': to address [OP_TRUE], anyone can spend
                                    #   'op_false': to address [OP_FALSE], noone can spend
                                    #   'user_ab': ab-minting, to multisig address: (police OR (user + project))
                                    #   'user_ab_ex2': ab-minting, to multisig address: (user OR (user + project))
                                    #   'user_ab_ex3': ab-minting, to multisig address: (user OR (user + user))
                                    #   'user_ab_locked': ab-minting, to multisig address: (user-with-timelock OR (user + project)) 
                                    #   'ben_ab': ab-minting, to multisig address: (police OR (ben + project))
                                    #   'ben_ab_locked': ab-minting, to multisig address: (ben-with-timelock OR (ben + project))
                                    # Examples:
                                    #   'moneybox+moneybox+moneybox': creates 3 moneybox outputs
                                    #   'moneybox+user+ben': sends coins to moneybox, user and ben simultaneously, 1 output per each
                                    #   'ben': sends coins to ben
                                    #   '': (empty string) doesn't send coins, no outputs


In any parameters instead of value there may be array of values of the same type.
This will be transformed to all possible combinations of these values.
Example:
'parameter_a' : [True, False]
'parameter_b' : [1,2,3]
Result: (True, 1), (True, 2), (True, 3), (False, 1), (False, 2), (False, 3)
'''


testcases_templates = \
[
    {
        # (all keys_count from 1 to 15 and all reward_to (user, ben, other) in positive scenario): accepted
        'name': 'base00',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'ben', 'other'],
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'accepted': True,
    },
    {
        # base00, rewardamount +1 satoshi more than allowed): rejected
        'name': 'base00e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'ben', 'other'],
        'rewardamount': COIN * 10 // 365 + 1,
        'fee_user_percent': 'auto',
        'accepted': False,
        'error': (64, [BAD_REWARD_ROBBERY, BAD_REWARD_BEN_AMOUNT_TOO_HIGH]), # BAD_REWARD_ROBBERY for user and ben, BAD_REWARD_BEN_AMOUNT_TOO_HIGH for other
    },
    {
        # (usermoney_age < 23h, greenflag: any, ca3_age: any): rejected
        'name': 'm00',
        'rootcertamount': 1 * COIN,
        'greenflag': [True, False],
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': [0, 24 * 60 * 60],
        'usermoney_age': 23 * 60 * 60 - 60,
        'useramount': 1000 * COIN,
        'reward_to': ['user', 'ben', 'other'],
        'rewardamount': COIN * 10 * 22 // 24 // 365,
        'fee_user_percent': 'auto',
        'accepted': False,
        'error': (64, BAD_REWARD_NOT_MATURE),
    },

    #
    # greenflag == True
    #
    {
        # (usermoney_age == 23h, greenflag == True): accepted
        # + add parameter green_flag_in_user_cert=[False,True], it must be ignored, ensure that result is the same
        'name': 'm01',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 23 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'other']),
        'rewardamount': COIN * 10 * 23 // 24 // 365,
        'fee_user_percent': 'auto',
        'green_flag_in_user_cert': [ False, True ],
        'accepted': True,
    },
    {
        # (based on m01, greenflag=False, green_flag_in_user_cert=True, use green flag in user cert instead of root cert): rejected
        'name': 'm01A',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 23 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'other']),
        'rewardamount': COIN * 10 * 23 // 24 // 365,
        'fee_user_percent': 'auto',
        'green_flag_in_user_cert': True,
        'accepted': False,
        'error': (64, BAD_REWARD_NOT_MATURE),
    },
    {
        # (m01, rewardamount +1 satoshi more than allowed): rejected
        'name': 'm01e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 23 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'other']),
        'rewardamount': COIN * 10 * 23 // 24 // 365 + 1,
        'fee_user_percent': 'auto',
        'accepted': False,
        'error': (64, [BAD_REWARD_ROBBERY, BAD_REWARD_BEN_AMOUNT_TOO_HIGH]), # BAD_REWARD_ROBBERY for user and ben, BAD_REWARD_BEN_AMOUNT_TOO_HIGH for other
    },
    {
        # (23h < usermoney_age < 30d, greenflag == True): accepted
        'name': 'm03',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 12 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'other'],
        'rewardamount': COIN * 10 * 12 // 365,
        'fee_user_percent': 'auto',
        'accepted': True,
    },
    {
        # m03, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm03e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 23 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'other'],
        'rewardamount': COIN * 10 * 12 // 365 + 1,
        'fee_user_percent': 'auto',
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (usermoney_age >= 30d, greenflag == True): accepted
        'name': 'm05',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': [ 30 * 24 * 60 * 60, 31 * 24 * 60 * 60 ],
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m05, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm05e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': [ 30 * 24 * 60 * 60, 31 * 24 * 60 * 60 ],
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },

    #
    # greenflag == False
    #
    {
        # (usermoney_age < 20d, 20d < ca3_age < 30d, greenflag == False): rejected
        'name': 'm09',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 21 * 24 * 60 * 60,
        'usermoney_age': 20 * 24 * 60 * 60 - 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 19 // 365,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_NOT_MATURE),
    },
    {
        # (ca3_age < 20d, 20d < usermoney_age < 30d, greenflag == False): accepted (ca3_age must be used)
        'name': 'm10',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 18 * 24 * 60 * 60,
        'usermoney_age': 22 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 * 18 // 365,
        'fee_user_percent': 'auto',
        'accepted': True,
    },
    {
        # m10, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm10e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 18 * 24 * 60 * 60,
        'usermoney_age': 22 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 * 18 // 365 + 1,
        'fee_user_percent': 'auto',
        'accepted': False,
        'error': (64, [BAD_REWARD_ROBBERY, BAD_REWARD_BEN_AMOUNT_TOO_HIGH]), # BAD_REWARD_ROBBERY for user and ben, BAD_REWARD_BEN_AMOUNT_TOO_HIGH for other
    },
    {
        # (usermoney_age == 20d, ca3_age == 20d, greenflag == False): accepted
        'name': 'm11',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 20 * 24 * 60 * 60,
        'usermoney_age': 20 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 20 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m11, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm11e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 20 * 24 * 60 * 60,
        'usermoney_age': 20 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 20 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (usermoney_age == 20d, 20d < ca3_age < 30d, greenflag == False): accepted
        'name': 'm13',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 21 * 24 * 60 * 60,
        'usermoney_age': 20 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 20 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m13, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm13e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 21 * 24 * 60 * 60,
        'usermoney_age': 20 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 20 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (20d < usermoney_age < 30d, ca3_age == 20d, greenflag == False): accepted
        'name': 'm15',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 20 * 24 * 60 * 60,
        'usermoney_age': 23 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 20 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m15, rewardamount +1 satoshi more than allowed): rejected
        'name': 'm15e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 20 * 24 * 60 * 60,
        'usermoney_age': 23 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 20 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (20d < usermoney_age < 30d, 20d < ca3_age < 30d, usermoney_age > ca3_age, greenflag == False): accepted
        'name': 'm17',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 23 * 24 * 60 * 60,
        'usermoney_age': 25 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 23 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m17, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm17e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 23 * 24 * 60 * 60,
        'usermoney_age': 25 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 23 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (20d < usermoney_age < 30d, 20d < ca3_age < 30d, ca3_age > usermoney_age, greenflag == False): accepted
        'name': 'm19',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 29 * 24 * 60 * 60,
        'usermoney_age': 25 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 25 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m19, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm19e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 29 * 24 * 60 * 60,
        'usermoney_age': 25 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 25 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (usermoney_age == 30d, 20d < ca3_age < 30d, greenflag == False): accepted
        'name': 'm21',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 21 * 24 * 60 * 60,
        'usermoney_age': 30 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 21 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m21, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm21e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 21 * 24 * 60 * 60,
        'usermoney_age': 30 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 21 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (20d < usermoney_age < 30d, ca3_age == 30d, greenflag == False): accepted
        'name': 'm23',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 30 * 24 * 60 * 60,
        'usermoney_age': 23 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 23 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m23, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm23e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 30 * 24 * 60 * 60,
        'usermoney_age': 23 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 23 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (usermoney_age == 30d, ca3_age == 30d, greenflag == False): accepted
        'name': 'm25',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 30 * 24 * 60 * 60,
        'usermoney_age': 30 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m25, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm25e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 30 * 24 * 60 * 60,
        'usermoney_age': 30 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (usermoney_age == 30d, ca3_age > 30d, greenflag == False): accepted
        'name': 'm27',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 31 * 24 * 60 * 60,
        'usermoney_age': 30 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m27, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm27e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 31 * 24 * 60 * 60,
        'usermoney_age': 30 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (usermoney_age > 30d, ca3_age == 30d, greenflag == False): accepted
        'name': 'm29',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 30 * 24 * 60 * 60,
        'usermoney_age': 37 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m29, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm29e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 30 * 24 * 60 * 60,
        'usermoney_age': 37 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (usermoney_age > 30d, ca3_age > 30d, usermoney_age > ca3_age, greenflag == False): accepted
        'name': 'm31',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 31 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m31, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm31e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 31 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (usermoney_age > 30d, ca3_age > 30d, ca3_age > usermoney_age, greenflag == False): accepted
        'name': 'm33',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m33, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm33e',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (the same as m33, but large useramount is used): accepted
        'name': 'm33A',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 5000 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 500 * 30 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # (m33A, rewardamount +1 satoshi more than allowed): rejected
        'name': 'm33Ae',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 5000 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 500 * 30 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (the same as m33, but large rewardamount is used, close to 100 PLCU): accepted
        # refill_moneybox: script (more than 1 output), check moneybox granularity near fork at block height = 500
        'name': 'm33B',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 10000 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 1000 * 30 // 365,
        'fee_user_percent': 0,
        'refill_moneybox': 'script',
        'blockchain_height': [499, 500, 501],
        'accepted': True,
    },
    {
        # (m33B, rewardamount +1 satoshi more than allowed): rejected
        'name': 'm33Be',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 10000 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 1000 * 30 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (the same as m33, rewardamount is 2 times less than must be): accepted
        'name': 'm33C',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365 // 2,
        'fee_user_percent': 0,
        'accepted': True,
    },
    # other cases
    {
        # (rootcertamount < ca3certamount): accepted, rootcertamount is used
        'name': 'm35',
        'rootcertamount': 1000000,
        'greenflag': True,
        'ca3certamount': 1200000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # m35, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm35e',
        'rootcertamount': 1000000,
        'greenflag': True,
        'ca3certamount': 1200000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 * 30 // 365 + 1,
        'fee_user_percent': 0,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # reward to [user, ben], fee_user_percent [50%, 100%]: accepted (not needed user to pay fee, but not forbidden)
        'name': 'm38',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'ben'],
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_total': '0.01',
        'fee_user_percent': [ 50, 100 ],
        'accepted': True,
    },
    {
        # (reward to other, fee_user_percent == 60%, 100%): accepted (user must pay ~45-52%, not needed user to pay more, but not forbidden)
        'name': 'm42',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'other',
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_total': '0.01',
        'fee_user_percent': [ 60, 100 ],
        'keys_count_total': randint(3,5),
        'keys_count_required': 3,
        'accepted': True,
    },
    {
        # (reward to other, fee_user_percent == 0%, 35%): rejected (user must pay ~45-49% fee)
        'name': 'm44',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'other',
        'rewardamount': COIN * 10 * 30 // 365,
        'fee_total': '0.01',
        'fee_user_percent': [ 0, 35 ],
        'accepted': False,
        'error': (64, BAD_REWARD_BEN_AMOUNT_TOO_HIGH),
    },
    {
        # (rewardamount == 0, fee_user_percent == 0): accepted
        'name': 'm45',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': 0,
        'fee_total': '0.01',
        'fee_user_percent': 0,
        'refill_moneybox': ['node', 'script'],
        'accepted': True,
    },
    {
        # (rewardamount == 0, fee_user_percent == 100): user_output_amount < user_input_amount: rejected
        'name': 'm45e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': 0,
        'fee_total': '0.01',
        'fee_user_percent': 100,
        'accepted': False,
        # 'non-mandatory-script-verify-flag (unknown error)'
    },
    {
        # based on base00, 2 user inputs, 2 user outputs (user_outputs_count == 2): accepted
        'name': 'm46',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 200 * COIN),
        'reward_to': ['user', 'ben', 'other'],
        'rewardamount': COIN * 30 // 365,
        'fee_user_percent': 'auto',
        'user_outputs_dest': 'user+user', # means (user_outputs_count == 2)
        'accepted': True,
    },
    {
        # m46, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm46e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 200 * COIN),
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 30 // 365 + 1,
        'fee_user_percent': 'auto',
        'user_outputs_dest': 'user+user', # means (user_outputs_count == 2)
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # based on base00, 3 user inputs, 2 user outputs (user_outputs_count == 2): accepted
        'name': 'm47',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 300 * COIN, 200 * COIN),
        'reward_to': ['user', 'ben', 'other'],
        'rewardamount': COIN * 60 // 365,
        'fee_user_percent': 'auto',
        'user_outputs_dest': 'user+user', # means (user_outputs_count == 2)
        'accepted': True,
    },
    {
        # m47, rewardamount +1 satoshi more than allowed: rejected
        'name': 'm47e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 300 * COIN, 200 * COIN),
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 60 // 365 + 1,
        'fee_user_percent': 'auto',
        'user_outputs_dest': 'user+user', # means (user_outputs_count == 2)
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # based on base00, reward_to ben+other: accepted
        'name': 'm48',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 200 * COIN),
        'reward_to': 'ben+other',
        'rewardamount': COIN * 30 // 365,
        'fee_user_percent': 'auto',
        'user_outputs_dest': 'user+user', # means (user_outputs_count == 2)
        'accepted': True,
    },
    {
        # rewardamount < fee_total: accepted
        'name': 'm49',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 1 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN // 10 // 365, # less than 0.001
        'fee_total': '0.005',
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # based on base00, reward_to: 'user+other', 'user+ben+other': accepted
        'name': 'm50',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 200 * COIN),
        'reward_to': [ 'user+other', 'user+ben+other' ],
        'rewardamount': COIN * 30 // 365,
        'fee_user_percent': 50,
        'user_outputs_dest': 'user+user',  # means (user_outputs_count == 2)
        'accepted': True,
    },
    {
        # based on base00, reward_to: 'user+ben: accepted
        'name': 'm51',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user+ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'accepted': True,
    },
    {
        # based on base00, (keys_count_required is not set, by default keys_count_required == keys_count_total): accepted
        'name': 'm52',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'keys_count_required': [ 0, None ],
        'sig_model': 'multisig',
        'accepted': True,
    },
    {
        # m52, (keys_count_used != keys_count_required): rejected
        'name': 'm52e1',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'keys_count_total': 5,
        'keys_count_required': 3,
        'keys_count_used': [ 1, 2, 4, 5 ],
        'sig_model': 'multisig',
        'accepted': False,
        'error': (64, [BAD_PLC_CERTIFICATE, BAD_REWARD_SCRIPT]),
    },
    {
        # m52, (keys_count_required > keys_count_total): rejected
        'name': 'm52e2',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'keys_count_total': 5,
        'keys_count_required': 6,
        'keys_count_used': 5,
        'sig_model': 'multisig',
        'accepted': False,
        'error': (64, BAD_PLC_CERTIFICATE),
    },
    {
        # free_ben_enabled == True, ben_enabled == False, reward_to different cases: accepted
        'name': 'm53',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'user+other', 'other', 'other+other', 'other+other+other', 'other_p2sh', 'other_p2pkh+other_p2sh'],
        'rewardamount': 10 * COIN // 365,
        'fee_user_percent': 0,
        'free_ben_enabled': True,
        'accepted': True,
    },
    {
        # free_ben_enabled == True, ben_enabled == True, reward_to different cases: accepted
        'name': 'm53A',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'user+ben', 'user+other', 'user+ben+other', 'other', 'ben+other', 'ben+other+other'],
        'rewardamount': 10 * COIN // 365,
        'fee_user_percent': 0,
        'free_ben_enabled': True,
        'accepted': True,
    },
    {
        # rewardamount == granularity, no moneybox change outputs: accepted
        'name': 'm56',
        'rootcertamount': 10 * COIN,
        'greenflag': True,
        'ca3certamount': 10 * COIN,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': 10 * COIN,
        'fee_total': 1000000,
        'fee_user_percent': 100,
        'accepted': True,
    },
    {
        # rewardamount == entire moneybox (no moneybox change) with acceptnonstdtxn=1: accepted
        # keys_count_total == randint(1,3) (for less complexity),
        'name': 'm58',
        'rootcertamount': 10 * COIN,
        'greenflag': True,
        'ca3certamount': 10 * COIN,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 40000 * COIN,
        'reward_to': 'user',
        'rewardamount': 10000 * COIN,
        'fee_user_percent': 100,
        'keys_count_total': randint(1,3),
        'blockchain_height': 200,
        'acceptnonstdtxn': 1,
        'accepted': True,
    },
    {
        # rewardamount == entire moneybox (no moneybox change) with acceptnonstdtxn=0: rejected
        # keys_count_total == randint(1,3) (for less complexity),
        'name': 'm58e',
        'rootcertamount': 10 * COIN,
        'greenflag': True,
        'ca3certamount': 10 * COIN,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 40000 * COIN,
        'reward_to': 'user',
        'rewardamount': 10000 * COIN,
        'fee_user_percent': 100,
        'keys_count_total': randint(1,3),
        'blockchain_height': 200,
        'acceptnonstdtxn': 0,
        'accepted': False,
        'error': (64, 'tx-size'),
    },
    {
        # rewardamount + rewardamount_step2 == entire moneybox (no moneybox change) with acceptnonstdtxn=1: accepted
        # keys_count_total == randint(1,3) (for less complexity),
        'name': 'm59',
        'rootcertamount': 10 * COIN,
        'greenflag': True,
        'ca3certamount': 10 * COIN,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 20000 * COIN,
        'reward_to': 'ben',
        'rewardamount': 5000 * COIN,
        'fee_user_percent': 100,
        'keys_count_total': randint(1,3),
        'blockchain_height': 200,
        'acceptnonstdtxn':1,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': 5000 * COIN,
        'step2_reward_to': 'user',
        'step2_accepted': True,
    },
    {
        # m60 with acceptnonstdtxn=1: accepted
        # rewardamount_step1 == 4 * COIN (10 coins moneybox_input --> 6 coins moneybox_change, 4 coins new_moneybox_input)
        # rewardamount_step2 == 10 * COINS (no moneybox change)
        # rewardamount_step3 == entire_moneybox - 10 * COINS (they are not matured from step2)
        # On step3 new_moneybox_inputs are mature from step1 and not mature from step2.
        # This testcase ensures that on step3 we correctly use moneybox_change from step1 and new_moneybox_input from step1
        # keys_count_total == randint(1,3) (for less complexity),
        'name': 'm60',
        'rootcertamount': 10 * COIN,
        'greenflag': True,
        'ca3certamount': 10 * COIN,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 40000 * COIN,
        'reward_to': choice(['user', 'ben']),
        'rewardamount': 4 * COIN,
        'fee_user_percent': 100,
        'keys_count_total': randint(1,3),
        'blockchain_height': 200,
        'max_blocks_in_wait_cycle': 100,
        'acceptnonstdtxn': 1,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': 10 * COIN,
        'step2_reward_to': choice(['user', 'ben']),
        'step2_accepted': True,
        'step3_enabled': True,
        'step3_wait_interval': 24 * 60 * 60,
        'step3_rewardamount': 10000 * COIN - 10 * COIN,
        'step3_reward_to': choice(['user', 'ben']),
        'step3_accepted': True,
    },
    {
        # with alt_behavior: accepted
        'name': 'm61',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'keys_count_total': randint(6, 12),
        'keys_count_required': randint(2, 5),
        'alt_behavior': [10, 11],
        'sig_model': 'multisig',
        'accepted': True,
    },
    {
        # rewardamount takes some more moneybox inputs, more than allowed (30*COIN instead of 10*COIN): rejected
        'name': 'm62',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 365 * 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': 30 * COIN,
        'fee_user_percent': 100,
        'accepted': False,
        'error': (64, [BAD_REWARD_ROBBERY, BAD_REWARD_MANY_MONEYBOX_INPUTS]),
    },
    {
        # step1:
        # --> moneybox input 10.0
        #   rewardamount 0.35
        #   fee 0.1
        # <-- moneybox_change 9.55
        # <-- new moneybox input (refill in coinbase tx) 0.45
        # step2: (less than 100 blocks left from step1, 0.45 is not mature yet, because it was refilled in coinbase tx)
        # --> moneybox input 9.55 (change from step1)
        #   rewardamount 9.45
        #   fee 0.1
        # <-- no moneybox_change (moneybox_change == 0)
        # <-- new moneybox input (refill in coinbase tx) 9.55
        # step3: (more than 100 blocks left from step1, 0.45 is mature; less than 100 blocks left from step2, 9.55 is not mature yet)
        # --> moneybox input 0.45 (refill from step1)
        # --> moneybox input 10.0
        #   rewardamount 0.4
        #   fee 0.1
        # <-- moneybox_change 9.95
        # <-- new moneybox input (refill in coinbase tx) 0.5
        # Here (inputMoneyBoxAmount > neededReward + awardGranularity),
        # but (inputMoneyBoxAmount + fee < neededReward + awardGranularity)
        # [accepted]
        'name': 'm63',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 365 * 4 * COIN,
        'reward_to': 'ben',
        'rewardamount': '0.35',
        'fee_total': '0.1',
        'fee_user_percent': 0,
        'max_blocks_in_wait_cycle': 100,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 25 * 24 * 60 * 60,
        'step2_rewardamount': '9.45',
        'step2_reward_to': 'ben',
        'step2_accepted': True,
        'step3_enabled': True,
        'step3_wait_interval': 24 * 60 * 60,
        'step3_rewardamount': '0.4',
        'step3_reward_to': choice(['user', 'ben']),
        'step3_accepted': True,
    },
    {
        # reward_to op_true, op_false with acceptnonstdtxn=1: accepted
        'name': 'm64',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['op_true', 'op_false'],
        'rewardamount': 10 * COIN // 365,
        'fee_user_percent': 'auto',
        'acceptnonstdtxn': 1,
        'accepted': True,
    },
    {
        # reward_to op_true, op_false with acceptnonstdtxn=0: rejected
        'name': 'm64e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['op_true', 'op_false'],
        'rewardamount': 10 * COIN // 365,
        'fee_user_percent': 'auto',
        'acceptnonstdtxn': 0,
        'accepted': False,
        'error': (64, 'scriptpubkey'),
    },
    {
        # moneybox change is 1 satoshi more than dust output threshold: accepted
        # moneybox change is 1 satoshi less than dust output threshold: accepted (such output will be dropped by tests itself)
        'name': 'm65',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * 365 * COIN,
        'reward_to': 'user',
        'rewardamount': [ 10 * COIN - DUST_OUTPUT_THRESHOLD - 1, 10 * COIN - DUST_OUTPUT_THRESHOLD + 1 ],
        'fee_user_percent': 100,
        'accepted': True,
    },
    {
        # moneybox change is 1 satoshi less than dust output threshold with (drop_moneybox_dust_change == False): rejected
        # moneybox change is 1 satoshi with (drop_moneybox_dust_change == False): rejected
        'name': 'm65e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * 365 * COIN,
        'reward_to': 'user',
        'rewardamount': 10 * COIN - 1,
        'fee_user_percent': 100,
        'drop_moneybox_dust_change': False,
        'accepted': False,
        'error': (64, DUST),
    },
    {
        # (fee == 10 PLCU), rewardamount is multiple to granularity: accepted
        # both granularities before block 500 and after are used
        'name': 'm66',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 36500 * 2 * COIN,
        'reward_to': 'ben',
        'rewardamount': 20 * COIN,
        'fee_total': 10 * COIN,
        'fee_user_percent': [0, 100],
        'blockchain_height': [100, 501],
        'accepted': True,
    },
    {
        # m66, (fee > 10 PLCU), rewardamount is multiple to granularity: rejected
        # both granularities before block 500 and after are used
        'name': 'm66e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 36500 * 2 * COIN,
        'reward_to': 'ben',
        'rewardamount': 20 * COIN,
        'fee_total': 10 * COIN + 1,
        'fee_user_percent': [0, 100],
        'blockchain_height': [100, 501],
        'accepted': False,
        'error': (64, BIG_FEE),
    },
    {
        # (fee == 10 PLCU), rewardamount is not multiple to granularity: accepted
        # both granularities before block 500 and after are used
        'name': 'm67',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 3650 * 23 * COIN,
        'reward_to': 'ben',
        'rewardamount': 23 * COIN,
        'fee_total': 10 * COIN,
        'fee_user_percent': [0, 100],
        'blockchain_height': [100, 501],
        'accepted': True,
    },
    {
        # m67, (fee > 10 PLCU), rewardamount is not multiple to granularity: rejected
        # both granularities before block 500 and after are used
        'name': 'm67e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 3650 * 23 * COIN,
        'reward_to': 'ben',
        'rewardamount': 23 * COIN,
        'fee_total': 10 * COIN + 1,
        'fee_user_percent': [0, 100],
        'blockchain_height': [100, 501],
        'accepted': False,
        'error': (64, BIG_FEE),
    },

    #
    # Step2 series: tests with 2 steps of minting, user output of the first step is user input for the second one:
    #
    {
        # (reward_to ben, useramount between steps is without changes): accepted
        'name': 'step2_01',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': choice(['user', 'ben']),
        'step2_accepted': True,
    },
    {
        # step2_01, reward_to ben, step2_rewardamount +1 satoshi more than allowed: rejected
        'name': 'step2_01e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365 + 1,
        'step2_reward_to': choice(['user', 'ben']),
        'step2_accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (reward_to user, useramount between steps is accumulated): accepted
        'name': 'step2_02',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': (COIN * 10 + COIN // 365) // 365,
        'step2_reward_to': 'user',
        'step2_accepted': True,
    },
    {
        # step2_02, reward_to user, step2_rewardamount +1 satoshi more than allowed: rejected
        'name': 'step2_02e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': (COIN * 10 + COIN // 365) // 365 + 1,
        'step2_reward_to': 'user',
        'step2_accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },

    #
    # L series (Limits): tests with cert expiration date, minting limits and daily limits:
    #
    {
        # (rewardamount <= ca3_minting_limit, user_fee == 0): accepted
        'name': 'L01',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'ca3_minting_limit': [ COIN * 10 // 365, COIN * 10 // 365 + 1000 ],
        'accepted': True,
    },
    {
        # (rewardamount > ca3_minting_limit, user_fee == 0): rejected
        # (ca3_minting_limit <= 0): rejected
        'name': 'L01e1',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'ca3_minting_limit': [ COIN * 10 // 365 - 1, 0, -100 ],
        'accepted': False,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED),
    },
    {
        # (rewardamount - user_fee <= ca3_minting_limit, user_fee > 0): accepted
        'name': 'L01A',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'other',
        'rewardamount': COIN * 10 // 365,
        'fee_total': 2000000,
        'fee_user_percent': 80,
        'keys_count_total': randint(2, 6),
        'ca3_minting_limit': [COIN * 10 // 365 - 1600000, COIN * 10 // 365],
        'accepted': True,
    },
    {
        # (rewardamount - user_fee > ca3_minting_limit, user_fee > 0): rejected
        'name': 'L01Ae',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'other',
        'rewardamount': COIN * 10 // 365,
        'fee_total': 2000000,
        'fee_user_percent': 80,
        'keys_count_total': randint(2, 6),
        'ca3_minting_limit': COIN * 10 // 365 - 1600000 - 1,
        'accepted': False,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED),
    },
    {
        # (sum(rewardamount) <= ca3_minting_limit) in different transactions, user_fee == 0: accepted
        'name': 'L02',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'ca3_minting_limit': [ COIN * 10 // 365 * 2, COIN * 10 // 365 * 2 + 1, COIN * 10 // 365 * 200 ],
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': choice(['user', 'ben']),
        'step2_accepted': True,
    },
    {
        # (sum(rewardamount) > ca3_minting_limit) in different transactions, user_fee == 0: rejected
        # Example: minting limit L=100
        # M1=100, M2=50: rejected (M1 + M2 > L) where (M1 == L)
        # M1=60, M2=50: rejected (M1 + M2 > L)
        'name': 'L02e1',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'ca3_minting_limit': [ COIN * 10 // 365, COIN * 10 // 365 + 1, COIN * 10 // 365 * 2 - 1 ],
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': choice(['user', 'ben']),
        'step2_accepted': False,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED),
    },
    {
        # last_rewardamount > ca3_minting_limit, user_fee == 0: rejected
        # Example: minting limit L=100
        # M1=50, M2=150: rejected (M2 > L)
        'name': 'L02e2',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'ca3_minting_limit': COIN * 10 // 365 * 2,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 3 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365 * 2 + 1,
        'step2_reward_to': choice(['user', 'ben']),
        'step2_accepted': False,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED),
    },
    {
        # (sum(rewardamount) <= ca3_minting_limit) in different transactions, user_fee > 0: accepted
        'name': 'L02A',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'other',
        'rewardamount': COIN * 10 // 365,
        'fee_total': 2000000,
        'fee_user_percent': 80,
        'keys_count_total': randint(2, 6),
        'ca3_minting_limit': [COIN * 10 // 365 * 2 - 1600000 * 2, COIN * 10 // 365 * 2],
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': 'other',
        'step2_accepted': True,
    },
    {
        # (sum(rewardamount) > ca3_minting_limit) in different transactions, user_fee > 0: rejected
        'name': 'L02Ae',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'other',
        'rewardamount': COIN * 10 // 365,
        'fee_total': 2000000,
        'fee_user_percent': 80,
        'keys_count_total': randint(2, 6),
        'ca3_minting_limit': COIN * 10 // 365 * 2 - 1600000 * 2 - 1,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': 'other',
        'step2_accepted': False,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED),
    },
    {
        # (sum(rewardamount) <= ca3_minting_limit) within a transaction in different inputs/outputs, user_fee == 0: accepted
        'name': 'L03',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN),
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365 * 2,
        'fee_user_percent': 0,
        'ca3_minting_limit': [COIN * 10 // 365 * 2, COIN * 10 // 365 * 2 + 1, COIN * 10 // 365 * 200],
        'user_outputs_dest': 'user+user', # means (user_outputs_count == 2)
        'accepted': True,
    },
    {
        # (sum(rewardamount) > ca3_minting_limit) within a transaction in different inputs/outputs, user_fee == 0: rejected
        # Example: minting limit L=100
        # M1=100, M2=50: rejected (M1 + M2 > L) where (M1 == L)
        # M1=60, M2=50: rejected (M1 + M2 > L)
        'name': 'L03e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN),
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365 * 2,
        'fee_user_percent': 0,
        'ca3_minting_limit': [COIN * 10 // 365, COIN * 10 // 365 + 1, COIN * 10 // 365 * 2 - 1],
        'user_outputs_dest': 'user+user', # means (user_outputs_count == 2)
        'accepted': False,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED),
    },
    {
        # (sum(rewardamount) <= ca3_minting_limit) within a transaction in different inputs/outputs, user_fee > 0: accepted
        'name': 'L03A',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN),
        'reward_to': 'other',
        'rewardamount': COIN * 10 // 365 * 2,
        'fee_total': 2000000,
        'fee_user_percent': 80,
        'keys_count_total': randint(2, 6),
        'ca3_minting_limit': [COIN * 10 // 365 * 2 - 1600000, COIN * 10 // 365 * 2],
        'user_outputs_dest': 'user+user',  # means (user_outputs_count == 2)
        'accepted': True,
    },
    {
        # (sum(rewardamount) > ca3_minting_limit) within a transaction in different inputs/outputs, user_fee > 0: rejected
        'name': 'L03Ae',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN),
        'reward_to': 'other',
        'rewardamount': COIN * 10 // 365 * 2,
        'fee_total': 2000000,
        'fee_user_percent': 80,
        'keys_count_total': randint(2, 6),
        'ca3_minting_limit': COIN * 10 // 365 * 2 - 1600000 - 1,
        'user_outputs_dest': 'user+user',  # means (user_outputs_count == 2)
        'accepted': False,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED),
    },
    {
        # (sum(rewardamount) <= ca3_minting_limit) in different transactions (3 steps), user_fee == 0: accepted
        'name': 'L04',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'ca3_minting_limit': [ COIN * 10 // 365 * 3, COIN * 10 // 365 * 3 + 1, COIN * 10 // 365 * 300 ],
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': 'ben',
        'step2_accepted': True,
        'step3_enabled': True,
        'step3_wait_interval': 24 * 60 * 60,
        'step3_rewardamount': COIN * 10 // 365,
        'step3_reward_to': choice(['user', 'ben']),
        'step3_accepted': True,
        'acceptnonstdtxn': 1, # dust
    },
    {
        # (sum(rewardamount) > ca3_minting_limit) in different transactions (3 steps), user_fee == 0: rejected
        'name': 'L04e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'ca3_minting_limit': [ COIN * 10 // 365 * 2, COIN * 10 // 365 * 2 + 1, COIN * 10 // 365 * 3 - 1  ],
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': 'ben',
        'step2_accepted': True,
        'step3_enabled': True,
        'step3_wait_interval': 24 * 60 * 60,
        'step3_rewardamount': COIN * 10 // 365,
        'step3_reward_to': choice(['user', 'ben']),
        'step3_accepted': False,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED),
        'acceptnonstdtxn': 1, # dust
    },
    {
        # (ca3_block_timestamp + ca3_expiration_offset + 23h > mint_tx_time): accepted
        'name': 'L05',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_expiration_offset': 3600 + 120,
        'accepted': True,
    },
    {
        # (ca3_block_timestamp + ca3_expiration_offset + 23h < mint_tx_time): rejected
        'name': 'L05e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_expiration_offset': [3600 - 30, 0, -100],
        'accepted': False,
        'error': (64, BAD_REWARD_CERT_EXPIRED),
    },
    {
        # step2: (ca3_block_timestamp + ca3_expiration_offset + 23h > mint_tx_time): accepted
        'name': 'L06',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_expiration_offset': 3600 * 25 + 120,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': choice(['user', 'ben']),
        'step2_accepted': True,
    },
    {
        # step2: (ca3_block_timestamp + ca3_expiration_offset + 23h < mint_tx_time): rejected
        'name': 'L06e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_expiration_offset': 3600 * 25 - 30,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': choice(['user', 'ben']),
        'step2_accepted': False,
        'error': (64, BAD_REWARD_CERT_EXPIRED),
    },
    {
        # (rewardamount <= ca3_minting_limit && ca3_block_timestamp + ca3_expiration_offset + 23h > mint_tx_time): accepted
        'name': 'L07',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'ca3_minting_limit': COIN * 1000,
        'ca3_expiration_offset': 120,
        'accepted': True,
    },
    {
        # sum(allowed_rewardamount) > ca3_minting_limit and sum(actual_rewardamount) <= ca3_minting_limit: accepted
        # allowed_rewardamount: COIN * 10 // 365,
        'name': 'L08',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': [COIN * 10 // 365 - 10000, COIN * 10 // 365 - 20000],
        'fee_user_percent': 0,
        'ca3_minting_limit': COIN * 10 // 365 - 10000,
        'accepted': True,
    },
    {
        # (useramount <= ca3_daily_limit): accepted
        'name': 'L09',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': [100 * COIN, 100 * COIN + 1000],
        'accepted': True,
    },
    {
        # (useramount > ca3_daily_limit): rejected
        'name': 'L09e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': 100 * COIN - 1,
        'accepted': False,
        'error': (64, BAD_REWARD_DAILY_LIMIT_EXCEEDED),
    },
    {
        # (useramount1 + useramount2 <= ca3_daily_limit) in different transactions: accepted
        'name': 'L10',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': [100 * COIN * 2, 100 * COIN * 2 + 1000],
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 23 * 60 * 60 + 30,
        'step2_rewardamount': COIN * 10 * 23 // 24 // 365,
        'step2_reward_to': choice(['user', 'ben', 'other']),
        'step2_accepted': True,
    },
    {
        # (useramount1 + useramount2 > ca3_daily_limit) in different transactions: rejected
        'name': 'L10e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': 100 * COIN * 2 - 1,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 23 * 60 * 60 + 30,
        'step2_rewardamount': COIN * 10 * 23 // 24 // 365,
        'step2_reward_to': choice(['user', 'ben', 'other']),
        'step2_accepted': False,
        'error': (64, BAD_REWARD_DAILY_LIMIT_EXCEEDED),
    },
    {
        # (ca3_daily_limit <= 0): rejected
        'name': 'L11e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': [ 0, -100 ],
        'accepted': False,
        'error': (64, BAD_REWARD_DAILY_LIMIT_EXCEEDED),
    },
    {
        # (useramount1 <= ca3_daily_limit) --> wait 24h 30s --> (useramount2 <= ca3_daily_limit), where (useramount1 + useramount2 > ca3_daily_limit): accepted
        'name': 'L12',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': [ 100 * COIN, 100 * COIN * 3 // 2 ],
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60 + 30,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': choice(['user', 'ben', 'other']),
        'step2_daily_limit_used': 0,
        'step2_accepted': True,
    },
    {
        # (useramount1 + useramount2 <= ca3_daily_limit) within a transaction in different inputs/outputs: accepted
        'name': 'L13',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN),
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365 * 2,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': [100 * COIN * 2, 100 * COIN * 2 + 1000],
        'accepted': True,
    },
    {
        # (useramount1 + useramount2 > ca3_daily_limit) within a transaction in different inputs/outputs: rejected
        'name': 'L13e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN),
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365 * 2,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': 100 * COIN * 2 - 1,
        'accepted': False,
    },
    {
        # (useramount1 --> wait 24h 30s --> useramount2)
        # where (useramount1 == ca3_daily_limit), reward to user, (useramount2 > ca3_daily_limit): rejected
        'name': 'L14e',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': 100 * COIN,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 24 * 60 * 60 + 30,
        'step2_rewardamount': COIN * 10 // 365,
        'step2_reward_to': choice(['user', 'ben', 'other']),
        'step2_accepted': False,
        'error': (64, BAD_REWARD_DAILY_LIMIT_EXCEEDED),
    },
    {
        # (useramount <= ca3_daily_limit && rewardamount <= ca3_minting_limit): accepted
        'name': 'L15',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_minting_limit': [ COIN * 10 // 365, COIN * 10 // 365 + 1000 ],
        'ca3_daily_limit': [ 100 * COIN, 100 * COIN + 1000 ],
        'accepted': True,
    },
    {
        # (useramount > ca3_daily_limit && rewardamount <= ca3_minting_limit): rejected
        'name': 'L15e1',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_minting_limit': choice([COIN * 10 // 365, COIN * 10 // 365 + 1000]),
        'ca3_daily_limit': 100 * COIN - 1,
        'accepted': False,
        'error': (64, BAD_REWARD_DAILY_LIMIT_EXCEEDED),
    },
    {
        # (useramount <= ca3_daily_limit && rewardamount > ca3_minting_limit): rejected
        'name': 'L15e2',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_minting_limit': COIN * 10 // 365 - 1,
        'ca3_daily_limit': choice([100 * COIN, 100 * COIN + 1000]),
        'accepted': False,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED),
    },
    {
        # (useramount <= ca3_daily_limit && rewardamount <= ca3_minting_limit && ca3_block_timestamp + ca3_expiration_offset + 23h > mint_tx_time): accepted
        'name': 'L16',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_minting_limit': choice([COIN * 10 // 365, COIN * 10 // 365 + 1000]),
        'ca3_daily_limit': choice([100 * COIN, 100 * COIN + 1000]),
        'ca3_expiration_offset': 120,
        'accepted': True,
    },
    {
        # ca3_daily_limit == 2*X
        # useramount == X
        # mint useramount --> wait 23h --> mint useramount --> wait 23h --> mint useramount: accepted
        # (daily_limit_counter is reset after 24h from the first minting)
        # 0h - mint X (now daily_limit_counter == X)
        # 23h - mint X (now daily_limit_counter == 2*X)
        # 24h - reset (now daily_limit_counter == 0)
        # 46h - mint X (now daily_limit_counter == X)
        'name': 'L17',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 23 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['ben', 'other']),
        'rewardamount': COIN * 10 * 23 // 24 // 365,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': 200 * COIN,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 23 * 60 * 60 + 30,
        'step2_rewardamount': COIN * 10 * 23 // 24 // 365,
        'step2_reward_to': choice(['ben', 'other']),
        'step2_accepted': True,
        'step3_enabled': True,
        'step3_wait_interval': 23 * 60 * 60 + 30,
        'step3_rewardamount': COIN * 10 * 23 // 24 // 365,
        'step3_reward_to': choice(['user', 'ben']),
        'step3_daily_limit_used': 0,
        'step3_accepted': True,
    },

    #
    # E (error) series:
    #
    {
        # (revoke_root_cert): rejected
        'name': 'e00',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'revoke_root_cert': True,
        'accepted': False,
        'error': (64, BAD_PLC_CERTIFICATE),
    },
    {
        # (revoke_user_cert): rejected
        'name': 'e01',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'revoke_user_cert': True,
        'accepted': False,
        'error': (64, BAD_PLC_CERTIFICATE),
    },
    {
        # (invalid_root_cert, scenarios 1-6, 20-23): rejected
        'name': 'e02',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'invalid_root_cert': [ 1, 2, 3, 4, 5, 6, 20, 21, 22, 23 ],
        'accepted': False,
        'error': (64, BAD_PLC_CERTIFICATE),
    },
    {
        # (invalid_user_cert, scenarios 1-5, 20-23): rejected
        'name': 'e03',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'invalid_user_cert': [ 1, 2, 3, 4, 5, 20, 21, 22, 23 ],
        'accepted': False,
        'error': (64, [BAD_PLC_CERTIFICATE, BAD_REWARD_SCRIPT, BAD_REWARD_INV_USER_ADDRESS]),
    },
    {
        # invalid_refill_moneybox, scenarios 1-5: minting is accepted, refill_moneybox is rejected
        'name': 'e04',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': False,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 10000 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 1000 * 30 // 365,
        'fee_user_percent': 0,
        'refill_moneybox': 'script',
        'invalid_refill_moneybox': [ 1, 2, 3, 4, 5 ],
        'blockchain_height': [ 499, 500, 501 ],
        'accepted': True,
        'refill_moneybox_accepted': False,
    },
    {
        # forbidden refill_moneybox_dest: minting is accepted, refill_moneybox is rejected
        'name': 'e04A',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 5000 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 500 * 30 // 365,
        'fee_user_percent': 0,
        'refill_moneybox': 'script',
        'refill_moneybox_dest': [ 'user', 'ben', 'other', 'other_p2sh' ],
        'accepted': True,
        'refill_moneybox_accepted': False,
    },
    {
        # forbidden refill_moneybox_dest (op_true, op_false) with acceptnonstdtxn=1: minting is accepted, refill_moneybox is rejected
        'name': 'e04B',
        'rootcertamount': 1 * COIN,
        'greenflag': False,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 38 * 24 * 60 * 60,
        'usermoney_age': 35 * 24 * 60 * 60,
        'useramount': 5000 * COIN,
        'reward_to': 'user',
        'rewardamount': COIN * 500 * 30 // 365,
        'fee_user_percent': 0,
        'refill_moneybox': 'script',
        'acceptnonstdtxn': 1,
        'refill_moneybox_dest': ['op_true', 'op_false'],
        'accepted': True,
        'refill_moneybox_accepted': False,
    },
    {
        # (based on base00, moneybox_outputs_count == 2): rejected
        'name': 'e05',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'ben', 'other'],
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'moneybox_change_dest': 'moneybox+moneybox', # means (moneybox_outputs_count == 2)
        'accepted': False,
        'error': (64, BAD_REWARD_MANY_MONEYBOX_OUTPUTS),
    },
    {
        # (based on base00, user_outputs_count == 2, more than user inputs): rejected
        'name': 'e06',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'ben', 'other'],
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'user_outputs_dest': 'user+user', # means (user_outputs_count == 2)
        'accepted': False,
        'error': (64, BAD_REWARD_MANY_USER_OUTPUTS),
    },
    {
        # based on base00, user_inputs_count == 2, user_outputs_count == 3, more than user inputs: rejected
        'name': 'e07',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 200 * COIN),
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 30 // 365,
        'fee_user_percent': 'auto',
        'user_outputs_dest': 'user+user+user', # means (user_outputs_count == 3)
        'accepted': False,
        'error': (64, BAD_REWARD_MANY_USER_OUTPUTS),
    },
    {
        # moneybox_change_dest == [forbidden combinations]: rejected
        'name': 'e08',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN),  # to avoid error BAD_REWARD_MANY_USER_OUTPUTS for (moneybox_change_dest == 'user')
        'reward_to': 'user',                     # to avoid error BAD_REWARD_MANY_BEN_OUTPUTS for (moneybox_change_dest to ben/other)
        'rewardamount': COIN * 10 // 365 * 2,
        'fee_user_percent': 'auto',
        'moneybox_change_dest': [ 'user', 'ben', 'other_p2pkh', 'other_p2sh', 'user+ben' ],
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # moneybox_change_dest == [forbidden combinations] with acceptnonstdtxn=1: rejected
        'name': 'e08A',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN),  # to avoid error BAD_REWARD_MANY_USER_OUTPUTS for (moneybox_change_dest == 'user')
        'reward_to': 'user',                     # to avoid error BAD_REWARD_MANY_BEN_OUTPUTS for (moneybox_change_dest to ben/other)
        'rewardamount': 10 * COIN // 365 * 2,
        'fee_user_percent': 'auto',
        'acceptnonstdtxn': 1,
        'moneybox_change_dest': ['op_true', 'op_false', 'moneybox+op_false'],
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # reward to ben/other and moneybox_change_dest to ben/other: rejected
        'name': 'e08B',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['ben', 'other'],
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'moneybox_change_dest': ['ben', 'other_p2pkh', 'other_p2sh'],
        'accepted': False,
        'error': (64, BAD_REWARD_MANY_BEN_OUTPUTS),
    },
    {
        # based on base00, moneybox_outputs_count == 0 (don't return change to moneybox, leave 1/2 of it to miner): accepted
        'name': 'e09',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'ben'],
        'rewardamount': COIN * 10 // 365,
        'fee_total': '0.01',
        'fee_user_percent': 'auto',
        'refill_moneybox': 'script',
        'moneybox_change_dest': '',
        'accepted': True,
        'refill_moneybox_accepted': False,
    },
    {
        # based on base00, moneybox_outputs_count == 0 (don't return change to moneybox, leave 1/2 of it to miner),
        # but when reward_to 'other' - rejected
        'name': 'e09A',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'other',
        'rewardamount': COIN * 10 // 365,
        'fee_total': '0.01',
        'fee_user_percent': 'auto',
        'moneybox_change_dest': '',
        'accepted': False,
        # error: 'non-mandatory-script-verify-flag (Bad reward, less than transaction fee)'
    },
    {
        # based on base00, extra_moneybox_inputs_count == 1: rejected
        'name': 'e10',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'extra_moneybox_inputs_count': 1,
        'moneybox_change_dest': 'moneybox',
        'accepted': False,
        'error': (16, 'bad-txns-moneybox-value-toolarge'),
    },
    {
        # based on base00, extra_moneybox_inputs_count == 1: rejected
        'name': 'e10A',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'extra_moneybox_inputs_count': 1,
        'moneybox_change_dest': 'moneybox+moneybox',
        'accepted': False,
        'error': (64, [BAD_REWARD_MANY_MONEYBOX_INPUTS, BAD_REWARD_MANY_MONEYBOX_OUTPUTS]),
    },
    {
        # different forbidden combinations for user_outputs_dest: rejected
        'name': 'e11',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'user_outputs_dest': [ 'moneybox', 'ben', 'other_p2pkh', 'other_p2sh', 'user+moneybox', 'user+ben', 'user+other', '' ],
        'accepted': False,
    },
    {
        # different forbidden combinations for user_outputs_dest with acceptnonstdtxn=1: rejected
        'name': 'e11A',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'acceptnonstdtxn': 1,
        'user_outputs_dest': ['op_true', 'op_false'],
        'accepted': False,
    },
    {
        # based on base00, both (user_outputs_dest and moneybox_change_dest) == nothing: rejected
        'name': 'e12',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': choice(['ben', 'other']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'user_outputs_dest': '',
        'moneybox_change_dest': '',
        'accepted': False,
        # error: 'non-mandatory-script-verify-flag (unknown error)'
    },
    {
        # based on base00, forbidden user_outputs_dest combinations: rejected
        'name': 'e14',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': ['user', 'ben'],
        'rewardamount': 10 * COIN // 365,
        'fee_user_percent': 'auto',
        'keys_count_total': randint(2,12), # for user_shuffled min 2 keys
        'sig_model': 'multisig',
        'user_outputs_dest': 'user_shuffled',
        'accepted': False,
        # error:
        #   for (reward_to == user): 'non-mandatory-script-verify-flag (unknown error)'
        #   for (reward_to == ben): BAD_REWARD_MANY_BEN_OUTPUTS
    },
    {
        # based on base00, reward_outputs > user_outputs: rejected
        'name': 'e15',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': [ 'ben+ben', 'other+other', 'ben+other' ],
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'accepted': False,
        'error': (64, BAD_REWARD_MANY_BEN_OUTPUTS),
    },
    {
        # useramount == 0 (no user inputs), user_outputs_dest == '' (no user outputs): rejected
        'name': 'e16',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 0,
        'reward_to': 'ben',
        'rewardamount': 1 * COIN,
        'fee_user_percent': 0,
        'user_outputs_dest': '',
        'accepted': False,
        'error': (64, BAD_REWARD_COMMON),
    },
    {
        # invalid_signature: rejected
        'name': 'e17A',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'keys_count_total': randint(5, 12),
        'keys_count_required': randint(1, 4),
        'invalid_signature': [100, 101, 102, 110, 200],
        'accepted': False,
        'error': (16, 'mandatory-script-verify-flag-failed'),
    },
    {
        # invalid_signature: rejected
        'name': 'e17B',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'keys_count_total': randint(5, 12),
        'keys_count_required': randint(2, 4),
        'invalid_signature': [111, 112],
        'sig_model': 'multisig',
        'accepted': False,
        'error': (16, 'mandatory-script-verify-flag-failed'),
    },
    {
        # invalid_signature in moneybox inputs: rejected
        'name': 'e17C',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'keys_count_total': randint(5, 12),
        'keys_count_required': randint(1, 4),
        'invalid_signature': [201, 202, 203, 210],
        'accepted': False,
        'error': (64, [BAD_REWARD_INV_SIGNATURE, BAD_PLC_CERTIFICATE, NON_CANONICAL_SIGNATURE]),
    },
    {
        # invalid_signature in moneybox inputs: rejected
        'name': 'e17D',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 22 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'keys_count_total': randint(5, 12),
        'keys_count_required': randint(2, 4),
        'invalid_signature': [204, 211, 212],
        'sig_model': 'multisig',
        'accepted': False,
        'error': (64, [BAD_REWARD_INV_SIGNATURE, BAD_PLC_CERTIFICATE, NON_CANONICAL_SIGNATURE]),
    },
    {
        # zero_change_to_moneybox, with change to moneybox and without it: rejected
        'name': 'e18',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 365 * 100 * COIN,
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': [6 * COIN, 10 * COIN],
        'fee_user_percent': 100,
        'zero_change_to_moneybox': 1,
        'accepted': False,
        'error': (64, DUST),
    },
    {
        # use (separate_white == True) not in minting 3.0: rejected
        'name': 'e19',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 0,
        'separate_white': True,
        'accepted': False,
        'error': (64, [BAD_REWARD_INV_USER_ADDRESS, BAD_REWARD_SCRIPT]),
    },

    #
    # Special series:
    #
    {
        # minting_limit is checked always, but is applied only when generating a block;
        # so many transactions less or equal to limit each will be accepted to mempool and they all will enter a block
        # Testcase: send one by one 3 transactions with minted amount equal to minting limit,
        # and generate a new block after it. Summary minting limit is exceeded, but they
        # all will be included into this block, because limit is applied only when generating a new block.
        # [accepted]
        'name': 'special_minting_limit_mempool',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN, 100 * COIN),
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_minting_limit': COIN * 10 // 365,
        'accepted': True,
        'error': (64, BAD_REWARD_LIMIT_EXCEEDED), # needed for reject step
    },
    {
        # [accepted]
        'name': 'special_minting_limit_fork_blocks',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN, 100 * COIN),
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'refill_moneybox': 'script',
        'ca3_minting_limit': COIN * 10 // 365 * 2,
        'accepted': True,
    },
    {
        # daily_limit is checked always, but is applied only when generating a block;
        # so many transactions less or equal to limit each will be accepted to mempool and they all will enter a block
        # Testcase: send one by one 3 transactions with usercoins amount equal to daily limit,
        # and generate a new block after it. Summary daily limit is exceeded, but they
        # all will be included into this block, because limit is applied only when generating a new block.
        # [accepted]
        'name': 'special_daily_limit_mempool',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN, 100 * COIN),
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'ca3_daily_limit': 100 * COIN,
        'accepted': True,
        'error': (64, BAD_REWARD_DAILY_LIMIT_EXCEEDED), # needed for reject step
    },
    {
        # [accepted]
        'name': 'special_daily_limit_fork_blocks',
        'rootcertamount': 1 * COIN,
        'greenflag': True,
        'ca3certamount': 1000000,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (100 * COIN, 100 * COIN, 100 * COIN),
        'reward_to': choice(['user', 'ben']),
        'rewardamount': COIN * 10 // 365,
        'fee_user_percent': 'auto',
        'refill_moneybox': 'script',
        'ca3_daily_limit': 100 * COIN * 2,
        'accepted': True,
    },
    {
        # spend all the moneybox, then try to mint using immature moneybox change: accepted
        # keys_count_total == 1 (for less complexity),
        'name': 'special_use_immature_moneybox_change',
        'rootcertamount': 10 * COIN,
        'greenflag': True,
        'ca3certamount': 10 * COIN,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN),
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': 0,  # is used inside the testcase
        'fee_user_percent': 100,
        'keys_count_total': 1,
        'keys_count_required': 1,
        'blockchain_height': 200,
        'accepted': True,
    },
    {
        # spend all the moneybox, then try to mint using moneybox change from mempool (not even from block): accepted
        # keys_count_total == 1 (for less complexity),
        'name': 'special_use_immature_moneybox_mempool',
        'rootcertamount': 10 * COIN,
        'greenflag': True,
        'ca3certamount': 10 * COIN,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN),
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': 0,  # is used inside the testcase
        'fee_user_percent': 100,
        'keys_count_total': 1,
        'keys_count_required': 1,
        'blockchain_height': 200,
        'accepted': True,
    },
    {
        # spend all the moneybox, then try to mint using immature moneybox coinbase inputs: rejected
        # keys_count_total == 1 (for less complexity),
        'name': 'special_use_immature_moneybox_coinbase',
        'rootcertamount': 10 * COIN,
        'greenflag': True,
        'ca3certamount': 10 * COIN,
        'ben_enabled': True,
        'ca3_age': 24 * 60 * 60,
        'usermoney_age': 24 * 60 * 60,
        'useramount': (5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN, 5000 * COIN),
        'reward_to': choice(['user', 'ben', 'other']),
        'rewardamount': 0, # is used inside the testcase
        'fee_user_percent': 100,
        'keys_count_total': 1,
        'keys_count_required': 1,
        'blockchain_height': 200,
        'accepted': False,
        'error': (16, PREMATURE_SPEND_OF_COINBASE),
    },

    #
    # sh series (silver hoof, or minting 3.0) and ab-minting:
    #
    {
        # base positive scenario: accepted
        'name': 'sh_ab_base',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked+other_locked',
        'rewardamount': 10 * COIN * 5,
        'fee_user_percent': 0,
        'user_outputs_dest': ['user', 'user_locked', 'user_ab', 'user_ab_locked'],
        'sig_model': 'singlesig',
        'accepted': True,
    },
    {
        # reward is less than allowed, including zero: accepted
        'name': 'sh_ab_01',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked+other_locked',
        'rewardamount': [2 * COIN * 5, 0],
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'accepted': True,
    },
    {
        # reward is more than allowed: rejected
        'name': 'sh_ab_01e1',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked+other_locked',
        'rewardamount': 10 * COIN * 5 + 1,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # reward is more than allowed by root cert: rejected
        'name': 'sh_ab_01e2',
        'rootcertamount': 1000000,
        'ca3certamount': 2000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked+other_locked',
        'rewardamount': 10 * COIN * 5 + 1,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (reward is more than allowed by user cert): rejected
        'name': 'sh_ab_01e3',
        'rootcertamount': 2000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked+other_locked',
        'rewardamount': 10 * COIN * 5 + 1,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (user_outputs_count <= user_inputs_count + 2): accepted
        'name': 'sh_ab_02',
        'rootcertamount': 2000000,
        'ca3certamount': 2000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': (50 * COIN, 100 * COIN),
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked+other+other_locked',
        'rewardamount': 30 * COIN * 6,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': ['user+'*4, 'user+user+user_ab+user_ab'],
        'accepted': True,
    },
    {
        # (user_outputs_count > user_inputs_count + 2): rejected
        'name': 'sh_ab_02e',
        'rootcertamount': 2000000,
        'ca3certamount': 2000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': (50 * COIN, 100 * COIN),
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked+other+other_locked',
        'rewardamount': 30 * COIN * 6,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': 'user+user+user+user_ab+user_ab',
        'accepted': False,
        'error': (64, BAD_REWARD_MANY_USER_OUTPUTS),
    },
    {
        # user output amount is less than user input amount (and no reward outputs): accepted
        'name': 'sh_ab_03',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'join_user_reward_to_user_outputs': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'user',
        'rewardamount': '0.01',
        'fee_total': '0.11',
        'fee_user_percent': 100,
        'sig_model': 'singlesig',
        'accepted': True,
    },
    {
        # user output amount is more than user input amount: accepted
        'name': 'sh_ab_03A',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'join_user_reward_to_user_outputs': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'user+ben',
        'rewardamount': 10 * COIN,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'accepted': True,
    },
    {
        # reward to user: accepted
        'name': 'sh_ab_04',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'join_user_reward_to_user_outputs': False,
        'ben_enabled': False,
        'useramount': 100 * COIN,
        'reward_to': choice(['user', 'user+other']),
        'rewardamount': 10 * COIN,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'accepted': True,
    },
    {
        # (user_outputs_dest and reward_to) to all possible destinations: accepted
        'name': 'sh_ab_05',
        'rootcertamount': 25000000,
        'ca3certamount': 2500000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': (60 * COIN, 100 * COIN),
        'reward_to': 'ben+ben_locked+other+other_locked+ben_ab+ben_ab_locked',
        'rewardamount': 40 * 6 * COIN,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': 'user+user_locked+user_ab+user_ab_locked',
        'accepted': True,
    },
    {
        # sh_ab_05, reward is more than allowed: rejected
        'name': 'sh_ab_05e',
        'rootcertamount': 25000000,
        'ca3certamount': 2500000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': (60 * COIN, 100 * COIN),
        'reward_to': 'ben+ben_locked+other+other_locked+ben_ab+ben_ab_locked',
        'rewardamount': 40 * 6 * COIN + 1,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': 'user+user_locked+user_ab+user_ab_locked',
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # base positive scenario with (gen_block_after_fill_user == False): accepted
        'name': 'sh_ab_06',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': choice(['ben+ben_locked+other', 'ben_ab+other+other_locked', 'ben+ben_ab+ben_ab_locked']),
        'rewardamount': 30 * COIN,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': choice(['user', 'user_locked', 'user_ab', 'user_ab_locked']),
        'gen_block_after_fill_user': False,
        'accepted': True,
    },
    {
        # base positive scenario, but without sivler_hoof flag: rejected
        'name': 'sh_ab_08e',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': False,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': choice(['ben+ben_locked+other', 'ben_ab+other+other_locked', 'ben+ben_ab+ben_ab_locked']),
        'rewardamount': 30 * COIN,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': choice(['user', 'user_locked', 'user_ab', 'user_ab_locked']),
        'accepted': False,
        'error': (64, BAD_REWARD_NOT_MATURE),
    },
    {
        # no user outputs and no reward (all user input amount to miner): accepted
        'name': 'sh_ab_09',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': '',
        'rewardamount': 0,
        'fee_user_percent': [0, 100],
        'sig_model': 'singlesig',
        'user_outputs_dest': '',
        'accepted': True,
    },
    {
        # lock user outputs and then spend them in step2: accepted
        # only available in singlesig model
        'name': 'sh_ab_10',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': (60 * COIN, 60 * COIN),
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked',
        'rewardamount': 12 * COIN * 4,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': ['user+user_locked', 'user+user_ab_locked', 'user_locked+user_ab_locked', 'user+user_locked+user_ab_locked'],
        'lock_interval_min': 30 * 24 * 60 * 60,
        'lock_interval_max': 45 * 24 * 60 * 60,
        'max_blocks_in_wait_cycle': 200,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 2 * 30 * 24 * 60 * 60,
        'step2_rewardamount': 12 * COIN * 4,
        'step2_reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked',
        'step2_user_outputs_dest': 'user+user_locked+user_ab+user_ab_locked',
        'step2_accepted': True,
    },
    {
        # lock user outputs and then spend them in step2 (exotic cases): accepted
        'name': 'sh_ab_10A',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': (30 * COIN, 30 * COIN, 60 * COIN),
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked',
        'rewardamount': 12 * COIN * 4,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': 'user+user_locked+user_ab_ex2+user_ab_ex3+user_ab_locked',
        'lock_interval_min': 30 * 24 * 60 * 60,
        'lock_interval_max': 45 * 24 * 60 * 60,
        'max_blocks_in_wait_cycle': 200,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 2 * 30 * 24 * 60 * 60,
        'step2_rewardamount': 12 * COIN * 4,
        'step2_reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked',
        'step2_user_outputs_dest': 'user+user_locked+user_ab+user_ab_ex2+user_ab_ex3+user_ab_locked',
        'step2_accepted': True,
    },
    {
        # spend_reward: spend ben_ab_locked[A] after waiting: spend_reward_accepted
        'name': 'sh_ab_11',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'ben_ab_locked+' * 4,
        'rewardamount': 40 * COIN,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': 'user_ab_locked',
        'lock_intervals': (3600, 3600 * 2, 3600 * 4, 3600 * 8, 3600 * 16),
        'accepted': True,
        'spend_reward': 'ben_ab_locked[A][0]',
        'spend_reward_wait': [ 3600 * 3, 3600 * 17 ],
        'spend_reward_accepted': True,
    },
    {
        # spend_reward: spend ben_ab_locked[A] with wrong wait interval: spend_reward_rejected
        'name': 'sh_ab_11e',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'ben_ab_locked+' * 4,
        'rewardamount': 40 * COIN,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': 'user_ab_locked',
        'max_blocks_in_wait_cycle': 100,
        'lock_intervals': (3600, 3600 * 2, 3600 * 4, 3600 * 8, 3600 * 16),
        'accepted': True,
        'spend_reward': 'ben_ab_locked[A][2]',
        'spend_reward_wait': 3600 * 7,
        'spend_reward_accepted': False,
        'error': (64, BAD_LOCKTIME_REQUIREMENT),
    },
    {
        # spend_reward: spend ben_ab_locked[B]: spend_reward_accepted
        'name': 'sh_ab_12',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'ben_ab_locked+' * 4,
        'rewardamount': 10 * COIN * 4,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': 'user_ab_locked',
        'max_blocks_in_wait_cycle': 100,
        'lock_intervals': (3600, 3600 * 2, 3600 * 4, 3600 * 8, 3600 * 16),
        'accepted': True,
        'spend_reward': 'ben_ab_locked[B][1]',
        'spend_reward_wait': [0, 3600 * 18],
        'spend_reward_accepted': True,
    },
    {
        # with step2_spend_inputs_with_proj_key: all inputs
        'name': 'sh_ab_13',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': (60 * COIN, 60 * COIN),
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked',
        'rewardamount': 12 * COIN * 4,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': 'user_ab+user_ab_locked',
        'lock_interval_min': 30 * 24 * 60 * 60,
        'lock_interval_max': 45 * 24 * 60 * 60,
        'max_blocks_in_wait_cycle': 200,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': choice([0, 2 * 24 * 60 * 60]),
        'step2_rewardamount': 12 * COIN * 4,
        'step2_reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked',
        'step2_user_outputs_dest': 'user+user_locked+user_ab+user_ab_locked',
        'step2_spend_inputs_with_proj_key': (0,1),
        'step2_accepted': True,
    },
    {
        # with step2_spend_inputs_with_proj_key: not all inputs
        'name': 'sh_ab_13A',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': (60 * COIN, 60 * COIN),
        'reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked',
        'rewardamount': 12 * COIN * 4,
        'fee_user_percent': 0,
        'sig_model': 'singlesig',
        'user_outputs_dest': ['user_ab+user_ab_locked', 'user_ab_locked+user_ab_locked'],
        'lock_interval_min': 30 * 24 * 60 * 60,
        'lock_interval_max': 45 * 24 * 60 * 60,
        'max_blocks_in_wait_cycle': 200,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': 2 * 30 * 24 * 60 * 60,
        'step2_rewardamount': 12 * COIN * 4,
        'step2_reward_to': 'ben+ben_locked+ben_ab+ben_ab_locked',
        'step2_user_outputs_dest': 'user+user_locked+user_ab+user_ab_locked',
        'step2_spend_inputs_with_proj_key': (0,),
        'step2_accepted': True,
    },
]


testcases_map = {}

def expand_parameter(testcases_array, t, param_name):
    if param_name in t and isinstance(t[param_name], list):
        assert (param_name != 'name')  # name cannot be expanded
        for v in t[param_name]:
            t2 = copy.deepcopy(t)
            t2[param_name] = v
            t2['name'] += ('_' + param_name + '_' + str(v))
            expand_testcase(testcases_array, t2)
        return True
    return False

def expand_testcase(testcases_array, t):
    expanded = False
    keys = [*t]
    keys.sort()
    for param in keys:
        if expand_parameter(testcases_array, t, param):
            expanded = True
            break
    if not expanded:
        testcases_array.append(t)

def get_minting_testcases():
    global testcases_map
    if len(testcases_map) > 0:
        return testcases_map
    testcases_array = []
    for t in testcases_templates:
        expand_testcase(testcases_array, t)
    for t in testcases_array:
        if t['name'] in testcases_map:
            raise AssertionError('Duplicated name in testcases: {}'.format(t['name']))
        testcases_map[t['name']] = t
    return testcases_map
