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
DELTA_REWARD = 1
ONE_HOUR = 3600
ONE_DAY = ONE_HOUR * 24
ONE_MONTH = ONE_DAY * 30
ONE_YEAR = ONE_DAY * 365

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
                                    #   5: invalid root certificate, with unknown root key not mentioned in genesis block
                                    #   60-69: root certificate with root key mentioned in genesis block, but not in the first entry: 6x, where x is index, example: 62 means use key[2]
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
'gen_block_after_fill_user': False, # Generate block after fill up user's address, True/False (when false and no wait time and no pack_tx_into_block, user inputs in mint tx will be from mempool), default True
'gen_block_after_cert': False,      # Generate block after creating certificate(s), True/False (when false and no wait time and no pack_tx_into_block, certificate inputs in mint tx will be from mempool), default True
'pack_tx_into_block': True,         # When true, pack cert_tx, mint_tx into a block and send msg_block to node; otherwise send msg_tx to node; True/False, default False
'separate_white': True,             # User PKH (in minting 3.0 is called white) is not mentioned in user certificate, True/False, default False
'ben_percent': '0.01',              # Certificate contains flag 0x00000020 (hasBenefitiaryPercent) and amount indicating this percent, is used in funding; int in satoshi, string or Decimal in coins, default None
'free_ben_percent': '0.02',         # Certificate contains flag 0x00000040 (hasFreeBenPercent) and amount indicating this percent, is used in funding; int in satoshi, string or Decimal in coins, default None
'spend_reward': 'ben_ab[a][0]',     # Spend reward output from mint tx, [a] (means a key with timelock) or [b] (means multisig a+b), [i] means reward output index - which exactly reward output
'spend_reward_wait': 3600,          # Wait before spending reward output, int, in seconds, default 0  
'spend_reward_accepted': False,     # spend_reward_accepted, True/False
'tx_version': 3,                    # Version of transaction, int, default random [1,2]; was introduces for tx version 3, later this functionality was removed
'skip_test': True,                  # Skip test, bool, default False
'use_burn': False,                  # Burn 3% of minted amount to grave, True/False, default True
'user_outputs_ratio': '2:3',        # Proportion to distribute money between user outputs, default equally; must be (len(user_outputs) == coefficients_count)

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
    #
    # shu series (silver hoof ultima):
    #

    {
        # classic positive scenario: accepted
        'name': 'shu_base',
        'rootcertamount': 1000000,
        'ca3certamount': 1000000,
        'sivler_hoof': True,
        'ben_enabled': True,
        'useramount': 100 * COIN,
        'reward_to': 'ben',
        'rewardamount': 10 * COIN,
        'fee_user_percent': 0,
        'user_outputs_dest': 'user_locked',
        'lock_intervals': (ONE_YEAR,),
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_base_e',
        'parent_testcase': 'shu_base',
        'rewardamount': 10 * COIN + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # lock_intervals > 1y: accepted
        'name': 'shu_01',
        'parent_testcase': 'shu_base',
        'rewardamount': 30 * COIN,
        'lock_intervals': (3 * ONE_YEAR,),
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_01e',
        'parent_testcase': 'shu_01',
        'rewardamount': 30 * COIN + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # lock_intervals < 1y: accepted
        'name': 'shu_02',
        'parent_testcase': 'shu_base',
        'rewardamount': 10 * COIN // 4,
        'lock_intervals': (ONE_YEAR // 4,),
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_02e',
        'parent_testcase': 'shu_02',
        'rewardamount': 10 * COIN // 4 + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # user outputs to user, not locked: rejected
        'name': 'shu_03e',
        'parent_testcase': 'shu_base',
        'rewardamount': 10 * COIN,
        'user_outputs_dest': 'user',
        'accepted': False,
        'error': (64, None),
    },
    {
        # user outputs to user_locked + user_locked in proportion (3:1): count only 1 with max amount: accepted
        'name': 'shu_04',
        'parent_testcase': 'shu_base',
        'rewardamount': 10 * COIN * 3 // 4,
        'user_outputs_dest': 'user_locked+user_locked',
        'user_outputs_ratio': '3:1',
        'lock_intervals': [(ONE_YEAR, ONE_YEAR * 2), (ONE_YEAR, ONE_YEAR // 2)],
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_04e',
        'parent_testcase': 'shu_04',
        'rewardamount': 10 * COIN * 3 // 4 + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # user outputs to user + user_locked in proportion (3:1): count only locked one with max amount: accepted
        'name': 'shu_05',
        'parent_testcase': 'shu_base',
        'rewardamount': 10 * COIN // 4,
        'user_outputs_dest': 'user+user_locked',
        'user_outputs_ratio': '3:1',
        'lock_intervals': (ONE_YEAR,),
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_05e',
        'parent_testcase': 'shu_05',
        'rewardamount': 10 * COIN // 4 + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # base positive scenario, but without sivler_hoof flag: rejected
        'name': 'shu_06e',
        'parent_testcase': 'shu_base',
        'sivler_hoof': False,
        'accepted': False,
        'error': (64, BAD_REWARD_NOT_MATURE),
    },
    {
        # lock user outputs and then spend them in step2: accepted
        # only available in singlesig model
        'name': 'shu_07',
        'parent_testcase': 'shu_base',
        'rewardamount': 10 * COIN // 4,
        'sig_model': 'singlesig',
        'user_outputs_dest': ['user+user_locked', 'user_locked+user_locked'],
        'lock_intervals': (ONE_YEAR // 2, ONE_YEAR // 2),
        'max_blocks_in_wait_cycle': 200,
        'accepted': True,
        'step2_enabled': True,
        'step2_wait_interval': ONE_YEAR // 2 + ONE_MONTH,
        'step2_rewardamount': 10 * COIN // 2,
        'step2_reward_to': 'ben',
        'step2_user_outputs_dest': 'user_locked',
        'step2_accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_07e',
        'parent_testcase': 'shu_07',
        'step2_rewardamount': 10 * COIN // 2 + DELTA_REWARD,
        'step2_accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },

    {
        # (rootcertamount < ca3certamount), use ca3certamount: accepted
        'name': 'shu_08',
        'parent_testcase': 'shu_base',
        'rootcertamount': 500000,
        'rewardamount': 5 * COIN,
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_08e',
        'parent_testcase': 'shu_08',
        'rewardamount': 5 * COIN + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # (ca3certamount < rootcertamount), use rootcertamount: accepted
        'name': 'shu_09',
        'parent_testcase': 'shu_base',
        'ca3certamount': 200000,
        'rewardamount': 2 * COIN,
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_09e',
        'parent_testcase': 'shu_09',
        'rewardamount': 2 * COIN + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # reward to ben+other, reward per transaction, not per output: accepted
        'name': 'shu_10',
        'parent_testcase': 'shu_base',
        'reward_to': 'ben+other',
        'rewardamount': 10 * COIN,
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_10e',
        'parent_testcase': 'shu_10',
        'rewardamount': 10 * COIN + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # large amounts, small percent and lock period: accepted
        'name': 'shu_11',
        'parent_testcase': 'shu_base',
        'rootcertamount': 100000,  # 1 % per year
        'useramount': 100000 * COIN,
        'rewardamount': 1000 * COIN // 365 // 24,
        'lock_intervals': (ONE_HOUR,),
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_11e',
        'parent_testcase': 'shu_11',
        'rewardamount': 1600 * COIN // 365 // 24 + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # large amounts, large percent and lock period: accepted
        'name': 'shu_12',
        'parent_testcase': 'shu_base',
        'rootcertamount': 10000000,  # 100 % per year
        'ca3certamount': 10000000,  # 100 % per year
        'useramount': 20000 * COIN,
        'rewardamount': 40000 * COIN,
        'lock_intervals': (ONE_YEAR * 2,),
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_12e',
        'parent_testcase': 'shu_12',
        'rewardamount': 40000 * COIN + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # multiple user_locked outputs: accepted
        'name': 'shu_13',
        'parent_testcase': 'shu_base',
        'rewardamount': 10 * COIN * 95 // 100,
        'user_outputs_dest': 'user_locked+' * 6,
        'user_outputs_ratio': '95:1:1:1:1:1',
        'lock_intervals': (ONE_YEAR,) * 6,
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_13e',
        'parent_testcase': 'shu_13',
        'rewardamount': 10 * COIN * 95 // 100 + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # reward to user and/or user_locked (with separate output): burn is not needed: accepted
        'name': 'shu_14',
        'parent_testcase': 'shu_base',
        'ben_enabled': False,
        'reward_to': ['user', 'user_locked', 'user+user_locked'],
        'join_user_reward_to_user_outputs': False,
        'rewardamount': 10 * COIN,
        'use_burn': False,
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_14e',
        'parent_testcase': 'shu_14',
        'rewardamount': 10 * COIN + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # reward to user_locked (increasing existing locked user output and consequently reward calc base), burn is not needed: accepted
        'name': 'shu_15',
        'parent_testcase': 'shu_base',
        'ben_enabled': False,
        'reward_to': 'user_locked',
        'join_user_reward_to_user_outputs': True,
        'rewardamount': 100 * COIN // 9,
        'use_burn': False,
        'accepted': True,
    },
    {
        # previous case, rewardamount is more than allowed: rejected
        'name': 'shu_15e',
        'parent_testcase': 'shu_15',
        'rewardamount': 100 * COIN // 9 + DELTA_REWARD,
        'accepted': False,
        'error': (64, BAD_REWARD_ROBBERY),
    },
    {
        # BC-617: root certificate created after block 512 is invalid
        'name': 'shu_16',
        'parent_testcase': 'shu_base',
        'blockchain_height': 510,
        'accepted': True,
    },
    {
        # previous case, (blockchain_height == 512): rejected
        'name': 'shu_16e',
        'parent_testcase': 'shu_16',
        'blockchain_height': 512,
        'accepted': False,
        'error': (64, BAD_PLC_CERTIFICATE),
    },
    {
        # invalid_root_cert = [60-69] is valid
        'name': 'shu_17',
        'parent_testcase': 'shu_base',
        'invalid_root_cert': list(range(60,70)),
        'accepted': True,
    },
    {
        # use (separate_white == True) in minting 3.0: accepted
        'name': 'shu_18',
        'parent_testcase': 'shu_base',
        'separate_white': True,
        'accepted': True,
    },

    #
    # E (error) series:
    #
    {
        # (revoke_root_cert): rejected
        'name': 'shu_e01',
        'parent_testcase': 'shu_base',
        'revoke_root_cert': True,
        'accepted': False,
        'error': (64, BAD_PLC_CERTIFICATE),
    },
    {
        # (revoke_user_cert): rejected
        'name': 'shu_e02',
        'parent_testcase': 'shu_base',
        'revoke_user_cert': True,
        'accepted': False,
        'error': (64, BAD_PLC_CERTIFICATE),
    },
    {
        # (invalid_root_cert, scenarios 1-5, 20-23): rejected
        'name': 'shu_e03',
        'parent_testcase': 'shu_base',
        'invalid_root_cert': [1, 2, 3, 4, 5, 20, 21, 22, 23],
        'accepted': False,
        'error': (64, BAD_PLC_CERTIFICATE),
    },
    {
        # (invalid_user_cert, scenarios 1-4, 20-23): rejected
        # scenario 5 was invalid in minting 1.0, but is valid in 3.0
        'name': 'shu_e04',
        'parent_testcase': 'shu_base',
        'invalid_user_cert': [1, 2, 3, 4, 20, 21, 22, 23],
        'accepted': False,
        'error': (64, [BAD_PLC_CERTIFICATE, BAD_REWARD_SCRIPT, BAD_REWARD_INV_USER_ADDRESS]),
    },
    {
        # invalid_refill_moneybox, scenarios 1-5: minting is accepted, refill_moneybox is rejected
        'name': 'shu_e05',
        'parent_testcase': 'shu_base',
        'refill_moneybox': 'script',
        'invalid_refill_moneybox': [1, 2, 3, 4, 5],
        'blockchain_height': [499, 501],
        'useramount': 10000 * COIN,
        'rewardamount': 10000 * COIN,
        'lock_intervals': (ONE_YEAR * 10,),
        'accepted': True,
        'refill_moneybox_accepted': False,
    },
    {
        # forbidden refill_moneybox_dest: minting is accepted, refill_moneybox is rejected
        'name': 'shu_e06',
        'parent_testcase': 'shu_base',
        'refill_moneybox': 'script',
        'refill_moneybox_dest': ['user', 'ben', 'other', 'other_p2sh'],
        'accepted': True,
        'refill_moneybox_accepted': False,
    },
    {
        # (moneybox_outputs_count == 2): rejected
        'name': 'shu_e07',
        'parent_testcase': 'shu_base',
        'moneybox_change_dest': 'moneybox+moneybox',  # means (moneybox_outputs_count == 2)
        'accepted': False,
        'error': (64, BAD_REWARD_MANY_MONEYBOX_OUTPUTS),
    },
    {
        # moneybox_change_dest == [forbidden combinations]: rejected
        'name': 'shu_e08',
        'parent_testcase': 'shu_base',
        'moneybox_change_dest': ['user', 'ben', 'other_p2pkh', 'other_p2sh', 'user+ben'],
        'accepted': False,
    },
    {
        # extra_moneybox_inputs_count == 1: rejected
        'name': 'shu_e09',
        'parent_testcase': 'shu_base',
        'extra_moneybox_inputs_count': 1,
        'accepted': False,
        'error': (16, 'bad-txns-moneybox-value-toolarge'),
    },
    {
        # extra_moneybox_inputs_count == 1: rejected
        'name': 'shu_e10',
        'parent_testcase': 'shu_base',
        'extra_moneybox_inputs_count': 1,
        'moneybox_change_dest': 'moneybox+moneybox',
        'accepted': False,
        'error': (64, [BAD_REWARD_MANY_MONEYBOX_INPUTS, BAD_REWARD_MANY_MONEYBOX_OUTPUTS]),
    },
    {
        # both (user_outputs_dest and moneybox_change_dest) == nothing: rejected
        'name': 'shu_e11',
        'parent_testcase': 'shu_base',
        'user_outputs_dest': '',
        'moneybox_change_dest': '',
        'accepted': False,
    },
    {
        # useramount == 0 (no user inputs), user_outputs_dest == '' (no user outputs): rejected
        'name': 'shu_e12',
        'parent_testcase': 'shu_base',
        'useramount': 0,
        'reward_to': 'ben',
        'user_outputs_dest': '',
        'accepted': False,
    },
    {
        # invalid_signature: rejected
        'name': 'shu_e13',
        'parent_testcase': 'shu_base',
        'invalid_signature': [100, 101, 102, 110, 200],
        'accepted': False,
        'error': (16, 'mandatory-script-verify-flag-failed'),
    },
    {
        # invalid_signature in moneybox inputs: rejected
        'name': 'shu_e14',
        'parent_testcase': 'shu_base',
        'invalid_signature': [201, 202, 203, 210],
        'accepted': False,
        'error': (64, [BAD_REWARD_INV_SIGNATURE, BAD_PLC_CERTIFICATE, NON_CANONICAL_SIGNATURE]),
    },
    {
        # zero_change_to_moneybox: rejected
        'name': 'shu_e15',
        'parent_testcase': 'shu_base',
        'zero_change_to_moneybox': 1,
        'accepted': False,
        'error': (64, DUST),
    },

]


testcases_map = {}

def sanitize(v):
    s = str(v)
    s = s.replace('(', '_')
    s = s.replace(')', '_')
    s = s.replace(',', '_')
    s = s.replace(' ', '')
    s = s.replace('\'', '_')
    s = s.replace('"', '_')
    return s


def expand_parameter(testcases_array, t, param_name):
    if param_name in t and isinstance(t[param_name], list):
        assert (param_name != 'name')  # name cannot be expanded
        for v in t[param_name]:
            t2 = copy.deepcopy(t)
            t2[param_name] = v
            t2['name'] += ('_' + param_name + '_' + sanitize(v))
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


def find_parent_testcase(testcases_array, name):
    for t in testcases_array:
        if t['name'] == name:
            return t
    assert 0


def get_minting_testcases():
    global testcases_map
    if len(testcases_map) > 0:
        return testcases_map
    for t in testcases_templates:
        if 'parent_testcase' in t:
            parent_testcase_name = t['parent_testcase']
            assert parent_testcase_name != t['name']
            parent_testcase = find_parent_testcase(testcases_templates, parent_testcase_name)
            for key in parent_testcase:
                if key not in t:
                    t[key] = parent_testcase[key]
    testcases_array = []
    for t in testcases_templates:
        expand_testcase(testcases_array, t)
    for t in testcases_array:
        if t['name'] in testcases_map:
            raise AssertionError('Duplicated name in testcases: {}'.format(t['name']))
        testcases_map[t['name']] = t
    return testcases_map
