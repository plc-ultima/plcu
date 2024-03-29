#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run regression test suite.

This module calls down into individual test cases via subprocess. It will
forward all unrecognized arguments onto the individual test scripts.

Functional tests are disabled on Windows by default. Use --force to run them anyway.

For a description of arguments recognized by test scripts, see
`test/functional/test_framework/test_framework.py:BitcoinTestFramework.main`.

"""

import argparse
import configparser
import datetime
import os
import time
import shutil
import signal
import sys
import subprocess
import tempfile
import re
import logging
import xml.etree.ElementTree as ET
import fnmatch
from minting_testcases import get_minting_testcases

# Formatting. Default colors to empty strings.
BOLD, BLUE, RED, GREY = ("", ""), ("", ""), ("", ""), ("", "")
try:
    # Make sure python thinks it can write unicode to its stdout
    "\u2713".encode("utf_8").decode(sys.stdout.encoding)
    TICK = "✓ "
    CROSS = "✖ "
    CIRCLE = "○ "
except UnicodeDecodeError:
    TICK = "P "
    CROSS = "x "
    CIRCLE = "o "

if os.name == 'posix':
    # primitive formatting on supported
    # terminal via ANSI escape sequences:
    BOLD = ('\033[0m', '\033[1m')
    BLUE = ('\033[0m', '\033[0;34m')
    RED = ('\033[0m', '\033[0;31m')
    GREY = ('\033[0m', '\033[1;30m')

TEST_EXIT_PASSED = 0
TEST_EXIT_SKIPPED = 77
PYTHON_BIN = os.getenv('PYTHON_BIN') or 'python3'


def replace_flag(flags, name, value, skip_check=False):
    for i, flag in enumerate(flags):
        if flag.startswith(f'--{name}='):
            flags[i] = f'--{name}={value}'
            return
    assert skip_check, f'flag {name} not found in {flags}'


BASE_SCRIPTS= [
    # Scripts that are run by the travis build process.
    # Longest test should go first, to favor running tests in parallel
    'wallet-hd.py',
    'walletbackup.py',
    # vv Tests less than 5m vv
    'p2p-fullblocktest.py',
    'fundrawtransaction.py',
    'p2p-compactblocks.py',
    'segwit.py',
    # vv Tests less than 2m vv
    'wallet.py',
    'wallet-accounts.py',
    'p2p-segwit.py',
    'wallet-dump.py',
    'listtransactions.py',
    'super_tx.py',
    # vv Tests less than 60s vv
    'sendheaders.py',
    'zapwallettxes.py',
    'importmulti.py',
    'mempool_limit.py',
    'merkle_blocks.py',
    'receivedby.py',
    'abandonconflict.py',
    'bip68-112-113-p2p.py',
    'rawtransactions.py',
    'reindex.py',
    # vv Tests less than 30s vv
    'keypool-topup.py',
    'zmq_test.py',
    'bitcoin_cli.py',
    'mempool_resurrect_test.py',
    'txn_doublespend.py --mineblock',
    'txn_clone.py',
    'getchaintips.py',
    'rest.py',
    'mempool_spendcoinbase.py',
    'mempool_reorg.py',
    'mempool_persist.py',
    'multiwallet.py',
    'httpbasics.py',
    'multi_rpc.py',
    'proxy_test.py',
    'signrawtransactions.py',
    'disconnect_ban.py',
    'decodescript.py',
    'blockchain.py',
    'disablewallet.py',
    'net.py',
    'keypool.py',
    'p2p-mempool.py',
    'prioritise_transaction.py',
    'invalidblockrequest.py',
    'invalidtxrequest.py',
    'p2p-versionbits-warning.py',
    'preciousblock.py',
    'test_script_address2.py',
    'importprunedfunds.py',
    'signmessages.py',
    'nulldummy.py',
    'import-rescan.py',
    'mining.py',
    'bumpfee.py',
    'rpcnamedargs.py',
    'listsinceblock.py',
    'p2p-leaktests.py',
    'wallet-encryption.py',
    'bipdersig-p2p.py',
    'bip65-cltv-p2p.py',
    'uptime.py',
    'resendwallettransactions.py',
    'minchainwork.py',
    'p2p-acceptblock.py',
    'grave.py',
    'coinbase_subsidy.py',
    'total_emission.py',
    'sendtograve.py',
    'free_tx.py',
    'miami_police.py',
    'minting.py',
    # 'minting.py --mintalltestcases',
]

EXTENDED_SCRIPTS = [
    # These tests are not run by the travis build process.
    # Longest test should go first, to favor running tests in parallel
    'pruning.py',
    # vv Tests less than 20m vv
    'smartfees.py',
    # vv Tests less than 5m vv
    'maxuploadtarget.py',
    'mempool_packages.py',
    'dbcrash.py',
    # vv Tests less than 2m vv
    'bip68-sequence.py',
    'getblocktemplate_longpoll.py',
    'p2p-timeouts.py',
    # vv Tests less than 60s vv
    'bip9-softforks.py',
    'p2p-feefilter.py',
    'rpcbind_test.py',
    # vv Tests less than 30s vv
    'assumevalid.py',
    'example_test.py',
    'txn_doublespend.py',
    'txn_clone.py --mineblock',
    'forknotify.py',
    'invalidateblock.py',
    'replace-by-fee.py',
]

# Place EXTENDED_SCRIPTS first since it has the 3 longest running tests
ALL_SCRIPTS = EXTENDED_SCRIPTS + BASE_SCRIPTS

NON_SCRIPTS = [
    # These are python files that live in the functional tests directory, but are not test scripts.
    "combine_logs.py",
    "create_cache.py",
    "test_runner.py",
    "minting_testcases.py",
    "tx_verifier.py",
]

def expand_minting_testcases(test_list, passon_args):
    all_testcases = False

    # Extract mintalltestcases from passon_args:
    if '--mintalltestcases' in passon_args:
        all_testcases = True
        passon_args.remove('--mintalltestcases')

    # Extract mintalltestcases from test_list:
    if 'minting.py --mintalltestcases' in test_list:
        all_testcases = True
        test_list.remove('minting.py --mintalltestcases')

    # Extract runtestcasemask from passon_args:
    runtestcasemask = '--runtestcasemask='
    runtestcasemask_len = len(runtestcasemask)
    masks1 = [x[runtestcasemask_len:] for x in passon_args if x.startswith(runtestcasemask) and len(x) > runtestcasemask_len]
    args_to_del = list(filter(lambda x: x.startswith(runtestcasemask), passon_args))
    verbose = (len(args_to_del) > 0)
    for a in args_to_del:
        passon_args.remove(a)

    # Extract runtestcasemask from test_list:
    runtestcasemask = 'minting.py --runtestcasemask='
    runtestcasemask_len = len(runtestcasemask)
    masks2 = [x[runtestcasemask_len:] for x in test_list if x.startswith(runtestcasemask) and len(x) > runtestcasemask_len]
    args_to_del = list(filter(lambda x: x.startswith(runtestcasemask), test_list))
    for a in args_to_del:
        test_list.remove(a)

    mi_testcases = []
    masks = masks1 + masks2

    if all_testcases:
        for t in get_minting_testcases():
            test_list.append('minting.py --runtestcase=' + t)
    elif len(masks) > 0:
        for t in get_minting_testcases():
            for mask in masks:
                if fnmatch.fnmatch(t, mask):
                    test_list.append('minting.py --runtestcase=' + t)
                    mi_testcases.append(t)
                    break
        if verbose:
            mi_testcases.sort()
            print('Expanded {} minting testcases:'.format(len(mi_testcases)), *mi_testcases, sep='\n- ')


def main():
    print("Python version:")
    print(sys.version)

    # Parse arguments and pass through unrecognised args
    parser = argparse.ArgumentParser(add_help=False,
                                     usage='%(prog)s [test_runner.py options] [script options] [scripts]',
                                     description=__doc__,
                                     epilog='''
    Help text and arguments for individual test script:''',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--coverage', action='store_true', help='generate a basic coverage report for the RPC interface')
    parser.add_argument('--exclude', '-x', help='specify a comma-seperated-list of scripts to exclude.')
    parser.add_argument('--extended', action='store_true', help='run the extended test suite in addition to the basic tests')
    parser.add_argument('--force', '-f', action='store_true', help='run tests even on platforms where they are disabled by default (e.g. windows).')
    parser.add_argument('--help', '-h', '-?', action='store_true', help='print help text and exit')
    parser.add_argument('--jobs', '-j', type=int, default=4, help='how many test scripts to run in parallel. Default=4.')
    parser.add_argument('--keepcache', '-k', action='store_true', help='the default behavior is to flush the cache directory on startup. --keepcache retains the cache from the previous testrun.')
    parser.add_argument('--quiet', '-q', action='store_true', help='only print results summary and failure logs')
    parser.add_argument('--tmpdirprefix', '-t', default=tempfile.gettempdir(), help="Root directory for datadirs")
    parser.add_argument('--junitoutput', '-J', default='junit_results.xml',
                        help="File that will store JUnit formatted test results. If no absolute path is given it is treated as relative to the temporary directory.")
    parser.add_argument('--testsuitename', '-n', default='PLC Ultima Node functional tests',
                        help="Name of the test suite, as it will appear in the logs and in the JUnit report.")
    parser.add_argument('--timeout', type=str, default=None, help='Timeout, m/h/d/w suffix may be used, without suffix is in seconds, default None')
    args, unknown_args = parser.parse_known_args()

    # args to be passed on always start with two dashes; tests are the remaining unknown args
    tests = [arg for arg in unknown_args if arg[:2] != "--"]
    passon_args = [arg for arg in unknown_args if arg[:2] == "--"]

    # Read config generated by configure.
    config = configparser.ConfigParser()
    configfile = os.path.abspath(os.path.dirname(__file__)) + "/../config.ini"
    config.read_file(open(configfile))

    passon_args.append("--configfile=%s" % configfile)

    # Set up logging
    logging_level = logging.INFO if args.quiet else logging.DEBUG
    logging.basicConfig(format='%(message)s', level=logging_level)

    # Create base test directory
    tmpdir = "%s/plcultima_test_runner_%s" % (args.tmpdirprefix, datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    os.makedirs(tmpdir)

    logging.debug("Temporary test directory at %s" % tmpdir)
    logging.debug("jobs: %d" % args.jobs)
    if args.timeout:
        suffix = args.timeout[-1]
        if not suffix.isdigit():
            value = int(args.timeout[:-1])
            assert suffix in ['s', 'm', 'h', 'd', 'w'], f'invalid suffix: {suffix}'
            if suffix == 'm':
                value *= 60
            elif suffix == 'h':
                value *= 3600
            elif suffix == 'd':
                value *= 3600 * 24
            elif suffix == 'w':
                value *= 3600 * 24 * 7
        else:
            value = int(args.timeout)
        args.timeout = value
    if args.timeout:
        logging.debug(f"timeout: {args.timeout} (now {datetime.datetime.now()})")
    start_point = time.time()

    if not os.path.isabs(args.junitoutput):
        args.junitoutput = os.path.join(tmpdir, args.junitoutput)

    enable_wallet = config["components"].getboolean("ENABLE_WALLET")
    enable_utils = config["components"].getboolean("ENABLE_UTILS")
    enable_bitcoind = config["components"].getboolean("ENABLE_BITCOIND")

    if config["environment"]["EXEEXT"] == ".exe" and not args.force:
        # https://github.com/bitcoin/bitcoin/commit/d52802551752140cf41f0d9a225a43e84404d3e9
        # https://github.com/bitcoin/bitcoin/pull/5677#issuecomment-136646964
        print("Tests currently disabled on Windows by default. Use --force option to enable")
        sys.exit(0)

    if not (enable_wallet and enable_utils and enable_bitcoind):
        print("No functional tests to run. Wallet, utils, and plcultimad must all be enabled")
        print("Rerun `configure` with -enable-wallet, -with-utils and -with-daemon and rerun make")
        sys.exit(0)

    # Build list of tests
    if tests:
        # Individual tests have been specified. Run specified tests that exist
        # in the ALL_SCRIPTS list. Accept the name with or without .py extension.
        tests = [re.sub("\.py$", "", t) + ".py" for t in tests]
        test_list = []
        for t in tests:
            if t in ALL_SCRIPTS:
                test_list.append(t)
            else:
                print("{}WARNING!{} Test '{}' not found in full test list.".format(BOLD[1], BOLD[0], t))
    else:
        # No individual tests have been specified.
        # Run all base tests, and optionally run extended tests.
        test_list = BASE_SCRIPTS
        if args.extended:
            # place the EXTENDED_SCRIPTS first since the three longest ones
            # are there and the list is shorter
            test_list = EXTENDED_SCRIPTS + test_list

    # Remove the test cases that the user has explicitly asked to exclude.
    if args.exclude:
        tests_excl = [re.sub("\.py$", "", t) + ".py" for t in args.exclude.split(',')]
        for exclude_test in tests_excl:
            if exclude_test in test_list:
                test_list.remove(exclude_test)
            else:
                print("{}WARNING!{} Test '{}' not found in current test list.".format(BOLD[1], BOLD[0], exclude_test))

    if not test_list:
        print("No valid test scripts specified. Check that your test is in one "
              "of the test lists in test_runner.py, or run test_runner.py with no arguments to run all tests")
        sys.exit(0)

    if args.help:
        # Print help for test_runner.py, then print help of the first script (with args removed) and exit.
        parser.print_help()
        subprocess.check_call([(config["environment"]["SRCDIR"] + '/test/functional/' + test_list[0].split()[0])] + ['-h'])
        sys.exit(0)

    expand_minting_testcases(test_list, passon_args)

    check_script_list(config["environment"]["SRCDIR"])

    if not args.keepcache:
        shutil.rmtree("%s/test/cache" % config["environment"]["BUILDDIR"], ignore_errors=True)

    run_tests(test_list, config["environment"]["SRCDIR"], config["environment"]["BUILDDIR"], config["environment"]["EXEEXT"], args.junitoutput, tmpdir, args.jobs, args.testsuitename, args.coverage, passon_args, start_point, args.timeout)

def run_tests(test_list, src_dir, build_dir, exeext, junitoutput, tmpdir, jobs=1, test_suite_name="PLCU", enable_coverage=False, args=[], start_point=0, timeout=0):
    # Warn if plcultimad is already running (unix only)
    try:
        if subprocess.check_output(["pidof", "plcultimad"]) is not None:
            print("%sWARNING!%s There is already a plcultimad process running on this system. Tests may fail unexpectedly due to resource contention!" % (BOLD[1], BOLD[0]))
    except (OSError, subprocess.SubprocessError):
        pass

    # Warn if there is a cache directory
    cache_dir = "%s/test/cache" % build_dir
    if os.path.isdir(cache_dir):
        print("%sWARNING!%s There is a cache directory here: %s. If tests fail unexpectedly, try deleting the cache directory." % (BOLD[1], BOLD[0], cache_dir))

    #Set env vars
    if "PLCULTIMAD" not in os.environ:
        os.environ["PLCULTIMAD"] = build_dir + '/src/plcultimad' + exeext
        os.environ["PLCULTIMACLI"] = build_dir + '/src/plcultima-cli' + exeext

    tests_dir = src_dir + '/test/functional/'

    flags = ["--srcdir={}/src".format(build_dir)] + args
    flags.append("--cachedir=%s" % cache_dir)

    if enable_coverage:
        coverage = RPCCoverage()
        flags.append(coverage.flag)
        logging.debug("Initializing coverage directory at %s" % coverage.dir)
    else:
        coverage = None

    if len(test_list) > 1 and jobs > 1:
        # Populate cache
        print(f'[{datetime.datetime.now().time()}] Creating normal cache...')
        subprocess.check_output([PYTHON_BIN, tests_dir + 'create_cache.py'] + flags + ["--tmpdir=%s/cache" % tmpdir])

        # print(f'[{datetime.datetime.now().time()}] Creating minting moneybox_inputs cache...')
        # subprocess.check_output([PYTHON_BIN, tests_dir + 'minting.py'] + flags + ["--tmpdir=%s/cache" % tmpdir])
        cache_dir_minting = os.path.join(cache_dir, 'minting')

        parent_cache_dir = cache_dir
        for value in []: #[400, 500, 1300, 1400, 1500]:
            print(f'[{datetime.datetime.now().time()}] Creating cache with {value} blocks...')
            this_cache_dir = os.path.join(cache_dir, 'more', f'cache_{value}')
            replace_flag(flags, 'cachedir', this_cache_dir)
            subprocess.check_output([PYTHON_BIN, tests_dir + 'create_cache.py'] + flags + [f"--tmpdir={tmpdir}/cache",
                                                                                           f'--customcacheheight={value}',
                                                                                           f'--parentcache={parent_cache_dir}'])
            # Redirect minting cache to cache_dir_minting, moneybox_inputs cache must be single for all custom caches:
            this_cache_dir_minting = os.path.join(this_cache_dir, 'minting')
            if not os.path.isdir(this_cache_dir_minting):
                # if run with --keepcache, it may already exist
                os.symlink(cache_dir_minting, this_cache_dir_minting)
            parent_cache_dir = this_cache_dir

    # Restore original cachedir:
    replace_flag(flags, 'cachedir', cache_dir)

    #Run Tests
    print(f'[{datetime.datetime.now().time()}] Running tests')
    job_queue = TestHandler(jobs, tests_dir, tmpdir, test_list, flags)
    time0 = time.time()
    test_results = []
    start_point = start_point if start_point else time0

    max_len_name = len(max(test_list, key=len))

    for _ in range(len(test_list)):
        test_result, stdout, stderr = job_queue.get_next(start_point, timeout)
        test_results.append(test_result)

        if test_result.status == "Passed":
            logging.debug("\n%s%s%s passed, Duration: %s s" % (BOLD[1], test_result.name, BOLD[0], test_result.time))
        elif test_result.status == "Skipped":
            logging.debug("\n%s%s%s skipped" % (BOLD[1], test_result.name, BOLD[0]))
        elif test_result.status == "Expired":
            logging.debug("\n%s%s%s time expired" % (BOLD[1], test_result.name, BOLD[0]))
        elif test_result.status == "Killed":
            logging.debug("\n%s%s%s killed, Duration: %s s" % (BOLD[1], test_result.name, BOLD[0], test_result.time))
        else:
            print("\n%s%s%s failed, Duration: %s s\n" % (BOLD[1], test_result.name, BOLD[0], test_result.time))
            print(BOLD[1] + 'stdout:\n' + BOLD[0] + stdout + '\n')
            print(BOLD[1] + 'stderr:\n' + BOLD[0] + stderr + '\n')

    now = time.time()
    runtime = int(now - time0)
    full_runtime = int(now - start_point)
    print_results(test_results, max_len_name, runtime, full_runtime)
    save_results_as_junit(test_results, junitoutput, runtime, test_suite_name)

    if coverage:
        coverage.report_rpc_coverage()

        logging.debug("Cleaning up coverage data")
        coverage.cleanup()

    # Clear up the temp directory if all subdirectories are gone
    if not os.listdir(tmpdir):
        os.rmdir(tmpdir)

    all_passed = all(map(lambda test_result: test_result.was_successful, test_results))

    sys.exit(not all_passed)

def print_results(test_results, max_len_name, runtime, full_runtime):
    results = "\n" + BOLD[1] + "%s | %s | %s\n\n" % ("TEST".ljust(max_len_name), "STATUS   ", "DURATION") + BOLD[0]

    test_results.sort(key=lambda result: result.name.lower())
    all_passed = True
    time_sum = 0
    failed_cnt = 0

    for test_result in test_results:
        all_passed = all_passed and test_result.was_successful
        failed_cnt += (not test_result.was_successful)
        time_sum += test_result.time
        test_result.padding = max_len_name
        results += str(test_result)

    status = TICK + "Passed" if all_passed else CROSS + f"Failed ({failed_cnt})"
    results += BOLD[1] + "\n%s | %s | %s s (accumulated) \n" % ("ALL".ljust(max_len_name), status.ljust(9), time_sum) + BOLD[0]
    results += f"Runtime: {runtime} s (with creating cache: {full_runtime} s)\n"
    print(results)

class TestHandler:
    """
    Trigger the testscrips passed in via the list.
    """

    def __init__(self, num_tests_parallel, tests_dir, tmpdir, test_list=None, flags=None):
        assert(num_tests_parallel >= 1)
        self.num_jobs = num_tests_parallel
        self.tests_dir = tests_dir
        self.tmpdir = tmpdir
        self.test_list = test_list
        self.flags = flags
        self.num_running = 0
        # In case there is a graveyard of zombie bitcoinds, we can apply a
        # pseudorandom offset to hopefully jump over them.
        # (625 is PORT_RANGE/MAX_NODES)
        self.portseed_offset = int(time.time() * 1000) % 625
        self.jobs = []

    def get_next(self, start_point, timeout=0):
        timeout_expired = timeout and int(time.time() - start_point) > timeout
        if timeout_expired and self.test_list:
            t = self.test_list.pop(0)
            return TestResult(t, 'Expired', 0, None, None), None, None
        while self.num_running < self.num_jobs and self.test_list:
            # Add tests
            self.num_running += 1
            t = self.test_list.pop(0)
            portseed = len(self.test_list) + self.portseed_offset
            portseed_arg = ["--portseed={}".format(portseed)]
            log_stdout = tempfile.SpooledTemporaryFile(max_size=2**16)
            log_stderr = tempfile.SpooledTemporaryFile(max_size=2**16)
            test_argv = t.split()
            tmpdir = ["--tmpdir=%s/%s_%s" % (self.tmpdir, re.sub(".py$", "", test_argv[0]), portseed)]
            self.jobs.append((t,
                              time.time(),
                              subprocess.Popen([PYTHON_BIN, self.tests_dir + test_argv[0]] + test_argv[1:] + self.flags + portseed_arg + tmpdir,
                                               universal_newlines=True,
                                               stdout=log_stdout,
                                               stderr=log_stderr),
                              log_stdout,
                              log_stderr))
        if not self.jobs:
            raise IndexError('pop from empty list')
        while True:
            # Return first proc that finishes
            time.sleep(.5)
            timeout_expired = timeout and int(time.time() - start_point) > timeout
            for j in self.jobs:
                (name, time0, proc, log_out, log_err) = j
                if (os.getenv('TRAVIS') == 'true' and int(time.time() - time0) > 20 * 60) or timeout_expired:
                    # In travis, timeout individual tests after 20 minutes (to stop tests hanging and not
                    # providing useful output.
                    proc.send_signal(signal.SIGINT)
                if proc.poll() is not None:
                    log_out.seek(0), log_err.seek(0)
                    [stdout, stderr] = [l.read().decode('utf-8') for l in (log_out, log_err)]
                    log_out.close(), log_err.close()
                    if proc.returncode == TEST_EXIT_PASSED and stderr == "":
                        status = "Passed"
                    elif proc.returncode == TEST_EXIT_SKIPPED:
                        status = "Skipped"
                    else:
                        status = "Killed" if timeout_expired else "Failed"
                    self.num_running -= 1
                    self.jobs.remove(j)

                    return TestResult(name, status, int(time.time() - time0), stdout, stderr), stdout, stderr
            print('.', end='', flush=True)

FAILED_STATUSES = ["Failed", "Killed", "Expired"]

class TestResult():
    def __init__(self, name, status, time, stdout, stderr):
        self.name = name
        self.status = status
        self.time = time
        self.padding = 0
        self.stdout = stdout
        self.stderr = stderr

    def __repr__(self):
        if self.status == "Passed":
            color = BLUE
            glyph = TICK
        elif self.status in FAILED_STATUSES:
            color = RED
            glyph = CROSS
        elif self.status == "Skipped":
            color = GREY
            glyph = CIRCLE

        return color[1] + "%s | %s%s | %s s\n" % (self.name.ljust(self.padding), glyph, self.status.ljust(7), self.time) + color[0]

    @property
    def was_successful(self):
        return self.status not in FAILED_STATUSES


def check_script_list(src_dir):
    """Check scripts directory.

    Check that there are no scripts in the functional tests directory which are
    not being run by pull-tester.py."""
    script_dir = src_dir + '/test/functional/'
    python_files = set([t for t in os.listdir(script_dir) if t[-3:] == ".py"])
    missed_tests = list(python_files - set(map(lambda x: x.split()[0], ALL_SCRIPTS + NON_SCRIPTS)))
    if len(missed_tests) != 0:
        print("%sWARNING!%s The following scripts are not being run: %s. Check the test lists in test_runner.py." % (BOLD[1], BOLD[0], str(missed_tests)))
        if os.getenv('TRAVIS') == 'true':
            # On travis this warning is an error to prevent merging incomplete commits into master
            sys.exit(1)

class RPCCoverage(object):
    """
    Coverage reporting utilities for test_runner.

    Coverage calculation works by having each test script subprocess write
    coverage files into a particular directory. These files contain the RPC
    commands invoked during testing, as well as a complete listing of RPC
    commands per `plcultima-cli help` (`rpc_interface.txt`).

    After all tests complete, the commands run are combined and diff'd against
    the complete list to calculate uncovered RPC commands.

    See also: test/functional/test_framework/coverage.py

    """
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="coverage")
        self.flag = '--coveragedir=%s' % self.dir

    def report_rpc_coverage(self):
        """
        Print out RPC commands that were unexercised by tests.

        """
        uncovered = self._get_uncovered_rpc_commands()

        if uncovered:
            print("Uncovered RPC commands:")
            print("".join(("  - %s\n" % i) for i in sorted(uncovered)))
        else:
            print("All RPC commands covered.")

    def cleanup(self):
        return shutil.rmtree(self.dir)

    def _get_uncovered_rpc_commands(self):
        """
        Return a set of currently untested RPC commands.

        """
        # This is shared from `test/functional/test-framework/coverage.py`
        reference_filename = 'rpc_interface.txt'
        coverage_file_prefix = 'coverage.'

        coverage_ref_filename = os.path.join(self.dir, reference_filename)
        coverage_filenames = set()
        all_cmds = set()
        covered_cmds = set()

        if not os.path.isfile(coverage_ref_filename):
            raise RuntimeError("No coverage reference found")

        with open(coverage_ref_filename, 'r') as f:
            all_cmds.update([i.strip() for i in f.readlines()])

        for root, dirs, files in os.walk(self.dir):
            for filename in files:
                if filename.startswith(coverage_file_prefix):
                    coverage_filenames.add(os.path.join(root, filename))

        for filename in coverage_filenames:
            with open(filename, 'r') as f:
                covered_cmds.update([i.strip() for i in f.readlines()])

        return all_cmds - covered_cmds

def save_results_as_junit(test_results, file_name, time, test_suite_name):
    """
    Save tests results to file in JUnit format

    See http://llg.cubic.org/docs/junit/ for specification of format
    """
    e_test_suite = ET.Element("testsuite",
                              {"name": "{}".format(test_suite_name),
                               "tests": str(len(test_results)),
                               # "errors":
                               "failures": str(len([t for t in test_results if t.status == "Failed"])),
                               "id": "0",
                               "skipped": str(len([t for t in test_results if t.status == "Skipped"])),
                               "time": str(time),
                               "timestamp": datetime.datetime.now().isoformat('T')
                               })

    for test_result in test_results:
        e_test_case = ET.SubElement(e_test_suite, "testcase",
                                    {"name": test_result.name,
                                     "classname": test_result.name,
                                     "time": str(test_result.time)
                                     }
                                    )
        if test_result.status == "Skipped":
            ET.SubElement(e_test_case, "skipped", {"message": "skipped"}).text = "skipped"
        elif test_result.status == "Failed":
            fail_result = test_result.stderr or test_result.stdout or "<no output>"
            ET.SubElement(e_test_case, "failure", {"message": "failure"}).text = fail_result
        # no special element for passed tests

        ET.SubElement(e_test_case, "system-out").text = test_result.stdout
        ET.SubElement(e_test_case, "system-err").text = test_result.stderr

    ET.ElementTree(e_test_suite).write(
        file_name, "UTF-8", xml_declaration=True)


if __name__ == '__main__':
    main()
