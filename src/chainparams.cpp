// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "script/standard.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "base58.h"
#include "chainparamsseeds.h"
#include "chainparams-checkpoints.h"

#include <assert.h>
#include <memory>

#include <boost/assign/list_of.hpp>

static CBlock CreateGenesisBlock(const char * pszTimestamp,
                                 const std::vector<CScript> & genesisOutputScripts,
                                 const uint32_t nTime,
                                 const uint32_t nNonce,
                                 const uint32_t nBits,
                                 const int32_t nVersion,
                                 const CAmount & genesisReward,
                                 const Consensus::Params & /*params*/)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;

    txNew.vin.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));

    for (const CScript & script : genesisOutputScripts)
    {
        txNew.vout.emplace_back(genesisReward, script);
    }

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

CScript makeMoneyBoxScriptPubKey()
{
    CScript scr;
    scr << OP_CHECKREWARD;
    CScriptID id(scr);
    CScript result;
    result << OP_HASH160 << ToByteVector(id) << OP_EQUAL;
    return result;
}

CScript makeGraveScriptPubKey(const std::string & graveAddress, const CChainParams & params)
{
    CBitcoinAddress grave(graveAddress);
    assert(grave.IsValid(params) && "invalid destination");
    return GetScriptForDestination(grave.Get(params));
}

CScript makeMausoleumScriptPubKey()
{
    CScript scr;
    scr << OP_INVALIDOPCODE;
    CScriptID id(scr);
    CScript result;
    result << OP_HASH160 << ToByteVector(id) << OP_EQUAL;
    return result;
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(0xC7)(0xE4)(0x90).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(0xC7)(0xE4)(0xCD).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = boost::assign::list_of(0xC7)(0xE4)(0x09).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        consensus.BIP34Height                    = 1;
        consensus.BIP34Hash                      = uint256S("0x00");
        consensus.BIP65Height                    = 1;
        consensus.BIP66Height                    = 1;
        consensus.powLimit                       = uint256S("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan             = 2.1 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing              = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks   = false;
        consensus.fPowNoRetargeting              = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% of 8064
        consensus.nMinerConfirmationWindow       = 2016; // nPowTargetTimespan / nPowTargetSpacing * 4

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000006805c7318ce2736c0");
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.countOfInitialAmountBlocks = 100;
        consensus.countOfInitialAwardBlocks  = 0;
        consensus.minGranularity             = 10*COIN;
        consensus.granularities              = std::vector<std::pair<uint32_t, int64_t> >(
                                                {{0, 100*COIN}});

        consensus.moneyBoxAddress = makeMoneyBoxScriptPubKey();
        consensus.graveAddresses  = {std::make_pair(makeGraveScriptPubKey("U1xPtGsuNviccXWGkTbERTxVAUd8RWtJ6243a", *this), 0.02),
                                     std::make_pair(makeMausoleumScriptPubKey(), 0.01)};

        consensus.maxCaBlock                 = 100000;
        consensus.maxTotalAmount             = 11000000 * COIN;

        consensus.startTotalNgBlock          = 1;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xe0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xd9;

        nDefaultPort       = 7392;
        nPruneAfterHeight  = 100000;

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("bc01.plcu.io", false));
        vSeeds.push_back(CDNSSeedData("bc02.plcu.io", false));
        vSeeds.push_back(CDNSSeedData("bc03.plcu.io", false));

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers            = true;
        fDefaultConsistencyChecks       = false;
        fRequireStandard                = true;
        fMineBlocksOnDemand             = false;
        consensus.fSkipProofOfWorkCheck = false;

        checkpointData.mapCheckpoints = MapCheckpoints(checkpointsMainnet, checkpointsMainnet + ARRAYLEN(checkpointsMainnet));

        chainTxData = ChainTxData{
            // Data as of block b44bc5ae41d1be67227ba9ad875d7268aa86c965b1d64b47c35be6e8d5c352f4 (height 1155626).
            1487715936, // * UNIX timestamp of last known number of transactions
            9243806,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            0.06     // * estimated number of transactions per second after that timestamp
        };
    }

    void init()
    {
        const char * pszTimestamp = "22/Now/2022 The Time For UU!\n"
                                    "BTC 764390  00000000000000000006f25cddd1173f4e9148ddd2c62a07dcbf2946f0523e63\n"
                                    "LTC 2374080 b3b6e087344d4bd0299e263da7cc233be70722637413613409234226294bd043";

        std::vector<CScript> scripts(10);

        // U1xPosjUAZmjZus2DuB3eY55K14usv9R5Qkge
        scripts[0] << OP_RETURN << ParseHex("0274286b0c7881b69fdc0b85ac4e2b286f154c5b9247dd6bd695980925a68a6c87");
        // U1xPgtCR8nTVwCUQB3nCTGyAoo9sQ73ghHnWN
        scripts[1] << OP_RETURN << ParseHex("03186fdf4218fde69bf46fc4f8d15ba0964dde8dab37039d7b790f0aaa62aa5e3b");
        // U1xPjxE4Rrqg57WwMTLQpV7hLw8KEyeBJm4m6
        scripts[2] << OP_RETURN << ParseHex("02f56946f2b33f2a08c27fc04ab3a4ddca768b1923d67af6796e21f9aa80d1c26b");
        // U1xPoaqNU8RcxVwHcnCTNY5QVGRqHkudZCSHk
        scripts[3] << OP_RETURN << ParseHex("0284f3dd09d5887fe13e14d58ab08e126a771b57923a3ed1435c39e61d1fa3a1e2");
        // U1xPhi9Gre269RrbHYZZKwKxcdZHcCFSkd4je
        scripts[4] << OP_RETURN << ParseHex("0267d94f18ba8f41a96768b77621d8af5113aea02554fec95a985a6e566980c611");
        // U1xPmiq7XrHH1gKxri5TxgYL1HowaYcLavCWx
        scripts[5] << OP_RETURN << ParseHex("02461c6a4778ecd3e180981da5a22d1c4c922976952acf8eec7644e0f5d8097491");
        // U1xPzM7RXFfKZMuYjEsir5iwmBRR9PTBCemhD
        scripts[6] << OP_RETURN << ParseHex("02ade43d9cf9b2d0a406aff1e3205317c9121f95e58bd1ed7cd6eaabf9de989ee0");
        // U1xPsuvRZsKrQDDw7XV6wX1wvgg2ekX5GNyeJ
        scripts[7] << OP_RETURN << ParseHex("02959f6cb7ef30833e8d015a69bf259eeb883e33a872d8758d7eeb78fd2f174b62");
        // U1xPgDk9WfaPiU8sHXJ7JS2dhvu5xbfo18Zy7
        scripts[8] << OP_RETURN << ParseHex("029c93b7f01a68dab13afa013a57e1032b9b6569cb0c187385a8e3bc48be18f748");
        // U1xPnAqbMVBWVw3RvC82KeTBmRXCoasdiLinz
        scripts[9] << OP_RETURN << ParseHex("02dfff4bc05b9193e3b8820d382122c1668b9078985e76459d7599c6732a5d97ea");

        genesis = CreateGenesisBlock(pszTimestamp, scripts, 1669075200, 0x512, 0x1f7fffff, 1, 1 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("66e86dc1473d0a0cc993323660d86161786c97fa3424656845798245b8e59003"));
        assert(genesis.hashMerkleRoot == uint256S("4803a73a12f8a140a1e9613c3fc818f27e69af75e466528b2e81acf3d396f231"));
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(0xC7)(0xE4)(0xD7).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(0xC7)(0xE4)(0xD8).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = boost::assign::list_of(0xC8)(0x06)(0xDE).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        consensus.BIP34Height                    = 1;
        consensus.BIP34Hash                      = uint256S("0x00");
        consensus.BIP65Height                    = 1;
        consensus.BIP66Height                    = 1;
        consensus.powLimit                       = uint256S("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan             = 2.1 * 24 * 60 * 60;
        consensus.nPowTargetSpacing              = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks   = true;
        consensus.fPowNoRetargeting              = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow       = 2016; // nPowTargetTimespan / nPowTargetSpacing

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000054cb9e7a0");
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.countOfInitialAmountBlocks = 100;
        consensus.countOfInitialAwardBlocks  = 0;
        consensus.minGranularity             = 10*COIN;
        consensus.granularities              = std::vector<std::pair<uint32_t, int64_t> >(
                                                {{0, 100*COIN}});

        consensus.moneyBoxAddress = makeMoneyBoxScriptPubKey();
        consensus.graveAddresses  = {std::make_pair(makeGraveScriptPubKey("U1xtDNR5B9ik8qbMZETkH3jtfKp8BGPaHYSAD", *this), 0.02),
                                     std::make_pair(makeMausoleumScriptPubKey(), 0.01)};

        consensus.maxCaBlock                 = 0;
        consensus.maxTotalAmount             = 5500000 * COIN;

        consensus.startTotalNgBlock          = 1;

        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xd0;
        pchMessageStart[2] = 0xc8;
        pchMessageStart[3] = 0xef;

        nDefaultPort       = 17392;
        nPruneAfterHeight  = 1000;

        vFixedSeeds.clear();
        vSeeds.clear();

        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("bc1.testnet.plcu.io", false));
        vSeeds.push_back(CDNSSeedData("bc2.testnet.plcu.io", false));
        vSeeds.push_back(CDNSSeedData("bc3.testnet.plcu.io", false));

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers            = false;
        fDefaultConsistencyChecks       = false;
        fRequireStandard                = false;
        fMineBlocksOnDemand             = false;
        consensus.fSkipProofOfWorkCheck = false;

        checkpointData.mapCheckpoints = MapCheckpoints(checkpointsTestnet, checkpointsTestnet + ARRAYLEN(checkpointsTestnet));

        chainTxData = ChainTxData{
            1516631301,
            1238,
            0.011
        };
    }

    void init()
    {
        const char * pszTimestamp = "21/Now/2022 testnet";

        std::vector<CScript> scripts(10);
        scripts[0] << OP_RETURN << ParseHex("02f7e849e2b11f743920eabd7b9a7c7fad3699b89b8daa68d51dd100b52c8e214d");
        scripts[1] << OP_RETURN << ParseHex("02686badf81e5d4f8064113162b73cdff7f00e8562d6ca6289e3ff5f3723206e0e");
        scripts[2] << OP_RETURN << ParseHex("032846379dc755ce383e424dfca703f345bc827af12636aef73342018fb1161bd4");
        scripts[3] << OP_RETURN << ParseHex("03e2a373a4b19793b3fdc0e070d3ebcae59b20cf18f6666dc3c4295ef5bf45dbda");
        scripts[4] << OP_RETURN << ParseHex("03ce0ff8cd1854e522d36dc6ffe68b2a49441995866f86a4bb9adcb9b90829b9c4");
        scripts[5] << OP_RETURN << ParseHex("033edf26a33af400befd54f4de237531a6df169cb22529f928415e972d6d0c194a");
        scripts[6] << OP_RETURN << ParseHex("027a98c0d1f519812119eb907ca5d9cc068cd58d5c1d0d32f129d10b53c030b68d");
        scripts[7] << OP_RETURN << ParseHex("02de8eadbf3d27b3c7f9eef66f19f5ba291a1879b955171bd56c606023c3edee98");
        scripts[8] << OP_RETURN << ParseHex("02092ee2eac0cb99462b26db08e8d43fbe529ad73c5a258bd75807806a2c567cab");
        scripts[9] << OP_RETURN << ParseHex("031784e02877cd8492cb9b04692e1f561ce81d921528acba234a35dcd09476beb3");

        genesis = CreateGenesisBlock(pszTimestamp, scripts, 1668988800, 0x1237, 0x1f7fffff, 1, 1 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("ce95c8d8efa83ab317fc1977d576f91ec2b685be861d31b3ba5857e00700e6c4"));
        assert(genesis.hashMerkleRoot == uint256S("8fc0a72ccd63393b22a408021ec285bd5074f2f92df4c915ec9dad2c29d873bd"));
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(0xC7)(0xE4)(0xD7).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(0xC7)(0xE4)(0xD8).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = boost::assign::list_of(0xC8)(0x06)(0xDE).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        consensus.BIP34Height                    = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash                      = uint256();
        consensus.BIP65Height                    = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height                    = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit                       = uint256S("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan             = 2.1 * 24 * 60 * 60;
        consensus.nPowTargetSpacing              = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks   = true;
        consensus.fPowNoRetargeting              = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow       = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.countOfInitialAmountBlocks = 100;
        consensus.countOfInitialAwardBlocks  = 0;
        consensus.minGranularity             = 10*COIN;
        consensus.granularities              = std::vector<std::pair<uint32_t, int64_t> >(
                                               {{0, 100*COIN}});

        consensus.moneyBoxAddress = makeMoneyBoxScriptPubKey();
        consensus.graveAddresses  = {std::make_pair(makeGraveScriptPubKey("U1xtDNR5B9ik8qbMZETkH3jtfKp8BGPaHYSAD", *this), 0.02),
                                     std::make_pair(makeMausoleumScriptPubKey(), 0.01)};

        consensus.maxCaBlock                 = 512;
        consensus.maxTotalAmount             = 2000000 * COIN;

        consensus.startTotalNgBlock          = 1;

        pchMessageStart[0] = 0xf0;
        pchMessageStart[1] = 0xbd;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xd8;

        nDefaultPort       = 29302;
        nPruneAfterHeight  = 1000;

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers            = false;
        fDefaultConsistencyChecks       = true;
        fRequireStandard                = false;
        fMineBlocksOnDemand             = true;
        consensus.fSkipProofOfWorkCheck = true;

        checkpointData.mapCheckpoints = MapCheckpoints(checkpointsTestnet, checkpointsTestnet + ARRAYLEN(checkpointsTestnet));

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }

    void init()
    {
        const char * pszTimestamp = "21/Now/2022 regtest";

        std::vector<CScript> scripts(10);
        scripts[0] << OP_RETURN << ParseHex("02f7e849e2b11f743920eabd7b9a7c7fad3699b89b8daa68d51dd100b52c8e214d");
        scripts[1] << OP_RETURN << ParseHex("02686badf81e5d4f8064113162b73cdff7f00e8562d6ca6289e3ff5f3723206e0e");
        scripts[2] << OP_RETURN << ParseHex("032846379dc755ce383e424dfca703f345bc827af12636aef73342018fb1161bd4");
        scripts[3] << OP_RETURN << ParseHex("03e2a373a4b19793b3fdc0e070d3ebcae59b20cf18f6666dc3c4295ef5bf45dbda");
        scripts[4] << OP_RETURN << ParseHex("03ce0ff8cd1854e522d36dc6ffe68b2a49441995866f86a4bb9adcb9b90829b9c4");
        scripts[5] << OP_RETURN << ParseHex("033edf26a33af400befd54f4de237531a6df169cb22529f928415e972d6d0c194a");
        scripts[6] << OP_RETURN << ParseHex("027a98c0d1f519812119eb907ca5d9cc068cd58d5c1d0d32f129d10b53c030b68d");
        scripts[7] << OP_RETURN << ParseHex("02de8eadbf3d27b3c7f9eef66f19f5ba291a1879b955171bd56c606023c3edee98");
        scripts[8] << OP_RETURN << ParseHex("02092ee2eac0cb99462b26db08e8d43fbe529ad73c5a258bd75807806a2c567cab");
        scripts[9] << OP_RETURN << ParseHex("031784e02877cd8492cb9b04692e1f561ce81d921528acba234a35dcd09476beb3");

        genesis = CreateGenesisBlock(pszTimestamp, scripts, 1668988800, 0, 0x1f7fffff, 1, 1 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("443e3a1ab2119e08119d2a2d618da3c78abf6b31ba5e493df7b8516e3ea89764"));
        assert(genesis.hashMerkleRoot == uint256S("dfa5b9593bf255ccf3e688e79896b0af2de46da11fad2d17b01383923e2de772"));
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};

//******************************************************************************
//******************************************************************************
static std::unique_ptr<CChainParams> globalChainParams;

//******************************************************************************
//******************************************************************************
const CChainParams & Params() 
{
    assert(globalChainParams);
    return *globalChainParams;
}

//******************************************************************************
//******************************************************************************
std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
    {
        auto ptr = std::unique_ptr<CChainParams>(new CMainParams());
        ptr->init();
        return ptr;
    }
    else if (chain == CBaseChainParams::TESTNET)
    {
        auto ptr = std::unique_ptr<CChainParams>(new CTestNetParams());
        ptr->init();
        return ptr;
    }
    else if (chain == CBaseChainParams::REGTEST)
    {
        auto ptr = std::unique_ptr<CChainParams>(new CRegTestParams());
        ptr->init();
        return ptr;
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

//******************************************************************************
//******************************************************************************
// CChainParamsPtr ParamsPtr(const std::string & chain)
// {
//     if (chain == CBaseChainParams::MAIN)
//     {
//         if (!mainParams)
//         {
//             mainParams.reset(new CMainParams);
//             mainParams->init();
//         }
//         return mainParams;
//     }
//     else if (chain == CBaseChainParams::TESTNET)
//     {
//         if (!testNetParams)
//         {
//             testNetParams.reset(new CTestNetParams);
//             testNetParams->init();
//         }
//         return testNetParams;
//     }
//     else if (chain == CBaseChainParams::REGTEST)
//     {
//         if (!regTestParams)
//         {
//             regTestParams.reset(new CRegTestParams);
//             regTestParams->init();
//         }
//         return regTestParams;
//     }

//     throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
// }

//******************************************************************************
//******************************************************************************
// CChainParams & Params(const std::string & chain)
// {
//     return *ParamsPtr(chain);
// }

//******************************************************************************
//******************************************************************************
void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

//******************************************************************************
//******************************************************************************
void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

//******************************************************************************
//******************************************************************************
int64_t CChainParams::awardGranularity(const uint32_t height) const
{
    if (consensus.granularities.back().first < height)
    {
        return consensus.granularities.back().second;
    }
    for (std::vector<std::pair<uint32_t, int64_t> >::const_reverse_iterator i = consensus.granularities.rbegin();
         i != consensus.granularities.rend(); ++i)
    {
        if (i->first < height)
        {
            return i->second;
        }
    }

    return consensus.granularities.front().second;
}

//******************************************************************************
//******************************************************************************
double CChainParams::gravePercent() const
{
    static double percent = [this]()
    {
        double sum = 0;
        for (const auto & item : consensus.graveAddresses)
        {
            sum += item.second;
        }
        return sum;
    }();

    return percent;
}

//******************************************************************************
//******************************************************************************
bool CChainParams::isGrave(const CScript & scriptPubKey) const
{
    for (const auto & item : consensus.graveAddresses)
    {
        if (item.first == scriptPubKey)
        {
            return true;
        }
    }
    return false;
}

//******************************************************************************
//******************************************************************************
uint32_t CChainParams::maxCaBlock() const
{
    if (NetworkIDString() == CBaseChainParams::REGTEST)
    {
        return gArgs.GetArg("-maxcablock-regtest", consensus.maxCaBlock);
    }
    return consensus.maxCaBlock;
}

//******************************************************************************
//******************************************************************************
uint32_t CChainParams::startTotalNgBlock() const
{
    if (NetworkIDString() == CBaseChainParams::REGTEST)
    {
        return gArgs.GetArg("-totalforkblock-regtest", consensus.startTotalNgBlock);
    }

    return consensus.startTotalNgBlock;
}
