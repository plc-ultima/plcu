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
    return GetScriptForDestination(CBitcoinAddress(graveAddress).Get(params));
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(0xC8)(0x05)(0x28).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(0xC8)(0x05)(0x29).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = boost::assign::list_of(0xC8)(0x04)(0xAA).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        consensus.BIP34Height                    = 1;
        consensus.BIP34Hash                      = uint256S("da1679b38daa52ffb878f3b3d7a20726a9de21ed937f71410b711278ddb3fa7a");
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
        consensus.defaultAssumeValid = uint256S("0x1673fa904a93848eca83d5ca82c7af974511a7e640e22edc2976420744f2e56a"); //1155631

        consensus.countOfInitialAmountBlocks = 100;
        consensus.countOfInitialAwardBlocks  = 100;
        consensus.minGranularity             = 10*COIN;
        consensus.granularities              = std::vector<std::pair<uint32_t, int64_t> >(
                                                {{0, 100*COIN}});

        consensus.moneyBoxAddress = makeMoneyBoxScriptPubKey();
        consensus.graveAddress    = makeGraveScriptPubKey("U2xHJx3f6hbaDW4FvFvANLL4FJhuxg5Bo12ho", *this);

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xdf;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xda;

        nDefaultPort       = 9835;
        nPruneAfterHeight  = 100000;

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("bc01.plcu.io", "bc01.plcu.io"));
        vSeeds.push_back(CDNSSeedData("bc02.plcu.io", "bc02.plcu.io"));
        vSeeds.push_back(CDNSSeedData("bc03.plcu.io", "bc03.plcu.io"));

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
        const char * pszTimestamp = "01/Now/2021 The Time Is Now!\n"
                                    "BTC 707690  0000000000000000000c753df2aad84ec832c09b20b00cc9e526ac917367d73a\n"
                                    "LTC 2150310 eaa22f638167d45b4d4388cf566482cd16ee3d98fc3d598364a1ab0da7653771";

        std::vector<CScript> scripts(10);
        // U2xHL8a4MGe47f1gwxXmvVwDeN6iW5c2n924J
        scripts[0] << OP_RETURN << ParseHex("02643893c9834e7620908bfbefef8a7c0ab54a3cbe140e6757d0b1959dea7d0f28");
        // U2xHHMWh65QX56FQBfKC7uPiRPstnGNzjZtgR
        scripts[1] << OP_RETURN << ParseHex("02505688ad32ea6245b621101c52816c9df7ea6de15e18bdf31356fe1bece15199");
        // U2xHDfg6KshZKDbc1h3z2Zgf5P2yzTXWC8Dbb
        scripts[2] << OP_RETURN << ParseHex("0225142b65627c64f2cb8791598be62bc1d6d9ee77eeff89ef62406f15e562a48f");

        genesis = CreateGenesisBlock(pszTimestamp, scripts, 1635714000, 0x3e9, 0x1f7fffff, 1, 1 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("f596cf825f5833b7e30243d12c6164bd26db5fba05af08c498c886ff843158dd"));
        assert(genesis.hashMerkleRoot == uint256S("de31cc9e239f0d567443d3dec49cd21770681f98cfff34441a55e331626d1dac"));
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(0xC8)(0x05)(0x24).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(0xC8)(0x05)(0x25).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = boost::assign::list_of(0xC8)(0x05)(0xDE).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        consensus.BIP34Height                    = 1;
        consensus.BIP34Hash                      = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
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
        consensus.defaultAssumeValid = uint256S("0x43a16a626ef2ffdbe928f2bc26dcd5475c6a1a04f9542dfc6a0a88e5fcf9bd4c"); //8711

        consensus.countOfInitialAmountBlocks = 100;
        consensus.countOfInitialAwardBlocks  = 100;
        consensus.minGranularity             = 10*COIN;
        consensus.granularities              = std::vector<std::pair<uint32_t, int64_t> >(
                                                {{0, 100*COIN}});

        consensus.moneyBoxAddress = makeMoneyBoxScriptPubKey();
        consensus.graveAddress    = makeGraveScriptPubKey("U2xFeMxJfqbjGFEoCiQ3wFProGrDct9Ep7Snk", *this);

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xd1;
        pchMessageStart[2] = 0xc7;
        pchMessageStart[3] = 0xf0;

        nDefaultPort       = 19835;
        nPruneAfterHeight  = 1000;

        vFixedSeeds.clear();
        vSeeds.clear();

        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("bc0.testnet.plcu.io", "bc0.testnet.plcu.io"));
        vSeeds.push_back(CDNSSeedData("bc1.testnet.plcu.io", "bc1.testnet.plcu.io"));
        vSeeds.push_back(CDNSSeedData("bc2.testnet.plcu.io", "bc2.testnet.plcu.io"));
        vSeeds.push_back(CDNSSeedData("bc3.testnet.plcu.io", "bc3.testnet.plcu.io"));

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
        const char * pszTimestamp = "22/Oct/2021 testnet";

        std::vector<CScript> scripts(10);
        scripts[0] << OP_RETURN << ParseHex("036daf2772300f2226baf3a5012f23a5e775be80d7324427319a6f39d43b71271b");
        scripts[1] << OP_RETURN << ParseHex("034d83ef03bf4bdd6b6acb1fe164c03b2098eb1db605162fdd57c8846717fed83a");
        scripts[2] << OP_RETURN << ParseHex("03e63753c25c8fd5d0fe769e3f8c8601438db8e0a16420a09cd18dc049dd9f8521");
        scripts[3] << OP_RETURN << ParseHex("032b2b33fc097606930ebe94c17397ca0487fe61176b808dbd0cea420f10b2ca96");
        scripts[4] << OP_RETURN << ParseHex("036bfcf2c1eb983536ddde4f7af64cdb8ef2c2cdd08dbbb7735858b3e101c6edb4");
        scripts[5] << OP_RETURN << ParseHex("0287796a6e81d9e6060d50f86c19434391a69f13afb9d4999790b1cdc62ef09dc0");
        scripts[6] << OP_RETURN << ParseHex("02b59fc18825693c7497e23bae68e5331f7c751b6bdc3b216a64d1e6b5a23da5eb");
        scripts[7] << OP_RETURN << ParseHex("027b2ed67aedade28d0832e75ebbadc9aec8f418fb8a6ecbe02bdd61dd338d9cb9");
        scripts[8] << OP_RETURN << ParseHex("0263b101775655a0a9f8b19a9a84ad6b41d97d07b30ae8e9269614c620fc0addea");
        scripts[9] << OP_RETURN << ParseHex("024e84be3ce19f99e32cbc0314ff80b8a4f81b0d5393220330248c3316cb7474d0");

        genesis = CreateGenesisBlock(pszTimestamp, scripts, 1634850000, 0xf9f, 0x1f7fffff, 1, 1 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("83b43792fc6255e24d471ce91e4d2a31de74280990ce8ff220c04227864d5377"));
        assert(genesis.hashMerkleRoot == uint256S("3f8c26b097a00ef6f5ce9a1191b885c26c678c327d14f79f627592b4a6d12449"));
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(0xC8)(0x05)(0x24).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(0xC8)(0x05)(0x25).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = boost::assign::list_of(0xC8)(0x05)(0xDE).convert_to_container<std::vector<unsigned char> >();
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
        consensus.countOfInitialAwardBlocks  = 100;
        consensus.minGranularity             = 10*COIN;
        consensus.granularities              = std::vector<std::pair<uint32_t, int64_t> >(
                                               {{0, 100*COIN}});

        consensus.moneyBoxAddress = makeMoneyBoxScriptPubKey();
        consensus.graveAddress    = makeGraveScriptPubKey("U2xFeMxJfqbjGFEoCiQ3wFProGrDct9Ep7Snk", *this);

        pchMessageStart[0] = 0xef;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;

        nDefaultPort       = 19945;
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
        const char * pszTimestamp = "22/Oct/2021 regtest";

        std::vector<CScript> scripts(10);
        scripts[0] << OP_RETURN << ParseHex("036daf2772300f2226baf3a5012f23a5e775be80d7324427319a6f39d43b71271b");
        scripts[1] << OP_RETURN << ParseHex("034d83ef03bf4bdd6b6acb1fe164c03b2098eb1db605162fdd57c8846717fed83a");
        scripts[2] << OP_RETURN << ParseHex("03e63753c25c8fd5d0fe769e3f8c8601438db8e0a16420a09cd18dc049dd9f8521");
        scripts[3] << OP_RETURN << ParseHex("032b2b33fc097606930ebe94c17397ca0487fe61176b808dbd0cea420f10b2ca96");
        scripts[4] << OP_RETURN << ParseHex("036bfcf2c1eb983536ddde4f7af64cdb8ef2c2cdd08dbbb7735858b3e101c6edb4");
        scripts[5] << OP_RETURN << ParseHex("0287796a6e81d9e6060d50f86c19434391a69f13afb9d4999790b1cdc62ef09dc0");
        scripts[6] << OP_RETURN << ParseHex("02b59fc18825693c7497e23bae68e5331f7c751b6bdc3b216a64d1e6b5a23da5eb");
        scripts[7] << OP_RETURN << ParseHex("027b2ed67aedade28d0832e75ebbadc9aec8f418fb8a6ecbe02bdd61dd338d9cb9");
        scripts[8] << OP_RETURN << ParseHex("0263b101775655a0a9f8b19a9a84ad6b41d97d07b30ae8e9269614c620fc0addea");
        scripts[9] << OP_RETURN << ParseHex("024e84be3ce19f99e32cbc0314ff80b8a4f81b0d5393220330248c3316cb7474d0");

        genesis = CreateGenesisBlock(pszTimestamp, scripts, 1634850000, 0, 0x1f7fffff, 1, 1 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("5cb90a95d9f64031633b7c6d640834c17cf02be6cc16abef37c7bd3e7dba7b2e"));
        assert(genesis.hashMerkleRoot == uint256S("55cea9dc9eb2488fa176bf3fc5bebe8e4e83e87ab5521d4320f23f0cc730c852"));
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
