//******************************************************************************
//******************************************************************************

#include "plcvalidator.h"
#include "pubkey.h"
#include "validation.h"
#include "streams.h"
#include "script/standard.h"
#include "base58.h"
#include "util.h"

#include <algorithm>

#include <boost/range/adaptor/reversed.hpp>

namespace plc
{

//******************************************************************************
//******************************************************************************
class Validator::Impl
{
    friend class Validator;

protected:
    // return block timestamp
    // reqire cs_main!!!
    unsigned int getBlockTimestamp(const int & blockNo) const;

    // reqire cs_main!!!
    // see getBlockTimestamp
    bool verifyCert(const Certificate          & cert,
                    std::vector<std::vector<unsigned char> > & pubkeysOrHash,
                    CertParameters             & params) const;

    bool loadCert(const CTxOut   & out,
                  CertParameters & params) const;

    bool loadCert(const Certificate & cert,
                  CertParameters    & params) const;

    bool loadCertWithDb(const Certificate & cert,
                        CertParameters    & params) const;
};

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
unsigned int Validator::Impl::getBlockTimestamp(const int & blockNo) const
{
    if (blockNo < 0 || blockNo > chainActive.Height())
    {
        // block not found???
        return 0;
    }

    CBlockIndex * index = chainActive[blockNo];
    if (!index)
    {
        return 0;
    }

    return index->nTime;
}

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
bool Validator::Impl::verifyCert(const Certificate & cert,
                                 std::vector<std::vector<unsigned char> > & pubkeysOrHash,
                                 CertParameters & params) const
{
    if (pubkeysOrHash.size() == 0)
    {
        LogPrintf("%s: no pubkeys\n", __func__);
        return false;
    }

    params.percent = 0;

    const Coin coin = pcoinsTip->AccessCoin(COutPoint(cert.txid, cert.vout));
    if (coin.IsSpent())
    {
        // txout is spent
        LogPrintf("%s: Cert tx out is spent <%s:%d>\n", __func__, cert.txid.ToString(), cert.vout);
        return false;
    }

    const CTxOut & out = coin.out;

    if (!loadCert(out, params))
    {
        return false;
    }

    if (params.requiredCountOfSigs > pubkeysOrHash.size())
    {
        LogPrintf("%s: too few keys, need %d vs %d\n",
               __func__, params.requiredCountOfSigs, pubkeysOrHash.size());
        return false;
    }

    std::set<uint160> toSearch;
    std::set<uint160> forCheckDuplicates;
    std::copy(params.pubkeyHashes.begin(), params.pubkeyHashes.end(), std::inserter(toSearch, toSearch.end()));
    if (toSearch.size() != params.pubkeyHashes.size())
    {
        LogPrintf("%s: duplicated keys in certificate: <%s:%d>\n", __func__, cert.txid.ToString(), cert.vout);
        return false;
    }

    for (uint32_t i = 0; i < pubkeysOrHash.size(); ++i)
    {
        const std::vector<unsigned char> & pubkeyOrHash = pubkeysOrHash[i];
        // check pubkey or hash
        uint160 hash;
        if (pubkeysOrHash[i].size() == sizeof(uint160))
        {
            // this is hash of key
            hash = uint160(pubkeysOrHash[i]);
        }
        else
        {
            // this is a full publick key
            hash = Hash160(pubkeyOrHash.begin(),
                        pubkeyOrHash.begin() + pubkeyOrHash.size());
        }

        if (toSearch.count(hash) == 0)
        {
            LogPrintf("%s: specified key not found in certificate: <%s>\n", __func__, hash.ToString());
            return false;
        }

        if (forCheckDuplicates.count(hash))
        {
            LogPrintf("%s: key duplicated: <%s>\n", __func__, hash.ToString());
            return false;
        }
        forCheckDuplicates.insert(hash);
    }

    // get cert params and calc hash
    opcodetype op;
    std::vector<unsigned char> data;
    CScript::const_iterator pc = out.scriptPubKey.begin();
    if (!out.scriptPubKey.GetOp(pc, op, data))
    {
        LogPrintf("GetOp failed <%s>\n", __func__);
        return false;
    }

    uint256  streamHash;
    CDataStream stream(data, SER_NETWORK, 0);
    streamHash = Hash(stream.begin(), stream.end());

    // get signature
    std::vector<unsigned char> signature;
    if (!out.scriptPubKey.GetOp(pc, op, signature))
    {
        LogPrintf("GetOp failed (get signature error) <%s>\n", __func__);
        return false;
    }

    // skip all from begin to OP_2DROP
    for (; out.scriptPubKey.GetOp(pc, op) && op != OP_2DROP; );
    if (pc == out.scriptPubKey.end() || op != OP_2DROP)
    {
        // bad script?
        LogPrintf("Incorrect script <%s>\n", __func__);
        return false;
    }

    CScript copy;
    std::copy(pc, out.scriptPubKey.end(), std::back_inserter(copy));

    // extract up adress or public key
    CTxDestination dest;
    if (!ExtractDestination(copy, dest))
    {
        LogPrintf("Destination not extracted <%s>\n", __func__);
        return false;
    }

    CKeyID * keyid = boost::get<CKeyID>(&dest);
    if (!keyid)
    {
        LogPrintf("Invalid destination <%s>\n", __func__);
        return false;
    }

    // recover pubkey from signature
    CPubKey recoveredPubKey;
    if (!recoveredPubKey.RecoverCompact(streamHash, signature))
    {
        LogPrintf("Pubkey recovery error <%s>\n", __func__);
        return false;
    }

    // check pubkey
    if (recoveredPubKey.GetID() != *keyid)
    {
        // wrong signature
        LogPrintf("Wrong signature <%s>\n", __func__);
        return false;
    }

    pubkeysOrHash.resize(1);
    pubkeysOrHash.front().resize(keyid->size());
    std::copy(keyid->begin(), keyid->end(), pubkeysOrHash.front().begin());

    // block age
    params.height         = coin.nHeight;
    params.blockTimestamp = getBlockTimestamp(coin.nHeight);

    // amount (percent)
    params.percent = out.nValue;

    if (params.flags & hasMintingLimit || params.flags & hasMaxload)
    {
        // minting currents
        coin.getMintedAmount(params.limits);
    }

    return true;
}

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
bool Validator::Impl::loadCert(const CTxOut   & out,
                               CertParameters & params) const
{
    opcodetype op;
    std::vector<unsigned char> data;
    CScript::const_iterator pc = out.scriptPubKey.begin();
    if (!out.scriptPubKey.GetOp(pc, op, data))
    {
        LogPrintf("GetOp failed <%s>\n", __func__);
        return false;
    }

    params.percent = out.nValue;

    try
    {
        CDataStream stream(data, SER_NETWORK, 0);

        stream >> params.flags;
        uint32_t countOfKeys = (params.flags & pubkeyCountMask) >> 12;
        if (countOfKeys == 0)
        {
            // 0 interpreted as single key
            countOfKeys = 1;
        }
        for (size_t i = 0; i < countOfKeys; ++i)
        {
            params.pubkeyHashes.emplace_back(uint160());
            stream >> params.pubkeyHashes.back();
        }

        params.requiredCountOfSigs = (params.flags & requireCountMask) >> 28;
        if (params.requiredCountOfSigs == 0)
        {
            // require all
            params.requiredCountOfSigs = countOfKeys;
        }

        if (params.flags & hasDeviceKey)
        {
            stream >> params.deviceKeyHash;
        }
        if (params.flags & hasBeneficiaryKey)
        {
            stream >> params.beneficiaryKeyHash;
        }
        if (params.flags & hasExpirationDate)
        {
            stream >> params.expirationDate;
        }
        if (params.flags & hasMintingLimit)
        {
            stream >> params.mintingLimit;
        }
        if (params.flags & hasMaxload)
        {
            stream >> params.maxLoad;
        }
    }
    catch (const std::exception & e)
    {
        LogPrintf("Exception <%s> <%s>\n", e.what(), __func__);
        return false;
    }

    return true;
}

//******************************************************************************
// reqire cs_main!!!
// copied from fn above
//******************************************************************************
bool Validator::Impl::loadCert(const Certificate & cert,
                               CertParameters    & params) const
{
    const Coin & coin = pcoinsTip->AccessCoin(COutPoint(cert.txid, cert.vout));
    if (coin.IsSpent())
    {
        // txout is spent
        LogPrintf("Cert tx out is spent <%s> <%s>\n", cert.txid.ToString(), __func__);
        return false;
    }

    return loadCert(coin.out, params);
}

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
bool Validator::Impl::loadCertWithDb(const Certificate & cert,
                                     CertParameters    & params) const
{
    CTransactionRef tx;
    uint256 block;
    if (!GetTransaction(cert.txid, tx, Params().GetConsensus(), block, true))
    {
        LogPrintf("%s: cert <%s:%d> not found. no -txindex?\n",  __func__, cert.txid.ToString(), cert.vout);
        return false;
    }

    if (cert.vout >= tx->vout.size())
    {
        LogPrintf("%s: bad cert <%s:%d>\n",  __func__, cert.txid.ToString(), cert.vout);
        return false;
    }

    if (!loadCert(tx->vout[cert.vout], params))
    {
        LogPrintf("%s: cert load error <%s:%d>\n",  __func__, cert.txid.ToString(), cert.vout);
        return false;
    }

    BlockMap::iterator mi = mapBlockIndex.find(block);
    if (mi == mapBlockIndex.end() || !(*mi).second)
    {
        LogPrintf("%s: block not found for <%s:%d>\n",  __func__, cert.txid.ToString(), cert.vout);
        return false;
    }

    CBlockIndex * pindex = (*mi).second;
    if (!chainActive.Contains(pindex))
    {
        LogPrintf("%s: block not in main chain <%s:%d>\n",  __func__, cert.txid.ToString(), cert.vout);
        return false;
    }

    params.blockTimestamp = pindex->nTime;

    return true;
}

//******************************************************************************
//******************************************************************************
Validator::Validator()
    : m_p(new Impl)
{

}

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
bool Validator::validateChainOfCerts(const std::vector<Certificate>                 & certs,
                                     const std::vector<std::vector<unsigned char> > & pubkeys,
                                     CertParameters                                 & params) const
{
    if (certs.size() < 2)
    {
        // 2 - minimum
        LogPrintf("%s: Wrong count of certs\n", __func__);
        return false;
    }

    CertParameters paramsInternal[certs.size()];

    std::vector<std::vector<unsigned char> > pubkeysOrHashUp = pubkeys;

    int64_t amount = std::numeric_limits<int64_t>::max();
    for (size_t i = certs.size(); i > 0; --i)
    {
        size_t idx = i-1;
        const Certificate & cert = certs[idx];
        if (!m_p->verifyCert(cert, pubkeysOrHashUp, paramsInternal[idx]))
        {
            LogPrintf("%s: Invalid certificate <%s:%d>\n", __func__, cert.txid.ToString(), cert.vout);
            return false;
        }
        amount = std::min(amount, paramsInternal[idx].percent);
        if (amount == 0)
        {
            LogPrintf("%s: Zero percent for reward <%s:%d>\n", __func__, cert.txid.ToString(), cert.vout);
            return false;
        }
    }

    bool isKeyFound = false;
    for (const CTxOut & out : Params().GenesisBlock().vtx[0]->vout)
    {
        // at this point pubkeyOrHashUp must be eq one of pubkeys from coinbase

        opcodetype op;
        std::vector<unsigned char> data;
        CScript::const_iterator pc = out.scriptPubKey.begin();
        if (!out.scriptPubKey.GetOp(pc, op, data) || op != OP_RETURN)
        {
            continue;
        }
        if (!out.scriptPubKey.GetOp(pc, op, data))
        {
            continue;
        }

        if (pubkeysOrHashUp.front().size() != sizeof(uint160))
        {
            continue;
        }

        // check pubkey hash
        uint160 hash = Hash160(data.begin(), data.begin() + data.size());
        if (std::equal(hash.begin(), hash.end(), pubkeysOrHashUp.front().begin()))
        {
            isKeyFound = true;
            break;
        }
    }

    if (!isKeyFound)
    {
        LogPrintf("Pubkey hash not eq <%s>\n", __func__);
        return false;
    }

    // check age of root cert in chain
    if (Params().maxCaBlock() != 0 && Params().maxCaBlock() < paramsInternal[0].height)
    {
        LogPrintf("Cert is not ripe, dude <%s>\n", __func__);
        return false;
    }

    params.percent = amount;

    // timestamp from last cert
    params.blockTimestamp      = paramsInternal[certs.size()-1].blockTimestamp;

    // endpoint, beneficiary and device from last cert
    params.requiredCountOfSigs = paramsInternal[certs.size()-1].requiredCountOfSigs;
    params.pubkeyHashes        = paramsInternal[certs.size()-1].pubkeyHashes;
    params.beneficiaryKeyHash  = paramsInternal[certs.size()-1].beneficiaryKeyHash;
    params.deviceKeyHash       = paramsInternal[certs.size()-1].deviceKeyHash;
    params.expirationDate      = paramsInternal[certs.size()-1].expirationDate;
    params.mintingLimit        = paramsInternal[certs.size()-1].mintingLimit;
    params.maxLoad             = paramsInternal[certs.size()-1].maxLoad;
    params.limits              = paramsInternal[certs.size()-1].limits;

    // flags from first
    params.flags               = paramsInternal[0].flags & generalFlags;
    params.flags              |= (paramsInternal[certs.size()-1].flags & (freeBen));
    params.flags              |= (paramsInternal[certs.size()-1].flags & (silverHoof));
    params.flags              |= (paramsInternal[certs.size()-1].flags & (shadowEmperor));
    params.flags              |= (paramsInternal[certs.size()-1].flags & (holyShovel));
    params.flags              |= (paramsInternal[certs.size()-1].flags & (masterOfTime));

    if (params.deviceKeyHash.IsNull() &&
            (params.flags & silverHoof) == 0 &&
            (params.flags & shadowEmperor) == 0 &&
            (params.flags & holyShovel) == 0 &&
            (params.flags & masterOfTime) == 0)
    {
        LogPrintf("%s: No device h(key) found\n", __func__);
        return false;
    }
    return true;
}

//******************************************************************************
//******************************************************************************
bool Validator::verifyCertSignatures(const std::vector<std::vector<unsigned char> > & signatures,
                                     const std::vector<std::vector<unsigned char> > & pubkeys,
                                     const CertParameters & params,
                                     const CScript & scriptCode,
                                     const BaseSignatureChecker & signatureChecker) const
{
    // Hash type is one byte tacked on to the end of the signature
    if (signatures.empty())
    {
        LogPrintf("%s: no signatures\n", __func__);
        return false;
    }

    if (signatures.size() != pubkeys.size())
    {
        LogPrintf("%s: wrong count of signatures\n", __func__);
        return false;
    }

    if (signatures.size() < params.requiredCountOfSigs)
    {
        LogPrintf("%s: count of signatures less than required\n", __func__);
        return false;
    }

    for (size_t i = 0; i < pubkeys.size(); ++i)
    {
        if (!signatureChecker.CheckSig(signatures[i], pubkeys[i], scriptCode, SIGVERSION_BASE))
        {
            LogPrintf("%s: invalid signature <%d>\n", __func__, i);
            return false;
        }
    }

    return true;
}

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
bool Validator::loadCert(const Certificate & cert,
                         CertParameters    & params) const
{
    return m_p->loadCert(cert, params);
}

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
bool Validator::loadCertWithDb(const Certificate & cert,
                               CertParameters    & params) const
{
    return m_p->loadCertWithDb(cert, params);
}

} // namespace plc
