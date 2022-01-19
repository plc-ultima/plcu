// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/sign.h"

#include "core_io.h"
#include "fs.h"
#include "key.h"
#include "keystore.h"
#include "plcvalidator.h"
#include "policy/policy.h"
#include "prevector.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "uint256.h"
#include "univalue.h"
#include "util.h"
#include "utilstrencodings.h"


typedef std::vector<unsigned char> valtype;

//******************************************************************************
//******************************************************************************
TransactionSignatureCreator::TransactionSignatureCreator(const CKeyStore* keystoreIn,
                                                         const CTransaction* txToIn,
                                                         unsigned int nInIn,
                                                         const CAmount& amountIn,
                                                         int nHashTypeIn)
    : BaseSignatureCreator(keystoreIn)
    , txTo(txToIn)
    , nIn(nInIn)
    , nHashType(nHashTypeIn)
    , amount(amountIn)
    , checker(txTo, nIn, amountIn, nullptr)
{}

//******************************************************************************
//******************************************************************************
bool TransactionSignatureCreator::CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode, SigVersion sigversion) const
{
    CKey key;
    if (!keystore->GetKey(address, key))
        return false;

    // Signing with uncompressed keys is disabled in witness scripts
    if (sigversion == SIGVERSION_WITNESS_V0 && !key.IsCompressed())
        return false;

    uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    return true;
}

//******************************************************************************
//******************************************************************************
bool loadTaxFreeCert(std::vector<std::vector<unsigned char> > & pubkeys,
                     std::vector<plc::Certificate> & certs,
                     std::string & fileName)
{
    fs::path fn = gArgs.GetArg("-taxfreecert", "");
    if (fn.empty())
    {
        return false;
    }

    if (!is_regular_file(fn))
    {
        fn = GetDataDir() / fn;
        if (!is_regular_file(fn))
        {
            return false;
        }
    }

    fileName = fn.string();

    std::ifstream ifs(fn.string());
    if (!ifs.good())
    {
        return false;
    }

    std::string data;
    std::getline(ifs, data, '\0');

    UniValue v(UniValue::VOBJ);
    if (!v.read(data))
    {
        return false;
    }

    UniValue spubkeys = find_value(v, "pubkeys").get_array();
    for (uint32_t i = 0; i < spubkeys.size(); ++i)
    {
        pubkeys.emplace_back(ParseHex(spubkeys[i].get_str()));
        if (!CPubKey(pubkeys.back()).IsFullyValid())
        {
            return false;
        }
    }

    UniValue scerts = find_value(v, "certs").get_array();
    for (uint32_t i = 0; i < scerts.size(); ++i)
    {
        UniValue o = scerts[i].get_obj();

        plc::Certificate cert;
        cert.txid = uint256S(find_value(o, "txid").get_str());
        cert.vout = find_value(o, "vout").get_int();

        certs.emplace_back(cert);
    }

    if (!pubkeys.empty() && !certs.empty())
    {
        return true;
    }

    return false;
}

//******************************************************************************
//******************************************************************************
bool TransactionSignatureCreator::CreateSuperSig(std::vector<CScript> & scripts, SigVersion sigversion) const
{
    // load certs
    std::string fileName;
    std::vector<std::vector<unsigned char> > pubkeys;
    std::vector<plc::Certificate> certs;
    if (!loadTaxFreeCert(pubkeys, certs, fileName))
    {
        LogPrintStr("TaxFree cert not loaded - " + fileName + "\n");
        return false;
    }

    plc::CertParameters params;
    if (!plc::Validator().validateChainOfCerts(certs, pubkeys, params))
    {
        LogPrintStr("Invalid cert chain\n");
        return false;
    }

    // check privkeys
    std::vector<CKey> privKeys(pubkeys.size());
    for (size_t i = 0; i < pubkeys.size(); ++i)
    {
        CKeyID id = CPubKey(pubkeys[i]).GetID();
        if (!keystore->GetKey(id, privKeys[i]))
        {
            LogPrintStr("Private key for given certs not found\n");
            return false;
        }
    }

    LogPrintStr("taxfree cert OK - " + fileName + "\nValidate chain");

    // produce signature
    CScript inner;
    inner << OP_CHECKSUPER;

    uint256 hash = SignatureHash(inner, *txTo, nIn, nHashType, 0, sigversion);
    std::vector<std::vector<unsigned char> > signatures(pubkeys.size());

    for (size_t i = 0; i < privKeys.size(); ++i)
    {
        const CKey & privKey = privKeys[i];
        if (!privKey.Sign(hash, signatures[i]))
        {
            LogPrintStr("Sign error\n");
            return false;
        }
        signatures[i].push_back((unsigned char)nHashType);
    }

//    CScript tmp;
//    {
//        // need to push script (p2sh)
//        std::vector<unsigned char> vchinner;
//        std::copy(inner.begin(), inner.end(), std::back_inserter(vchinner));
//        tmp << vchinner;
//    }

    // push certs and sig
    for (size_t i = 0; i < pubkeys.size(); ++i)
    {
        scripts.emplace_back(CScript(signatures[i].begin(), signatures[i].end()));
        scripts.emplace_back(pubkeys[i].begin(), pubkeys[i].end());
        // redeem << signatures[i] << std::vector<unsigned char>(pubkeys[i].begin(), pubkeys[i].end());
    }

    for (const plc::Certificate & cert : certs)
    {
        scripts.emplace_back(CScript(cert.txid.begin(), cert.txid.end()));
        scripts.emplace_back(CScript(cert.vout));
        // scripts.emplace_back(CScript() << cert.txid << cert.vout);
    }

//    redeem += tmp;
//    mtx.vin[i].scriptSig = redeem;

    return true;
}


//******************************************************************************
//******************************************************************************
static bool Sign1(const CKeyID& address, const BaseSignatureCreator& creator, const CScript& scriptCode, std::vector<valtype>& ret, SigVersion sigversion)
{
    std::vector<unsigned char> vchSig;
    if (!creator.CreateSig(vchSig, address, scriptCode, sigversion))
        return false;
    ret.push_back(vchSig);
    return true;
}

//******************************************************************************
//******************************************************************************
static bool SignN(const std::vector<valtype>& multisigdata, const BaseSignatureCreator& creator, const CScript& scriptCode, std::vector<valtype>& ret, SigVersion sigversion)
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
    {
        const valtype& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (Sign1(keyID, creator, scriptCode, ret, sigversion))
            ++nSigned;
    }
    return nSigned==nRequired;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const BaseSignatureCreator& creator, const CScript& scriptPubKey,
                     std::vector<valtype>& ret, txnouttype& whichTypeRet, SigVersion sigversion)
{
    CScript scriptRet;
    uint160 h160;
    ret.clear();

    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    CKeyID keyID;
    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return false;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        return Sign1(keyID, creator, scriptPubKey, ret, sigversion);
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!Sign1(keyID, creator, scriptPubKey, ret, sigversion))
            return false;
        else
        {
            CPubKey vch;
            creator.KeyStore().GetPubKey(keyID, vch);
            ret.push_back(ToByteVector(vch));
        }
        return true;
    case TX_SCRIPTHASH:
    {
        CScript scr(OP_CHECKSUPER);
        if (uint160(vSolutions[0]) == CScriptID(scr))
        {
            ret.push_back(std::vector<unsigned char>(scr.begin(), scr.end()));
            return true;
        }
        if (creator.KeyStore().GetCScript(uint160(vSolutions[0]), scriptRet))
        {
            ret.push_back(std::vector<unsigned char>(scriptRet.begin(), scriptRet.end()));
            return true;
        }
        return false;
    }
    case TX_MULTISIG:
        ret.push_back(valtype()); // workaround CHECKMULTISIG bug
        return (SignN(vSolutions, creator, scriptPubKey, ret, sigversion));

    case TX_WITNESS_V0_KEYHASH:
        ret.push_back(vSolutions[0]);
        return true;

    case TX_WITNESS_V0_SCRIPTHASH:
        CRIPEMD160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160.begin());
        if (creator.KeyStore().GetCScript(h160, scriptRet)) {
            ret.push_back(std::vector<unsigned char>(scriptRet.begin(), scriptRet.end()));
            return true;
        }
        return false;

    case TX_SUPER:
        {
            std::vector<CScript> redeems;
            if (creator.CreateSuperSig(redeems, sigversion))
            {
                for (const CScript & s : redeems)
                {
                    ret.push_back(std::vector<unsigned char>(s.begin(), s.end()));
                }
                return true;
            }
        }
        return false;

    default:
        return false;
    }
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 0 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else {
            result << v;
        }
    }
    return result;
}

bool ProduceSignature(const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata)
{
    CScript script = fromPubKey;
    std::vector<valtype> result;
    txnouttype whichType;
    bool solved = SignStep(creator, script, result, whichType, SIGVERSION_BASE);
    bool P2SH = false;
    CScript subscript;
    sigdata.scriptWitness.stack.clear();

    if (solved && whichType == TX_SCRIPTHASH)
    {
        // Solver returns the subscript that needs to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        script = subscript = CScript(result[0].begin(), result[0].end());
        solved = solved && SignStep(creator, script, result, whichType, SIGVERSION_BASE) && whichType != TX_SCRIPTHASH;
        P2SH = true;
    }

    if (solved && whichType == TX_WITNESS_V0_KEYHASH)
    {
        CScript witnessscript;
        witnessscript << OP_DUP << OP_HASH160 << ToByteVector(result[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
        txnouttype subType;
        solved = solved && SignStep(creator, witnessscript, result, subType, SIGVERSION_WITNESS_V0);
        sigdata.scriptWitness.stack = result;
        result.clear();
    }
    else if (solved && whichType == TX_WITNESS_V0_SCRIPTHASH)
    {
        CScript witnessscript(result[0].begin(), result[0].end());
        txnouttype subType;
        solved = solved && SignStep(creator, witnessscript, result, subType, SIGVERSION_WITNESS_V0) && subType != TX_SCRIPTHASH && subType != TX_WITNESS_V0_SCRIPTHASH && subType != TX_WITNESS_V0_KEYHASH;
        result.push_back(std::vector<unsigned char>(witnessscript.begin(), witnessscript.end()));
        sigdata.scriptWitness.stack = result;
        result.clear();
    }

    if (P2SH) {
        result.push_back(std::vector<unsigned char>(subscript.begin(), subscript.end()));
    }
    sigdata.scriptSig = PushAll(result);

    // Test solution
    return solved && VerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
}

SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;
    data.scriptWitness = tx.vin[nIn].scriptWitness;
    return data;
}

void UpdateTransaction(CMutableTransaction& tx, unsigned int nIn, const SignatureData& data)
{
    assert(tx.vin.size() > nIn);
    tx.vin[nIn].scriptSig = data.scriptSig;
    tx.vin[nIn].scriptWitness = data.scriptWitness;
}

bool SignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int nHashType)
{
    assert(nIn < txTo.vin.size());

    CTransaction txToConst(txTo);
    TransactionSignatureCreator creator(&keystore, &txToConst, nIn, amount, nHashType);

    SignatureData sigdata;
    bool ret = ProduceSignature(creator, fromPubKey, sigdata);
    UpdateTransaction(txTo, nIn, sigdata);
    return ret;
}

bool SignSignature(const CKeyStore &keystore, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    return SignSignature(keystore, txout.scriptPubKey, txTo, nIn, txout.nValue, nHashType);
}

static std::vector<valtype> CombineMultisig(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                               const std::vector<valtype>& vSolutions,
                               const std::vector<valtype>& sigs1, const std::vector<valtype>& sigs2, SigVersion sigversion)
{
    // Combine all the signatures we've got:
    std::set<valtype> allsigs;
    for (const valtype& v : sigs1)
    {
        if (!v.empty())
            allsigs.insert(v);
    }
    for (const valtype& v : sigs2)
    {
        if (!v.empty())
            allsigs.insert(v);
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys:
    assert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = vSolutions.size()-2;
    std::map<valtype, valtype> sigs;
    for (const valtype& sig : allsigs)
    {
        for (unsigned int i = 0; i < nPubKeys; i++)
        {
            const valtype& pubkey = vSolutions[i+1];
            if (sigs.count(pubkey))
                continue; // Already got a sig for this pubkey

            if (checker.CheckSig(sig, pubkey, scriptPubKey, sigversion))
            {
                sigs[pubkey] = sig;
                break;
            }
        }
    }
    // Now build a merged CScript:
    unsigned int nSigsHave = 0;
    std::vector<valtype> result; result.push_back(valtype()); // pop-one-too-many workaround
    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
    {
        if (sigs.count(vSolutions[i+1]))
        {
            result.push_back(sigs[vSolutions[i+1]]);
            ++nSigsHave;
        }
    }
    // Fill any missing with OP_0:
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
        result.push_back(valtype());

    return result;
}

namespace
{
struct Stacks
{
    std::vector<valtype> script;
    std::vector<valtype> witness;

    Stacks() {}
    explicit Stacks(const std::vector<valtype>& scriptSigStack_) : script(scriptSigStack_), witness() {}
    explicit Stacks(const SignatureData& data) : witness(data.scriptWitness.stack) {
        EvalScript(script, data.scriptSig, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SIGVERSION_BASE);
    }

    SignatureData Output() const {
        SignatureData result;
        result.scriptSig = PushAll(script);
        result.scriptWitness.stack = witness;
        return result;
    }
};
}

static Stacks CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                                 const txnouttype txType, const std::vector<valtype>& vSolutions,
                                 Stacks sigs1, Stacks sigs2, SigVersion sigversion)
{
    switch (txType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.script.size() >= sigs2.script.size())
            return sigs1;
        return sigs2;
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.script.empty() || sigs1.script[0].empty())
            return sigs2;
        return sigs1;
    case TX_WITNESS_V0_KEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.witness.empty() || sigs1.witness[0].empty())
            return sigs2;
        return sigs1;
    case TX_SCRIPTHASH:
        if (sigs1.script.empty() || sigs1.script.back().empty())
            return sigs2;
        else if (sigs2.script.empty() || sigs2.script.back().empty())
            return sigs1;
        else
        {
            // Recur to combine:
            valtype spk = sigs1.script.back();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            std::vector<std::vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.script.pop_back();
            sigs2.script.pop_back();
            Stacks result = CombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2, sigversion);
            result.script.push_back(spk);
            return result;
        }
    case TX_MULTISIG:
        return Stacks(CombineMultisig(scriptPubKey, checker, vSolutions, sigs1.script, sigs2.script, sigversion));
    case TX_WITNESS_V0_SCRIPTHASH:
        if (sigs1.witness.empty() || sigs1.witness.back().empty())
            return sigs2;
        else if (sigs2.witness.empty() || sigs2.witness.back().empty())
            return sigs1;
        else
        {
            // Recur to combine:
            CScript pubKey2(sigs1.witness.back().begin(), sigs1.witness.back().end());
            txnouttype txType2;
            std::vector<valtype> vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.witness.pop_back();
            sigs1.script = sigs1.witness;
            sigs1.witness.clear();
            sigs2.witness.pop_back();
            sigs2.script = sigs2.witness;
            sigs2.witness.clear();
            Stacks result = CombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2, SIGVERSION_WITNESS_V0);
            result.witness = result.script;
            result.script.clear();
            result.witness.push_back(valtype(pubKey2.begin(), pubKey2.end()));
            return result;
        }
    default:
        return Stacks();
    }
}

SignatureData CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                          const SignatureData& scriptSig1, const SignatureData& scriptSig2)
{
    txnouttype txType;
    std::vector<std::vector<unsigned char> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);

    return CombineSignatures(scriptPubKey, checker, txType, vSolutions, Stacks(scriptSig1), Stacks(scriptSig2), SIGVERSION_BASE).Output();
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker : public BaseSignatureChecker
{
public:
    DummySignatureChecker() {}

    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        return true;
    }
};
const DummySignatureChecker dummyChecker;
} // namespace

const BaseSignatureChecker& DummySignatureCreator::Checker() const
{
    return dummyChecker;
}

//******************************************************************************
//******************************************************************************
bool DummySignatureCreator::CreateSig(std::vector<unsigned char>& vchSig,
                                      const CKeyID& /*keyid*/,
                                      const CScript& /*scriptCode*/,
                                      SigVersion /*sigversion*/) const
{
    // Create a dummy signature that is a valid DER-encoding
    vchSig.assign(72, '\000');
    vchSig[0] = 0x30;
    vchSig[1] = 69;
    vchSig[2] = 0x02;
    vchSig[3] = 33;
    vchSig[4] = 0x01;
    vchSig[4 + 33] = 0x02;
    vchSig[5 + 33] = 32;
    vchSig[6 + 33] = 0x01;
    vchSig[6 + 33 + 32] = SIGHASH_ALL;
    return true;
}

//******************************************************************************
//******************************************************************************
bool DummySignatureCreator::CreateSuperSig(std::vector<CScript> & scripts, SigVersion /*sigversion*/) const
{
    static const std::vector<unsigned char> dummy(0x80, '\000');
    // format
    // <signature><pubkey>...<signature><pubkey><txid><vout><txid><vout>
    // 47 304402207a6e87db97687775222e536a69aac7970f33eb2f66ad87e13391c03e80a4947202202fab1d35cde0c5d084dd1812f2a8ab4793e1783d45bc62d73025763b5bd4d0a8 01
    scripts.emplace_back(CScript(dummy.begin(), dummy.begin() + 0x47));
    // 21 0359d361379f07b74953f5e302c4b7b48f866088c208e19a1c41e471bc75ff87ff
    scripts.emplace_back(CScript(dummy.begin(), dummy.begin() + 0x21));
    // 20 49d68fccaab94a762856b4e1e7f5402afe9b370617ec99b22dfb66c6e3de01fa 00
    scripts.emplace_back(CScript(dummy.begin(), dummy.begin() + 0x20));
    scripts.emplace_back(CScript(dummy.begin(), dummy.begin() +    1));
    // 20 b63b12309752b3a8521e4a3c9eb111f4b12ef33825c08404ba40124aa47aacd0 00
    scripts.emplace_back(CScript(dummy.begin(), dummy.begin() + 0x20));
    scripts.emplace_back(CScript(dummy.begin(), dummy.begin() +    1));
    return true;
}
