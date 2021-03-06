// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/standard.h"

#include "pubkey.h"
#include "script/script.h"
#include "util.h"
#include "utilstrencodings.h"


typedef std::vector<unsigned char> valtype;

bool fAcceptDatacarrier = DEFAULT_ACCEPT_DATACARRIER;
unsigned nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;

CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

const char* GetTxnOutputType(txnouttype t)
{
    switch (t)
    {
        case TX_NONSTANDARD: return "nonstandard";
        case TX_PUBKEY: return "pubkey";
        case TX_PUBKEYHASH: return "pubkeyhash";
        case TX_SCRIPTHASH: return "scripthash";
        case TX_MULTISIG: return "multisig";
        case TX_NULL_DATA: return "nulldata";
        case TX_WITNESS_V0_KEYHASH: return "witness_v0_keyhash";
        case TX_WITNESS_V0_SCRIPTHASH: return "witness_v0_scripthash";
        case TX_AB_MINTING: return "ab_minting";
        case TX_SUPER: return "super";
    }
    return nullptr;
}

bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet)
{
    uint32_t lockTimeRet = 0;
    return Solver(scriptPubKey, typeRet, vSolutionsRet, lockTimeRet);
}

/**
 * Return public keys or hashes from scriptPubKey, for 'standard' transaction types.
 */
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet, uint32_t & lockTimeRet)
{
    // Templates
    static std::multimap<txnouttype, CScript> mTemplates;
    if (mTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(std::make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        // and time locked version
        mTemplates.insert(std::make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));
        mTemplates.insert(std::make_pair(TX_PUBKEYHASH, CScript() << OP_SMALLINTEGER << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(std::make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));

        // ab-minting (with locktimeverify and without)
        mTemplates.insert(std::make_pair(TX_AB_MINTING, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUAL
                                         << OP_IF
                                         << OP_CHECKSIG
                                         << OP_ELSE
                                         << OP_OVER << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY
                                         << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY
                                         << OP_2 << OP_CHECKMULTISIG
                                         << OP_ENDIF));
        mTemplates.insert(std::make_pair(TX_AB_MINTING, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUAL
                                         << OP_IF
                                         << OP_SMALLINTEGER << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_CHECKSIG
                                         << OP_ELSE
                                         << OP_OVER << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY
                                         << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY
                                         << OP_2 << OP_CHECKMULTISIG
                                         << OP_ENDIF));

        // super tx
        mTemplates.insert(std::make_pair(TX_SUPER, CScript() << OP_CHECKSUPER));
    }

    vSolutionsRet.clear();
    lockTimeRet = 0;

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram))
    {
        if (witnessversion == 0 && witnessprogram.size() == 20)
        {
            typeRet = TX_WITNESS_V0_KEYHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        if (witnessversion == 0 && witnessprogram.size() == 32)
        {
            typeRet = TX_WITNESS_V0_SCRIPTHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        return false;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1))
    {
        typeRet = TX_NULL_DATA;
        return true;
    }

    // Scan templates
    const CScript & script1 = scriptPubKey;
    auto script1Begin = script1.begin();

    // two pass
    for (uint32_t i = 0; i < 2; ++i)
    {
        for (const std::pair<const txnouttype, CScript> & tplate : mTemplates)
        {
            const CScript & script2 = tplate.second;
            vSolutionsRet.clear();

            opcodetype opcode1, opcode2;
            std::vector<unsigned char> vch1, vch2;

            // Compare
            CScript::const_iterator pc1 = script1Begin;
            CScript::const_iterator pc2 = script2.begin();
            while (true)
            {
                if (pc1 == script1.end() && pc2 == script2.end())
                {
                    // Found a match
                    typeRet = tplate.first;
                    if (typeRet == TX_MULTISIG)
                    {
                        // Additional checks for TX_MULTISIG:
                        unsigned char m = vSolutionsRet.front()[0];
                        unsigned char n = vSolutionsRet.back()[0];
                        if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                        {
                            return false;
                        }
                    }
                    return true;
                }
                if (!script1.GetOp(pc1, opcode1, vch1) ||
                    !script2.GetOp(pc2, opcode2, vch2))
                {
                    break;
                }

                // Template matching opcodes:
                if (opcode2 == OP_PUBKEYS)
                {
                    while (vch1.size() >= 33 && vch1.size() <= 65)
                    {
                        vSolutionsRet.push_back(vch1);
                        if (!script1.GetOp(pc1, opcode1, vch1))
                        {
                            break;
                        }
                    }
                    if (!script2.GetOp(pc2, opcode2, vch2))
                    {
                        break;
                    }
                    // Normal situation is to fall through
                    // to other if/else statements
                }

                if (opcode2 == OP_PUBKEY)
                {
                    if (vch1.size() < 33 || vch1.size() > 65)
                    {
                        break;
                    }
                    vSolutionsRet.push_back(vch1);
                }
                else if (opcode2 == OP_PUBKEYHASH)
                {
                    if (vch1.size() != sizeof(uint160))
                    {
                        break;
                    }
                    vSolutionsRet.push_back(vch1);
                }
                else if (opcode2 == OP_SMALLINTEGER)
                {
                    bool is_lockTime = false;
                    // check next opcode, may be locktimeverify?
                    CScript::const_iterator pc2t = pc2;
                    opcodetype opcode2t;
                    std::vector<unsigned char> vch2t;
                    if (script2.GetOp(pc2t, opcode2t, vch2t))
                    {
                        if (opcode2t == OP_CHECKLOCKTIMEVERIFY)
                        {
                            is_lockTime = true;
                        }
                    }


                    // Single-byte small integer pushed onto vSolutions
                    if (opcode1 == OP_0 ||
                        (opcode1 >= OP_1 && opcode1 <= OP_16))
                    {
                        char n = (char)CScript::DecodeOP_N(opcode1);

                        if (is_lockTime)
                        {
                            if (lockTimeRet < static_cast<uint32_t>(n))
                            {
                                lockTimeRet = static_cast<uint32_t>(n);
                            }
                        }
                        else
                        {
                            vSolutionsRet.push_back(valtype(1, n));
                        }
                    }
                    else if (opcode1 <= OP_PUSHDATA1)
                    {
                        if (vch1.size() > 4)
                        {
                            break;
                        }

                        if (is_lockTime)
                        {
                            const CScriptNum locktime(vch1, true, 5);
                            // uint32_t locktime = (uint32_t)CScript::DecodeOP_N(opcode1);
                            if (lockTimeRet < locktime.get<uint32_t>())
                            {
                                lockTimeRet = locktime.get<uint32_t>();
                            }
                        }
                        else
                        {
                            // need to push ?
                            // vSolutionsRet.push_back(vch1);
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                else if (opcode1 != opcode2 || vch1 != vch2)
                {
                    // Others must match exactly
                    break;
                }
            }
        }

        if (i != 0)
        {
            break;
        }

        // second check, skip data from beginning of script1
        script1Begin = script1.begin_skipLeadingData();
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    uint32_t lockTimeRet = 0;
    return ExtractDestination(scriptPubKey, addressRet, lockTimeRet);
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet, uint32_t & lockTimeRet)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions, lockTimeRet))
        return false;

    if (whichType == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid())
        {
            return false;
        }

        addressRet = pubKey.GetID();
        return true;
    }
    else if (whichType == TX_PUBKEYHASH)
    {
        if (vSolutions[0].size() != 20)
        {
            return false;
        }
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TX_SCRIPTHASH)
    {
        if (vSolutions[0].size() != 20)
        {
            return false;
        }
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    }
    // Multisig txns have more than one address...
    return false;
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet)
{
    uint32_t lockTimeRet = 0;
    return ExtractDestinations(scriptPubKey, typeRet, addressRet, nRequiredRet, lockTimeRet);
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet, uint32_t & lockTimeRet)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, typeRet, vSolutions, lockTimeRet))
        return false;
    if (typeRet == TX_NULL_DATA)
    {
        // This is data, not addresses
        return false;
    }

    if (typeRet == TX_MULTISIG)
    {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; i++)
        {
            CPubKey pubKey(vSolutions[i]);
            if (!pubKey.IsValid())
            {
                continue;
            }

            CTxDestination address = pubKey.GetID();
            addressRet.push_back(address);
        }

        if (addressRet.empty())
        {
            return false;
        }
    }
    else if (typeRet == TX_AB_MINTING)
    {
        for (unsigned int i = 0; i < vSolutions.size(); i++)
        {
            if (vSolutions[i].size() != 20)
            {
                continue;
            }
            uint160 id(vSolutions[i]);
            addressRet.push_back(CKeyID(id));
        }
    }
    else
    {
        nRequiredRet = 1;
        CTxDestination address;
        if (!ExtractDestination(scriptPubKey, address, lockTimeRet))
           return false;
        addressRet.push_back(address);
    }

    return true;
}

//******************************************************************************
//******************************************************************************
bool isMintingTx(const CTransaction & tx)
{
    for (const CTxIn & in : tx.vin)
    {
        std::vector<plc::Certificate> certs;
        if (isMintingScript(in.scriptSig, certs))
        {
            return true;
        }
    }

    return false;
}

//******************************************************************************
//******************************************************************************
bool isCorrectPlcSignature(const CScript & scriptSig,
                           const CScript & innerScript,
                           std::vector<plc::Certificate> & certs)
{
    // script must be pushOnly
    // format
    // <signature><pubkey>...<signature><pubkey><txid><vout><txid><vout><OP_CHECKREWARD>

    certs.clear();

    if (!scriptSig.IsPushOnly())
    {
        return false;
    }

    // vector<opcode, data>
    CScript::Ops ops;
    if (!scriptSig.parse(ops) || ops.size() < 7)
    {
        return false;
    }

    // sheck signatures and pubkeys
    size_t i = 0;
    for (; i < ops.size()-5; i += 2)
    {
        if (!IsValidSignatureEncoding(ops[i].second))
        {
            return false;
        }
        if (!IsCompressedOrUncompressedPubKey(ops[i+1].second))
        {
            return false;
        }
    }

    for (; i < ops.size()-1; i += 2)
    {
        plc::Certificate cert;

        if (ops[i].second.size() != sizeof(uint256))
        {
            return false;
        }

        cert.txid = uint256(ops[i].second);

        if (ops[i+1].second.size() > 0)
        {
            cert.vout = CScriptNum(ops[i+1].second, true).get<uint32_t>();
        }
        else
        {
            if (ops[i+1].first > OP_16)
            {
                return false;
            }
            cert.vout = CScript::DecodeOP_N(ops[i+1].first);
        }

        certs.emplace_back(cert);
    }

    if (!std::equal(ops[i].second.begin(), ops[i].second.end(), innerScript.begin()))
    {
        return false;
    }

    return true;
}

//******************************************************************************
//******************************************************************************
bool isMintingScript(const CScript & scriptSig, std::vector<plc::Certificate> & certs)
{
    return isCorrectPlcSignature(scriptSig, CScript(OP_CHECKREWARD), certs);
}

//******************************************************************************
//******************************************************************************
bool isInputSuperSigned(const CTxIn & txin)
{
    if (txin.prevout.hash != uint256() || txin.prevout.n != 0)
    {
        return false;
    }

    if (txin.scriptSig.empty())
    {
        return false;
    }

    return true;
}

//******************************************************************************
//******************************************************************************
bool isValidSuperSignatureFormat(const CScript & scriptSig)
{
    std::vector<plc::Certificate> certs;
    return isCorrectPlcSignature(scriptSig, CScript(OP_CHECKSUPER), certs);
}

//******************************************************************************
//******************************************************************************
bool isSuperTx(const CTransaction & tx)
{
    for (const CTxIn & in : tx.vin)
    {
        if (isInputSuperSigned(in) && isValidSuperSignatureFormat(in.scriptSig))
        {
            return true;
        }
    }
    return false;
}

//******************************************************************************
//******************************************************************************
CScript makeSuperTxScriptPubKey()
{
    CScript scr(OP_CHECKSUPER);
    CScriptID id(scr);
    CScript result;
    result << OP_HASH160 << ToByteVector(id) << OP_EQUAL;
    return result;
}

//******************************************************************************
//******************************************************************************
namespace
{
class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
public:
    CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        return true;
    }
};
} // namespace

CScript GetScriptForDestination(const CTxDestination& dest)
{
    CScript script;

    boost::apply_visitor(CScriptVisitor(&script), dest);
    return script;
}

CScript GetScriptForRawPubKey(const CPubKey& pubKey)
{
    return CScript() << std::vector<unsigned char>(pubKey.begin(), pubKey.end()) << OP_CHECKSIG;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    CScript script;

    script << CScript::EncodeOP_N(nRequired);
    for (const CPubKey& key : keys)
        script << ToByteVector(key);
    script << CScript::EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
    return script;
}

CScript GetScriptForWitness(const CScript& redeemscript)
{
    CScript ret;

    txnouttype typ;
    std::vector<std::vector<unsigned char> > vSolutions;
    if (Solver(redeemscript, typ, vSolutions)) {
        if (typ == TX_PUBKEY) {
            unsigned char h160[20];
            CHash160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160);
            ret << OP_0 << std::vector<unsigned char>(&h160[0], &h160[20]);
            return ret;
        } else if (typ == TX_PUBKEYHASH) {
           ret << OP_0 << vSolutions[0];
           return ret;
        }
    }
    uint256 hash;
    CSHA256().Write(&redeemscript[0], redeemscript.size()).Finalize(hash.begin());
    ret << OP_0 << ToByteVector(hash);
    return ret;
}
