// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "util.h"
#include "validation.h"
#include "chainparams.h"
#include "validation.h"
#include "base58.h"
#include "plccertificate.h"
#include "plcvalidator.h"
#include "streams.h"
#include "txmempool.h"
#include "utilstrencodings.h"
#include "util.h"

typedef std::vector<unsigned char> valtype;

namespace {

inline bool set_success(ScriptError* ret)
{
    if (ret)
        *ret = SCRIPT_ERR_OK;
    return true;
}

inline bool set_error(ScriptError* ret, const ScriptError serror)
{
    if (ret)
        *ret = serror;
    return false;
}

} // namespace

bool CastToBool(const valtype& vch)
{
    for (unsigned int i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size()-1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))
static inline void popstack(std::vector<valtype>& stack)
{
    if (stack.empty())
        throw std::runtime_error("popstack(): stack empty");
    stack.pop_back();
}

bool IsCompressedOrUncompressedPubKey(const valtype &vchPubKey) {
    if (vchPubKey.size() < 33) {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != 65) {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    } else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != 33) {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    } else {
        //  Non-canonical public key: neither compressed nor uncompressed
        return false;
    }
    return true;
}

bool static IsCompressedPubKey(const valtype &vchPubKey) {
    if (vchPubKey.size() != 33) {
        //  Non-canonical public key: invalid length for compressed key
        return false;
    }
    if (vchPubKey[0] != 0x02 && vchPubKey[0] != 0x03) {
        //  Non-canonical public key: invalid prefix for compressed key
        return false;
    }
    return true;
}

/**
 * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
bool IsValidSignatureEncoding(const std::vector<unsigned char> &sig) {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != sig.size() - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= sig.size()) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != sig.size()) return false;

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

bool static IsLowDERSignature(const valtype &vchSig, ScriptError* serror) {
    if (!IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    std::vector<unsigned char> vchSigCopy(vchSig.begin(), vchSig.begin() + vchSig.size() - 1);
    if (!CPubKey::CheckLowS(vchSigCopy)) {
        return set_error(serror, SCRIPT_ERR_SIG_HIGH_S);
    }
    return true;
}

bool static IsDefinedHashtypeSignature(const valtype &vchSig) {
    if (vchSig.size() == 0) {
        return false;
    }
    unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(SIGHASH_ANYONECANPAY));
    if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE)
        return false;

    return true;
}

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror) {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (vchSig.size() == 0) {
        return true;
    }
    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    } else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig, serror)) {
        // serror is set
        return false;
    } else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    }
    return true;
}

bool CheckPubKeyEncoding(const std::vector<unsigned char> &vchPubKey, unsigned int flags, const SigVersion &sigversion, ScriptError* serror) {
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsCompressedOrUncompressedPubKey(vchPubKey)) {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }
    // Only compressed keys are accepted in segwit
    if ((flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 && sigversion == SIGVERSION_WITNESS_V0 && !IsCompressedPubKey(vchPubKey)) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PUBKEYTYPE);
    }
    return true;
}

bool static CheckMinimalPush(const valtype& data, opcodetype opcode) {
    if (data.size() == 0) {
        // Could have used OP_0.
        return opcode == OP_0;
    } else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16) {
        // Could have used OP_1 .. OP_16.
        return opcode == OP_1 + (data[0] - 1);
    } else if (data.size() == 1 && data[0] == 0x81) {
        // Could have used OP_1NEGATE.
        return opcode == OP_1NEGATE;
    } else if (data.size() <= 75) {
        // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == data.size();
    } else if (data.size() <= 255) {
        // Could have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    } else if (data.size() <= 65535) {
        // Could have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    return true;
}

//******************************************************************************
//******************************************************************************
bool getPlcSpecific(const std::vector<std::vector<unsigned char> > & stack,
                    const unsigned int flags, const SigVersion sigversion,
                    std::vector<plc::Certificate> & certs,
                    std::vector<std::vector<unsigned char> > & pubkeys,
                    std::vector<std::vector<unsigned char> > & signatures,
                    ScriptError * serror, size_t & stackUsed)
{
    if (stack.size() < 6)
    {
        return set_error(serror, SCRIPT_ERR_BAD_SCRIPT);
    }

    stackUsed = 0;

    while (stack.size() >= stackUsed + 4)
    {
        if (stacktop(-1-stackUsed).size() > sizeof(uint32_t) ||
            stacktop(-2-stackUsed).size() != sizeof(uint256))

        {
            break;
        }

        certs.emplace(certs.begin(),
                      uint256(stacktop(-2-stackUsed)),
                      CScriptNum(stacktop(-1-stackUsed), true).get<uint32_t>());
        stackUsed += 2;
    }

    if (certs.size() < 2)
    {
        // check, 2 - minimum
        return set_error(serror, SCRIPT_ERR_BAD_SCRIPT);
    }

    while (stack.size() >= stackUsed+2)
    {
        if (!CheckSignatureEncoding(stacktop(-2-stackUsed), flags, serror) ||
            !CheckPubKeyEncoding(stacktop(-1-stackUsed), flags, sigversion, serror))
        {
            // serror is set
            break;
        }

        pubkeys.emplace_back(stacktop(-1-stackUsed));
        signatures.emplace_back(stacktop(-2-stackUsed));

        stackUsed += 2;
    }

    return true;
}

//******************************************************************************
//******************************************************************************
bool loadPlcCerts(std::vector<std::vector<unsigned char> > & stack,
                  CScript::const_iterator pbegin, CScript::const_iterator pend,
                  const unsigned int flags,
                  const BaseSignatureChecker & checker,
                  const SigVersion sigversion,
                  std::vector<plc::Certificate> & certs, plc::CertParameters & params,
                  ScriptError * serror)
{
    if (stack.size() < 6)
    {
        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    std::vector<std::vector<unsigned char> > pubkeys;
    std::vector<std::vector<unsigned char> > signatures;

    size_t stackUsed = 0;
    bool fSuccess = getPlcSpecific(stack, flags, sigversion,
                        certs, pubkeys, signatures, serror, stackUsed);
    if (!fSuccess && (flags & SCRIPT_VERIFY_REWARD))
    {
        // error already set
        return false;
    }

    // validate certificate
    plc::Validator validator;
    fSuccess = fSuccess && validator.validateChainOfCerts(certs, pubkeys, params);
    if (!fSuccess && (flags & SCRIPT_VERIFY_REWARD))
    {
        // bad chain
        LogPrintf("Validate chain of certs failed <%s>\n", __func__);
        return set_error(serror, SCRIPT_ERR_BAD_CERTIFICATE);
    }

    // Subset of script starting at the most recent codeseparator
    CScript scriptCode(pbegin, pend);
    fSuccess = fSuccess && validator.verifyCertSignatures(signatures, pubkeys,
                                                          params, scriptCode, checker);
    if (!fSuccess && (flags & SCRIPT_VERIFY_REWARD))
    {
        // bad signatures
        LogPrintf("Incorrect cert signatures <%s>\n", __func__);
        return set_error(serror, SCRIPT_ERR_BAD_SIGNATURES);
    }

    // rm certs/signatures from stack
    for (uint32_t i = 0; i < stackUsed; ++i)
    {
        stack.pop_back();
    }

    return true;
}

//******************************************************************************
//******************************************************************************
bool EvalScript(std::vector<std::vector<unsigned char> >& stack,
                const CScript& script,
                unsigned int flags,
                const BaseSignatureChecker& checker,
                SigVersion sigversion,
                ScriptError* serror)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    // static const CScriptNum bnFalse(0);
    // static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    // static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    std::vector<bool> vfExec;
    std::vector<valtype> altstack;
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    if (script.size() > MAX_SCRIPT_SIZE)
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
    int nOpCount = 0;
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;

    try
    {
        while (pc < pend)
        {
            bool fExec = !count(vfExec.begin(), vfExec.end(), false);

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT)
                return set_error(serror, SCRIPT_ERR_OP_COUNT);

            if (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT)
                return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE); // Disabled opcodes.

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue, opcode)) {
                    return set_error(serror, SCRIPT_ERR_MINIMALDATA);
                }
                stack.push_back(vchPushValue);
            } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            switch (opcode)
            {
                //
                // Push value
                //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                    stack.push_back(bn.getvch());
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                }
                break;


                //
                // Control
                //
                case OP_NOP:
                    break;

                case OP_CHECKLOCKTIMEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // Actually compare the specified lock time with the transaction.
                    if (!checker.CheckLockTime(nLockTime))
                    {
                        // rm locktime
                        stack.pop_back();

                        // check master of time cert
                        std::vector<plc::Certificate> certs;
                        plc::CertParameters params;

                        bool hasCerts = loadPlcCerts(stack, pbegincodehash, pend, flags,
                                                     checker, sigversion,
                                                     certs, params, serror);

                        if (!hasCerts || (params.flags & plc::masterOfTime) == 0)
                        {
                            // restore locktime if error
                            stack.push_back(nLockTime.getvch());
                            return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
                        }
                    }

                    break;
                }

                case OP_CHECKSEQUENCEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                        // not enabled; treat as a NOP3
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // nSequence, like nLockTime, is a 32-bit unsigned integer
                    // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                    // 5-byte numeric operands.
                    const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (nSequence < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
                        break;

                    // Compare the specified sequence number with the input.
                    if (!checker.CheckSequence(nSequence))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    break;
                }

                case OP_NOP1: case OP_NOP4: case OP_NOP5:
                case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
                {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                }
                break;

                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        valtype& vch = stacktop(-1);
                        if (sigversion == SIGVERSION_WITNESS_V0 && (flags & SCRIPT_VERIFY_MINIMALIF)) {
                            if (vch.size() > 1)
                                return set_error(serror, SCRIPT_ERR_MINIMALIF);
                            if (vch.size() == 1 && vch[0] != 1)
                                return set_error(serror, SCRIPT_ERR_MINIMALIF);
                        }
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                break;

                case OP_ELSE:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.back() = !vfExec.back();
                }
                break;

                case OP_ENDIF:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.pop_back();
                }
                break;

                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                        popstack(stack);
                    else
                        return set_error(serror, SCRIPT_ERR_VERIFY);
                }
                break;

                case OP_RETURN:
                {
                    return set_error(serror, SCRIPT_ERR_OP_RETURN);
                }
                break;


                //
                // Stack ops
                //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    altstack.push_back(stacktop(-1));
                    popstack(stack);
                }
                break;

                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                    stack.push_back(altstacktop(-1));
                    popstack(altstack);
                }
                break;

                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-3);
                    valtype vch2 = stacktop(-2);
                    valtype vch3 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                    stack.push_back(vch3);
                }
                break;

                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-4);
                    valtype vch2 = stacktop(-3);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-6);
                    valtype vch2 = stacktop(-5);
                    stack.erase(stack.end()-6, stack.end()-4);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                break;

                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    if (CastToBool(vch))
                        stack.push_back(vch);
                }
                break;

                case OP_DEPTH:
                {
                    // -- stacksize
                    CScriptNum bn(stack.size());
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                }
                break;

                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.push_back(vch);
                }
                break;

                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    stack.erase(stack.end() - 2);
                }
                break;

                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-2);
                    stack.push_back(vch);
                }
                break;

                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    int n = CScriptNum(stacktop(-1), fRequireMinimal).get<int>();
                    popstack(stack);
                    if (n < 0 || n >= (int)stack.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-n-1);
                    if (opcode == OP_ROLL)
                        stack.erase(stack.end()-n-1);
                    stack.push_back(vch);
                }
                break;

                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.insert(stack.end()-2, vch);
                }
                break;


                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1).size());
                    stack.push_back(bn.getvch());
                }
                break;


                //
                // Bitwise logic
                //
                case OP_EQUAL:
                case OP_EQUALVERIFY:
                //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch1 = stacktop(-2);
                    valtype& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fEqual ? vchTrue : vchFalse);
                    if (opcode == OP_EQUALVERIFY)
                    {
                        if (fEqual)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
                    }
                }
                break;


                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1), fRequireMinimal);
                    switch (opcode)
                    {
                    case OP_1ADD:       bn += bnOne; break;
                    case OP_1SUB:       bn -= bnOne; break;
                    case OP_NEGATE:     bn = -bn; break;
                    case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                    case OP_NOT:        bn = (bn == bnZero); break;
                    case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                    default:            assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-2), fRequireMinimal);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal);
                    CScriptNum bn(0);
                    switch (opcode)
                    {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;

                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;

                    case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                    case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                    case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                    case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                    case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                    case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                    case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                    case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                    case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                    case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                    case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                    default:                     assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(bn.getvch());

                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if (CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                    }
                }
                break;

                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-3), fRequireMinimal);
                    CScriptNum bn2(stacktop(-2), fRequireMinimal);
                    CScriptNum bn3(stacktop(-1), fRequireMinimal);
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fValue ? vchTrue : vchFalse);
                }
                break;


                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                        CRIPEMD160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA1)
                        CSHA1().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA256)
                        CSHA256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_HASH160)
                        CHash160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_HASH256)
                        CHash256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    popstack(stack);
                    stack.push_back(vchHash);
                }
                break;

                case OP_CODESEPARATOR:
                {
                    // Hash starts after the code separator
                    pbegincodehash = pc;
                }
                break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype& vchSig    = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    if (sigversion == SIGVERSION_BASE) {
                        scriptCode.FindAndDelete(CScript(vchSig));
                    }

                    if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
                        //serror is set
                        return false;
                    }
                    bool fSuccess = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion);

                    if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && vchSig.size())
                        return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);

                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                    }
                }
                break;

                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    int i = 1;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).get<int>();
                    if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
                        return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                    nOpCount += nKeysCount;
                    if (nOpCount > MAX_OPS_PER_SCRIPT)
                        return set_error(serror, SCRIPT_ERR_OP_COUNT);
                    int ikey = ++i;
                    // ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                    // With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                    int ikey2 = nKeysCount + 2;
                    i += nKeysCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).get<int>();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                        return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                    int isig = ++i;
                    i += nSigsCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    for (int k = 0; k < nSigsCount; k++)
                    {
                        valtype& vchSig = stacktop(-isig-k);
                        if (sigversion == SIGVERSION_BASE) {
                            scriptCode.FindAndDelete(CScript(vchSig));
                        }
                    }

                    bool fSuccess = true;
                    while (fSuccess && nSigsCount > 0)
                    {
                        valtype& vchSig    = stacktop(-isig);
                        valtype& vchPubKey = stacktop(-ikey);

                        // Note how this makes the exact order of pubkey/signature evaluation
                        // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                        // See the script_(in)valid tests for details.
                        if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
                            // serror is set
                            return false;
                        }

                        // Check signature
                        bool fOk = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion);

                        if (fOk) {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;

                        // If there are more signatures left than keys left,
                        // then too many signatures have failed. Exit early,
                        // without checking any further signatures.
                        if (nSigsCount > nKeysCount)
                            fSuccess = false;
                    }

                    // Clean up stack of actual arguments
                    while (i-- > 1) {
                        // If the operation failed, we require that all signatures must be empty vector
                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && !ikey2 && stacktop(-1).size())
                            return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                        if (ikey2 > 0)
                            ikey2--;
                        popstack(stack);
                    }

                    // A bug causes CHECKMULTISIG to consume one extra argument
                    // whose contents were not checked in any way.
                    //
                    // Unfortunately this is a potential source of mutability,
                    // so optionally verify it is exactly equal to zero prior
                    // to removing it from the stack.
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if ((flags & SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size())
                        return set_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
                    popstack(stack);

                    stack.push_back(fSuccess ? vchTrue : vchFalse);

                    if (opcode == OP_CHECKMULTISIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                    }
                }
                break;

                case OP_CHECKREWARD:
                {
                    std::vector<plc::Certificate> certs;
                    plc::CertParameters params;

                    if (!loadPlcCerts(stack, pbegincodehash, pend, flags,
                                      checker, sigversion,
                                      certs, params, serror))
                    {
                        // error is already set
                        return false;
                    }

                    bool fSuccess = checker.CheckReward(certs, params, serror);
                    if (!fSuccess && (flags & SCRIPT_VERIFY_REWARD))
                    {
                        // error is already set
                        return false;
                    }

                    // rm values from stack
                    stack.clear();
                    stack.push_back(vchTrue);
                }
                break;

                case OP_CHECKSUPER:
                {
                    std::vector<plc::Certificate> certs;
                    plc::CertParameters params;

                    if (!loadPlcCerts(stack, pbegincodehash, pend, flags,
                                      checker, sigversion,
                                      certs, params, serror))
                    {
                        // error is already set
                        return false;
                    }

                    // cert is ok, check flags
                    if (!checker.CheckSuper(params.flags))
                    {
                        if (flags & SCRIPT_VERIFY_REWARD)
                        {
                            LogPrintf("Incorrect certificate (super transactions not allowed) <%s>\n", __func__);
                            return set_error(serror, SCRIPT_ERR_BAD_CERTIFICATE);
                        }

                        // error is already set
                        return false;
                    }

                    stack.clear();
                    stack.push_back(vchTrue);
                }
                break;

                case OP_CHECKDESTINATIONVERIFY:
                {
                    if (stack.size() < 2)
                    {
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    if (stacktop(-2).size() > sizeof(CAmount) ||
                        stacktop(-1).size() != sizeof(uint160))

                    {
                        break;
                    }

                    uint160 id = uint160(stacktop(-1));
                    CAmount amount = CScriptNum(stacktop(-2), true).get<CAmount>();

                    if (!checker.CheckRequiredOutputs(id, amount))
                    {
                        return set_error(serror, SCRIPT_ERR_MISSING_REQUIRED_OUTPUT);
                    }

                    popstack(stack);
                    popstack(stack);
                }
                break;

                default:
                {
                    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                }
            }

            // Size limits
            if (stack.size() + altstack.size() > MAX_STACK_SIZE)
                return set_error(serror, SCRIPT_ERR_STACK_SIZE);
        }
    }
    catch (...)
    {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    if (!vfExec.empty())
        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

    return set_success(serror);
}

namespace {

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class CTransactionSignatureSerializer {
private:
    const CTransaction& txTo;  //!< reference to the spending transaction (the one being serialized)
    const CScript& scriptCode; //!< output script being consumed
    const unsigned int nIn;    //!< input index of txTo being signed
    const bool fAnyoneCanPay;  //!< whether the hashtype has the SIGHASH_ANYONECANPAY flag set
    const bool fHashSingle;    //!< whether the hashtype is SIGHASH_SINGLE
    const bool fHashNone;      //!< whether the hashtype is SIGHASH_NONE

public:
    CTransactionSignatureSerializer(const CTransaction &txToIn, const CScript &scriptCodeIn, unsigned int nInIn, int nHashTypeIn) :
        txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
        fAnyoneCanPay(!!(nHashTypeIn & SIGHASH_ANYONECANPAY)),
        fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
        fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template<typename S>
    void SerializeScriptCode(S &s) const {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR)
                nCodeSeparators++;
        }
        ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR) {
                s.write((char*)&itBegin[0], it-itBegin-1);
                itBegin = it;
            }
        }
        if (itBegin != scriptCode.end())
            s.write((char*)&itBegin[0], it-itBegin);
    }

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeInput(S &s, unsigned int nInput) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay)
            nInput = nIn;
        // Serialize the prevout
        ::Serialize(s, txTo.vin[nInput].prevout);
        // Serialize the script
        if (nInput != nIn)
            // Blank out other inputs' signatures
            ::Serialize(s, CScript());
        else
            SerializeScriptCode(s);
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone))
            // let the others update at will
            ::Serialize(s, (int)0);
        else
            ::Serialize(s, txTo.vin[nInput].nSequence);
    }

    /** Serialize an output of txTo */
    template<typename S>
    void SerializeOutput(S &s, unsigned int nOutput) const {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut());
        else
            ::Serialize(s, txTo.vout[nOutput]);
    }

    /** Serialize txTo */
    template<typename S>
    void Serialize(S &s) const {
        // Serialize nVersion
        ::Serialize(s, txTo.nVersion);
        // Serialize vin
        unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++)
             SerializeInput(s, nInput);
        // Serialize vout
        unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.vout.size());
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
             SerializeOutput(s, nOutput);
        // Serialize nLockTime
        ::Serialize(s, txTo.nLockTime);
    }
};

uint256 GetPrevoutHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto& txin : txTo.vin) {
        ss << txin.prevout;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto& txin : txTo.vin) {
        ss << txin.nSequence;
    }
    return ss.GetHash();
}

uint256 GetOutputsHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto& txout : txTo.vout) {
        ss << txout;
    }
    return ss.GetHash();
}

} // namespace

PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction& txTo)
{
    hashPrevouts = GetPrevoutHash(txTo);
    hashSequence = GetSequenceHash(txTo);
    hashOutputs = GetOutputsHash(txTo);
}

uint256 SignatureHash(const CScript& scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache)
{
    if (sigversion == SIGVERSION_WITNESS_V0) {
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;

        if (!(nHashType & SIGHASH_ANYONECANPAY)) {
            hashPrevouts = cache ? cache->hashPrevouts : GetPrevoutHash(txTo);
        }

        if (!(nHashType & SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashSequence = cache ? cache->hashSequence : GetSequenceHash(txTo);
        }


        if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashOutputs = cache ? cache->hashOutputs : GetOutputsHash(txTo);
        } else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.vout.size()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }

        CHashWriter ss(SER_GETHASH, 0);
        // Version
        ss << txTo.nVersion;
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        ss << hashSequence;
        // The input being signed (replacing the scriptSig with scriptCode + amount)
        // The prevout may already be contained in hashPrevout, and the nSequence
        // may already be contain in hashSequence.
        ss << txTo.vin[nIn].prevout;
        ss << scriptCode;
        ss << amount;
        ss << txTo.vin[nIn].nSequence;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;
        // Locktime
        ss << txTo.nLockTime;
        // Sighash type
        ss << nHashType;

        return ss.GetHash();
    }

    static const uint256 one(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
    if (nIn >= txTo.vin.size()) {
        //  nIn out of range
        return one;
    }

    // Check for invalid use of SIGHASH_SINGLE
    if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
        if (nIn >= txTo.vout.size()) {
            //  nOut out of range
            return one;
        }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    return ss.GetHash();
}

bool TransactionSignatureChecker::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    return pubkey.Verify(sighash, vchSig);
}

bool TransactionSignatureChecker::CheckSig(const std::vector<unsigned char>& vchSigIn, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
{
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    // Hash type is one byte tacked on to the end of the signature
    std::vector<unsigned char> vchSig(vchSigIn);
    if (vchSig.empty())
        return false;
    int nHashType = vchSig.back();
    vchSig.pop_back();

    uint256 sighash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion, this->txdata);

    if (!VerifySignature(vchSig, pubkey, sighash))
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckLockTime(const CScriptNum& nLockTime) const
{
    // There are two kinds of nLockTime: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nLockTime < LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (!(
        (txTo->nLockTime <  LOCKTIME_THRESHOLD && nLockTime <  LOCKTIME_THRESHOLD) ||
        (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)
    ))
        return false;

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime > (int64_t)txTo->nLockTime)
        return false;

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence)
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckSequence(const CScriptNum& nSequence) const
{
    // Relative lock times are supported by comparing the passed
    // in operand to the sequence number of the input.
    const int64_t txToSequence = (int64_t)txTo->vin[nIn].nSequence;

    // Fail if the transaction's version number is not set high
    // enough to trigger BIP 68 rules.
    if (static_cast<uint32_t>(txTo->nVersion) < 2)
        return false;

    // Sequence numbers with their most significant bit set are not
    // consensus constrained. Testing that the transaction's sequence
    // number do not have this bit set prevents using this property
    // to get around a CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        return false;

    // Mask off any bits that do not have consensus-enforced meaning
    // before doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;

    // There are two kinds of nSequence: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nSequenceMasked being tested is the same as
    // the nSequenceMasked in the transaction.
    if (!(
        (txToSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
        (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
    )) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nSequenceMasked > txToSequenceMasked)
        return false;

    return true;
}

uint32_t getCoinWeight(const Coin & coin,
                const plc::CertParameters & params)
{
    CBlockIndex * pindex = chainActive[coin.nHeight];

    const uint32_t now   = chainActive.Tip()->nTime;

    uint32_t coinAge     = (now - pindex->nTime) / 60;
    uint32_t ageOfCert   = (now - params.blockTimestamp) / 60;

    uint32_t coinWeight1 = coinAge < 20*24*60 ? 0 :
                        coinAge < 30*24*60 ? coinAge : 30*24*60;
    uint32_t coinWeight2 = coinAge <    23*60 ? 0 :
                        coinAge < 30*24*60 ? coinAge : 30*24*60;

    uint32_t coinWeight = params.flags & plc::fastMinting ?
                       coinWeight2 : std::min(coinWeight1, ageOfCert);

    LogPrint(BCLog::MINTING, "height %d tip %d coin %d delta %d coinWeight %d\n", chainActive.Tip()->nHeight, now, pindex->nTime, coinAge, coinWeight);

    return coinWeight;
}

//******************************************************************************
//******************************************************************************
void extractUserDestinations(const CScript   & userScriptSig,
                             CTxDestinations & dests)
{
    CScript::Ops ops;
    userScriptSig.parse(ops);

    // for (CScript::Op & op : std::reverse(ops))
    for (auto i = ops.rbegin(); i != ops.rend(); ++i)
    {
        if (CheckPubKeyEncoding(i->second, SCRIPT_VERIFY_STRICTENC, SIGVERSION_BASE, nullptr))
        {
            CPubKey pub(i->second);
            dests.emplace_back(CTxDestination(pub.GetID()));
        }
    }

    if (!dests.empty())
    {
        return;
    }

    // id dests is empty, try multisig
    CScript::Ops mops;
    CScript(ops.back().second.begin(), ops.back().second.end()).parse(mops);
    if (mops.back().first != OP_CHECKMULTISIG)
    {
        // mot multisig
        return;
    }

    for (size_t i = 1; i < mops.size()-2; ++i)
    {
        if (CheckPubKeyEncoding(mops[i].second, SCRIPT_VERIFY_STRICTENC, SIGVERSION_BASE, nullptr))
        {
            CPubKey pub(mops[i].second);
            dests.emplace_back(CTxDestination(pub.GetID()));
        }
    }
}

//******************************************************************************
//******************************************************************************
size_t compareDestinations(const CTxDestinations & l, const CTxDestinations & r)
{
    const CTxDestinations & ll = (l.size() > r.size()) ? l : r;
    const CTxDestinations & rr = (ll == l) ? r : l;
    size_t issame = 0;
    for (const auto & lll : ll)
    {
        for (const auto & rrr : rr)
        {
            if (lll == rrr)
            {
                ++issame;
                break;
            }
        }
    }
    return issame;
};

//******************************************************************************
//******************************************************************************
bool compareDestinations(const txnouttype      & sourceAddressType,
                         const CTxDestinations & sourceDests,
                         const int               sourceRequired,
                         const txnouttype      & userAddressType,
                         const CTxDestinations & userDests,
                         const int               userRequired)
{
    bool isDestsEqualWithUser = false;

    if (userAddressType == sourceAddressType)
    {
        // simple rule if address types is eq
        isDestsEqualWithUser = (userRequired == sourceRequired) &&
                               (userDests.size() == sourceDests.size()) &&
                               compareDestinations(userDests, sourceDests) == userDests.size();
    }

    return isDestsEqualWithUser;
}

//******************************************************************************
//******************************************************************************
bool TransactionSignatureChecker::CheckReward(const std::vector<plc::Certificate> & certs,
                                              const plc::CertParameters & params,
                                              ScriptError * serror) const
{
    if (!m_rewardAlreadyChecked)
    {
        m_rewardCheckResult    = CheckRewardInternal(certs, params, serror);
        m_rewardAlreadyChecked = true;
    }
    return m_rewardCheckResult;
}

//******************************************************************************
//******************************************************************************
bool TransactionSignatureChecker::CheckRewardInternal(const std::vector<plc::Certificate> & certs,
                                                      const plc::CertParameters & params,
                                                      ScriptError * serror) const
{
    static const uint32_t oneYear = 60*60*24*365;

    uint32_t now   = chainActive.Tip()->nTime;

    // time drift 23 hours (82800 seconds)
    if (params.expirationDate != std::numeric_limits<unsigned int>::max() &&
            (params.expirationDate > (0xffffffff-0x14370) || now > (params.expirationDate+0x14370)))
    {
        // expired
        const plc::Certificate & cert = certs.back();
        LogPrintf("%s: Cert expired <%s:%d>, expirationDate: %u, now: %u\n", __func__, cert.txid.ToString(), cert.vout, params.expirationDate, now);
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_CERT_EXPIRED);
    }

    CMutableTransaction fakeUserTx;

    const double percent        = static_cast<double>(params.percent * 10) / COIN;

    CAmount inputAmount         = 0;
    CAmount inputMoneyBoxAmount = 0;
    CAmount neededReward        = 0;

    CScript         userScriptPubKey;
    CScript         userScriptSig;
    CTxDestinations userScriptSigDestinations;

    txnouttype      userAddressType = TX_NONSTANDARD;
    CTxDestinations userDests;
    int             userRequired = 0;

    CCoinsViewCache dummy(pcoinsTip);
    const CCoinsViewCache * cache = (view == nullptr) ? &dummy : view;

    const bool isFreeBen    = params.flags & plc::freeBen;
    const bool isSilverHoof = params.flags & plc::silverHoof;

    // inputs
    for(uint32_t i = 0; i < txTo->vin.size(); ++i)
    {
        const CTxIn & vin = txTo->vin[i];
        const COutPoint prev(vin.prevout);

        const Coin & coin = cache->AccessCoin(prev);

        if (coin.IsSpent())
        {
            // txout not found or spent
            LogPrintf("%s: txout is spent <%s>\n", __func__, prev.hash.ToString());
            return set_error(serror, SCRIPT_ERR_BAD_REWARD_SPENT);
        }

        const CTxOut & vout = coin.out;

        // money box?
        if (vout.scriptPubKey == Params().moneyBoxAddress())
        {
            // yes
            inputMoneyBoxAmount += vout.nValue;
            continue;
        }

        if (userScriptPubKey.empty())
        {
            userScriptPubKey = vout.scriptPubKey;
            userScriptSig    = vin.scriptSig;

            extractUserDestinations(userScriptSig, userScriptSigDestinations);

            if (!ExtractDestinations(userScriptPubKey, userAddressType, userDests, userRequired))
            {
                LogPrintf("%s: bad user address <%s>\n", __func__, HexStr(userScriptPubKey));
                return set_error(serror, SCRIPT_ERR_BAD_REWARD_ADDRESS);
            }
        }
        else
        {
            if (prev.isMarker(supertransaction))
            {
                continue;
            }

            txnouttype      tmpUserAddressType = TX_NONSTANDARD;
            CTxDestinations tmpUserDests;
            int             tmpUserRequired = 0;

            if (!ExtractDestinations(vout.scriptPubKey, tmpUserAddressType, tmpUserDests, tmpUserRequired))
            {
                LogPrintf("%s: bad user address/scriptpubkey <%s>\n", __func__, HexStr(vout.scriptPubKey));
                return set_error(serror, SCRIPT_ERR_BAD_REWARD_ADDRESS);
            }

            bool isDestEq = compareDestinations(tmpUserAddressType, tmpUserDests, tmpUserRequired,
                                                userAddressType, userDests, userRequired);

            // special for ab minting
            // this is the same person from Notre Dame de Paris
            // i'm sorry
            if (!isDestEq && userScriptSigDestinations.size() != 0)
            {
                isDestEq = compareDestinations(tmpUserDests, userScriptSigDestinations) >= std::min(userScriptSigDestinations.size(), tmpUserDests.size());
            }

            if (!isDestEq)
            {
                LogPrintf("%s: user address mismatch <%s>\n", __func__, txTo->GetHash().ToString());
                return set_error(serror, SCRIPT_ERR_BAD_REWARD_ADDR_MISMATCH);
            }
        }

        fakeUserTx.vin.emplace_back(txTo->vin[i]);

        inputAmount += vout.nValue;

        // not from money box, user funds
        // check coin age (get weight)
        // for silverHoof coinWeight always == 1
        if (isSilverHoof)
        {
            // must be defined later
            continue;
        }

        uint32_t coinWeight = getCoinWeight(coin, params);
        if (coinWeight == 0)
        {
            LogPrintf("%s: txout is spent or not matured <%s>\n", __func__, prev.hash.ToString());
            return set_error(serror, SCRIPT_ERR_VAD_REWARD_NOT_MATURED);
        }

        neededReward += (vout.nValue * coinWeight * percent) / (365 * 24 * 60);

    } // inputs

    CAmount outputAmount              = 0;
    CAmount outputMoneyBoxAmount      = 0;
    CAmount beneficiaryAmount         = 0;
    CAmount knownBeneficiaryAmount    = 0;
    uint32_t countOfUserOutputs       = 0;
    uint32_t countOfUserLockedOutputs = 0;
    uint32_t countOfBenOutputs        = 0;

    CAmount   maxLockedAmount         = 0;
    uint32_t  maxLockTime             = 0;

    enum OutType
    {
        unknown = 0,
        zeroAmount,
        moneybox,
        user,
        userLocked,
        ben,
        grave
    };

    std::vector<OutType>  outTypes(txTo->vout.size(), unknown);
    std::vector<uint32_t> locks(txTo->vout.size(), 0);

    // outputs
    for (uint32_t i = 0; i < txTo->vout.size(); ++i)
    {
        const CTxOut & vout = txTo->vout[i];

        if (vout.nValue == 0)
        {
            outTypes[i] = zeroAmount;
            continue;
        }

        if (vout.scriptPubKey == Params().moneyBoxAddress())
        {
            outTypes[i] = moneybox;
            continue;
        }

        if (Params().isGrave(vout.scriptPubKey))
        {
            outTypes[i] = grave;
            continue;
        }

        txnouttype      tmpUserAddressType = TX_NONSTANDARD;
        CTxDestinations tmpUserDests;
        int             tmpUserRequired    = 0;
        uint32_t        tmpLockTime        = 0;

        if (!ExtractDestinations(vout.scriptPubKey, tmpUserAddressType, tmpUserDests, tmpUserRequired, tmpLockTime))
        {
            LogPrintf("%s: bad user address/scriptpubkey <%s>\n", __func__, HexStr(vout.scriptPubKey));

            // it's ben, not error
            outTypes[i] = ben;
            // return set_error(serror, SCRIPT_ERR_BAD_REWARD_ADDRESS);
        }
        else
        {
            bool isDestEq = compareDestinations(tmpUserAddressType, tmpUserDests, tmpUserRequired,
                                                userAddressType, userDests, userRequired);

            // special for ab minting
            // this is the same person from Notre Dame de Paris
            // i'm sorry
            if (!isDestEq && userScriptSigDestinations.size() != 0)
            {
                isDestEq = compareDestinations(tmpUserDests, userScriptSigDestinations) >= std::min(userScriptSigDestinations.size(), tmpUserDests.size());
            }

            outTypes[i] = isDestEq
                          ? (tmpLockTime > 0 ? userLocked : user)
                          : ben;
            locks[i]    = tmpLockTime;
        }
    }

    // outputs
    for (uint32_t i = 0; i < txTo->vout.size(); ++i)
    {
        const CTxOut & vout = txTo->vout[i];

        if (outTypes[i] == zeroAmount)
        {
            // data output, skip
            continue;
        }

        else if (outTypes[i] == moneybox)
        {
            // returned to money box
            if (outputMoneyBoxAmount > 0)
            {
                LogPrintf("Too many moneybox outputs (outputMoneyBoxAmount: %d)\n", outputMoneyBoxAmount);
                return set_error(serror, SCRIPT_ERR_BAD_REWARD_MANY_MONEYBOX_OUTS);
            }
            outputMoneyBoxAmount += vout.nValue;
        }

        else if (outTypes[i] == user)
        {
            // user funds or reward to user address
            ++countOfUserOutputs;
            fakeUserTx.vout.emplace_back(vout);
            outputAmount += vout.nValue;
            continue;
        }

        else if (outTypes[i] == userLocked)
        {
            ++countOfUserOutputs;
            ++countOfUserLockedOutputs;
            fakeUserTx.vout.emplace_back(vout);
            outputAmount    += vout.nValue;

            if (maxLockedAmount < vout.nValue)
            {
                maxLockedAmount = vout.nValue;
                maxLockTime     = locks[i];
            }
            continue;
        }

        else
        {
            // reward to ben's

            ++countOfBenOutputs;
            fakeUserTx.vout.emplace_back(vout);

            if (isFreeBen)
            {
                // always known beneficiary
                knownBeneficiaryAmount += vout.nValue;
                continue;
            }

            // check address
            CTxDestination dest;
            if (!ExtractDestination(vout.scriptPubKey, dest))
            {
                // unknown destination
                beneficiaryAmount += vout.nValue;
                continue;
            }
            CKeyID id;
            if (!CBitcoinAddress(dest).GetKeyID(id))
            {
                // unknown destination
                beneficiaryAmount += vout.nValue;
                continue;
            }
            if (params.beneficiaryKeyHash != id)
            {
                // unknown destination
                beneficiaryAmount += vout.nValue;
                continue;
            }
            // wow, known beneficiary
            knownBeneficiaryAmount += vout.nValue;
        }

    } // outputs

    // more outputs
    if (isSilverHoof && countOfUserOutputs == 0)
    {
        // user outputs not found
        // find out with max locktime and use it
        uint32_t maxLockedIdx = std::numeric_limits<uint32_t>::max();
        for (uint32_t i = 0; i < txTo->vout.size(); ++i)
        {
            if (maxLockTime < locks[i])
            {
                maxLockedIdx = i;
                maxLockTime  = locks[i];
            }
        }

        if (maxLockedIdx == std::numeric_limits<uint32_t>::max())
        {
            LogPrintf("No locked outputs\n");
            return set_error(serror, SCRIPT_ERR_BAD_REWARD_NO_USER_VOUTS);
        }

        const CTxOut & vout = txTo->vout[maxLockedIdx];
        maxLockedAmount = vout.nValue;
        outputAmount    = vout.nValue;
        ++countOfUserOutputs;
        ++countOfUserLockedOutputs;

        if (beneficiaryAmount < vout.nValue)
        {
            LogPrintf("Small ben\n");
            return set_error(serror, SCRIPT_ERR_BAD_REWARD_NO_USER_VOUTS);
        }

        beneficiaryAmount -= vout.nValue;
    }

    // user locked only if silver hoof is set
    if (!isSilverHoof)
    {
        countOfUserLockedOutputs = 0;
    }
    else
    {
        // silver hoof rules
        if (maxLockTime <= now)
        {
            return set_error(serror, SCRIPT_ERR_INVALID_LOCKTIME);
        }

        CAmount hoofAmount = beneficiaryAmount + knownBeneficiaryAmount + outputAmount - inputAmount;

        double duration = static_cast<double>(maxLockTime - now) / oneYear;

        if (maxLockedAmount * percent * duration < hoofAmount)
        {
            LogPrintf("%s: Everybody be cool, silver hoof was broken!!! <%s> (locked: %d, percent: %f, duration: %f, ben amount %d)\n",
                   __func__, txTo->GetHash().ToString(), maxLockedAmount, percent, duration, hoofAmount);
            return set_error(serror, SCRIPT_ERR_BAD_REWARD_ROBBERY);
        }

        LogPrint(BCLog::MINTING,
                 "%s: silver hooves knocking on a money box, %d yo-ho-ho and the bottle of rum!\n",
                 __func__, hoofAmount);
        LogPrint(BCLog::MINTING,
                 "%s: %s\n",
                 __func__, txTo->GetHash().ToString());
        return true;
    }

    // classic rules

    // check user and ben outputs (with rest for silver hoof)
    // +2 when silverhoof = change + reward if silverhoof used in funding
    if (countOfUserOutputs - countOfUserLockedOutputs > fakeUserTx.vin.size())
    {
        LogPrintf("%s: Too many user outputs <%s> (countOfUserOutputs: %u, vin.size: %u)\n", __func__, txTo->GetHash().ToString(), countOfUserOutputs, fakeUserTx.vin.size());
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_MANY_USER_OUTS);
    }
    if (!isFreeBen && (countOfBenOutputs > fakeUserTx.vin.size()))
    {
        LogPrintf("%s: Too many beneficiary outputs <%s> (countOfBenOutputs: %u, vin.size: %u)\n", __func__, txTo->GetHash().ToString(), countOfBenOutputs, fakeUserTx.vin.size());
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_MANY_BEN_OUTS);
    }

    CScript::Ops ops;
    userScriptSig.parse(ops);

    txnouttype type;
    std::vector<CTxDestination> addrs;
    int required = 0;
    if (!ExtractDestinations(userScriptPubKey, type, addrs, required))
    {
        LogPrintf("%s: bad scriptPubKey <%s>\n", __func__, txTo->GetHash().ToString());
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_USER_ADDRESS);
    }

    if (type == TX_PUBKEYHASH)
    {
        // check user pub key
        // scriptsig --> <signature><pubkey>
        CPubKey pub(ops.back().second);
        if (params.pubkeyHashes.size() != 1 || pub.GetID() != params.pubkeyHashes[0])
        {
            LogPrintf("%s: mismatch user pubKey <%s>\n", __func__, txTo->GetHash().ToString());
            return set_error(serror, SCRIPT_ERR_BAD_REWARD_USER_ADDRESS);
        }
    }
    else if (type == TX_SCRIPTHASH)
    {
        // multisig?
        CScript::Ops mops;
        CScript(ops.back().second.begin(), ops.back().second.end()).parse(mops);
        if (mops.back().first != OP_CHECKMULTISIG)
        {
            LogPrintf("%s: not multisig p2sh <%s>\n", __func__, txTo->GetHash().ToString());
            return set_error(serror, SCRIPT_ERR_BAD_SCRIPT);
        }

        if (CScript::DecodeOP_N(mops.front().first) != static_cast<int>(params.requiredCountOfSigs) ||
                mops.size()-3 != params.pubkeyHashes.size())
        {
            LogPrintf("%s: multisig with bad count of keys/signatures <%s>\n", __func__, txTo->GetHash().ToString());
            return set_error(serror, SCRIPT_ERR_BAD_SCRIPT);
        }

        for (size_t i = 0; i < mops.size()-3; ++i)
        {
            const CKeyID id = CPubKey(mops[i+1].second).GetID();
            if (id != params.pubkeyHashes[i])
            {
                LogPrintf("%s: multisig error <%s>\n", __func__, txTo->GetHash().ToString());
                return set_error(serror, SCRIPT_ERR_BAD_SCRIPT);
            }
        }
    }
    else
    {
        LogPrintf("%s: bad destination <%s>\n", __func__, txTo->GetHash().ToString());
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_USER_ADDRESS);
    }

    // tx fee
    CAmount fee = (inputAmount + inputMoneyBoxAmount) -
                   (outputAmount + outputMoneyBoxAmount +
                        beneficiaryAmount + knownBeneficiaryAmount);

    if (fee > Params().minGranularity())
    {
        LogPrintf("%s: big fee <%s>\n", __func__, txTo->GetHash().ToString());
        return set_error(serror, SCRIPT_ERR_BIG_FEE);
    }

    // fake tx fee (for unknown beneficiary)
    CAmount fakeUserFee = 0;
    if ((params.flags & plc::freeBen) == 0 && beneficiaryAmount != 0)
    {
        fakeUserFee = fee * GetTransactionWeight(fakeUserTx) / GetTransactionWeight(*txTo);
    }

    // check count of money box inputs
    if (inputMoneyBoxAmount > (neededReward + (fee-fakeUserFee) + Params().awardGranularity(chainActive.Height())))
    {
        LogPrintf("%s: Too many moneybox inputs <%s> (inputMoneyBoxAmount: %d, neededReward: %d, fee: %d, fakeUserFee: %d, height: %d, awardGranularity: %d)\n",
                  __func__, txTo->GetHash().ToString(), inputMoneyBoxAmount, neededReward, fee, fakeUserFee, chainActive.Height(), Params().awardGranularity(chainActive.Height()));
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_MANY_MONEYBOX);
    }

    if (fakeUserTx.vin.size() == 0)
    {
        LogPrintf("%s: No user vin's <%s>\n", __func__, txTo->GetHash().ToString());
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_NO_USER_VINS);
    }

    // check common amount
    if (outputAmount + beneficiaryAmount + knownBeneficiaryAmount > inputAmount + neededReward)
    {
        // hey, man, it's a robbery
        LogPrintf("%s: WOW, robbery!!! %d vs %d (inputAmount: %d, neededReward: %d, outputAmount: %d, beneficiaryAmount: %d, knownBeneficiaryAmount: %d)\n",
                  __func__,
                  (inputAmount + neededReward),
                  (outputAmount + beneficiaryAmount + knownBeneficiaryAmount),
                  inputAmount, neededReward, outputAmount, beneficiaryAmount, knownBeneficiaryAmount);
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_ROBBERY);
    }

    if (inputAmount > outputAmount)
    {
        LogPrintf("%s: wrong output amount, less than input (inputAmount: %d, outputAmount: %d)\n", __func__, inputAmount, outputAmount);
        return false;
    }

    // with beneficiary
    if (knownBeneficiaryAmount > 0 || beneficiaryAmount > 0)
    {
        // check unknown beneficiary
        if (beneficiaryAmount > 0)
        {
            if (neededReward <= fakeUserFee)
            {
                LogPrintf("%s: Reward less than fee (neededReward: %d, fakeUserFee: %d, beneficiaryAmount: %d, knownBeneficiaryAmount: %d)\n",
                          __func__, neededReward, fakeUserFee, beneficiaryAmount, knownBeneficiaryAmount);
                return set_error(serror, SCRIPT_ERR_BAD_REWARD_LESS_THAN_FEE);
            }
            if (beneficiaryAmount > neededReward-fakeUserFee)
            {
                LogPrintf("%s: Beneficiary amount to high (beneficiaryAmount: %d, neededReward: %d, fakeUserFee: %d, knownBeneficiaryAmount: %d)\n",
                          __func__, beneficiaryAmount, neededReward, fakeUserFee, knownBeneficiaryAmount);
                return set_error(serror, SCRIPT_ERR_BAD_REWARD_BIG_BEN);
            }
        }
    }

    CAmount existingReward = outputAmount + beneficiaryAmount + knownBeneficiaryAmount - inputAmount;

    // check minting limits
    if (params.mintingLimit < params.limits.mintingCurrent + existingReward)
    {
        LogPrintf("%s: minting limit is exceeded <%s:%d> (allowed %d vs %d) (mintingLimit: %d, mintingCurrent: %d)\n",
                  __func__, certs.back().txid.ToString(), certs.back().vout,
                  params.mintingLimit - params.limits.mintingCurrent, existingReward, params.mintingLimit, params.limits.mintingCurrent);
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_LIMIT);
    }

    bool insideOneDay = params.limits.dailyTimestamp >= (now - oneDay);
    if ((insideOneDay && (params.maxLoad < params.limits.maxLoadCurrent + inputAmount)) ||
        (!insideOneDay && (params.maxLoad < inputAmount)))
    {
        // check daily limits
        LogPrintf("%s: maxLoad <%s:%d> (allowed %d vs %d) (insideOneDay: %d, maxLoad: %d, maxLoadCurrent: %d)\n",
                  __func__, certs.back().txid.ToString(), certs.back().vout,
                  insideOneDay ? params.maxLoad - params.limits.maxLoadCurrent : params.maxLoad,
                  inputAmount, insideOneDay, params.maxLoad, params.limits.maxLoadCurrent);
        return set_error(serror, SCRIPT_ERR_BAD_REWARD_DAILY);
    }

    return true;
}

bool TransactionSignatureChecker::CheckRequiredOutputs(const uint160 & id,
                                                       const CAmount & amount) const
{
    if (m_inOutRequired.count(nIn))
    {
        return true;
    }

    // outputs
    for (uint32_t i = 0; i < txTo->vout.size(); ++i)
    {
        const CTxOut & vout = txTo->vout[i];

        CTxDestination dest;
        if (!ExtractDestination(vout.scriptPubKey, dest))
        {
            return false;
        }

        if (dest == CTxDestination(CKeyID(id)) || dest == CTxDestination(CScriptID(id)))
        {
            if (vout.nValue == amount)
            {
                if (std::find_if(m_inOutRequired.begin(), m_inOutRequired.end(),
                                 [i](const std::pair<uint32_t, uint32_t> & val){ return i == val.second; })
                        == m_inOutRequired.end())
                {
                    m_inOutRequired[nIn] = i;
                    return true;
                }
            }
        }
    }

    return false;
}

bool TransactionSignatureChecker::CheckSuper(const uint32_t flags) const
{
    if (txTo->vin.at(nIn).prevout.n == static_cast<uint32_t>(-1))
    {
        if ((flags & plc::holyShovel) != 0)
        {
            return true;
        }
    }
    else if (txTo->vin.at(nIn).prevout.n == 0)
    {
        if ((flags & plc::shadowEmperor) != 0)
        {
            return true;
        }
    }

    return false;
}

static bool VerifyWitnessProgram(const CScriptWitness& witness, int witversion, const std::vector<unsigned char>& program, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    std::vector<std::vector<unsigned char> > stack;
    CScript scriptPubKey;

    if (witversion == 0) {
        if (program.size() == 32) {
            // Version 0 segregated witness program: SHA256(CScript) inside the program, CScript + inputs in witness
            if (witness.stack.size() == 0) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
            }
            scriptPubKey = CScript(witness.stack.back().begin(), witness.stack.back().end());
            stack = std::vector<std::vector<unsigned char> >(witness.stack.begin(), witness.stack.end() - 1);
            uint256 hashScriptPubKey;
            CSHA256().Write(&scriptPubKey[0], scriptPubKey.size()).Finalize(hashScriptPubKey.begin());
            if (memcmp(hashScriptPubKey.begin(), &program[0], 32)) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
            }
        } else if (program.size() == 20) {
            // Special case for pay-to-pubkeyhash; signature + pubkey in witness
            if (witness.stack.size() != 2) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH); // 2 items in witness
            }
            scriptPubKey << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY << OP_CHECKSIG;
            stack = witness.stack;
        } else {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
        }
    } else if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
    } else {
        // Higher version witness scripts return true for future softfork compatibility
        return set_success(serror);
    }

    // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
    for (unsigned int i = 0; i < stack.size(); i++) {
        if (stack.at(i).size() > MAX_SCRIPT_ELEMENT_SIZE)
            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
    }

    if (!EvalScript(stack, scriptPubKey, flags, checker, SIGVERSION_WITNESS_V0, serror)) {
        return false;
    }

    // Scripts inside witness implicitly require cleanstack behaviour
    if (stack.size() != 1)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (!CastToBool(stack.back()))
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    return true;
}

bool VerifyScript(const CScript& scriptSig,
                  const CScript& scriptPubKey,
                  const CScriptWitness* witness,
                  unsigned int flags,
                  const BaseSignatureChecker& checker,
                  ScriptError* serror)
{
    static const CScriptWitness emptyWitness;
    if (witness == nullptr) {
        witness = &emptyWitness;
    }
    bool hadWitness = false;

    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly()) {
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    std::vector<std::vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, flags, checker, SIGVERSION_BASE, serror))
        // serror is set
        return false;
    if (flags & SCRIPT_VERIFY_P2SH)
        stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, flags, checker, SIGVERSION_BASE, serror))
        // serror is set
        return false;
    if (stack.empty())
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (CastToBool(stack.back()) == false)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

    // Bare witness programs
    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (flags & SCRIPT_VERIFY_WITNESS) {
        if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
            hadWitness = true;
            if (scriptSig.size() != 0) {
                // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
                return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED);
            }
            if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, serror)) {
                return false;
            }
            // Bypass the cleanstack check at the end. The actual stack is obviously not clean
            // for witness programs.
            stack.resize(1);
        }
    }

    // Additional validation for spend-to-script-hash transactions:
    if ((flags & SCRIPT_VERIFY_P2SH) && scriptPubKey.IsPayToScriptHash())
    {
        // scriptSig must be literals-only or validation fails
        if (!scriptSig.IsPushOnly())
            return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);

        // Restore stack.
        swap(stack, stackCopy);

        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        assert(!stack.empty());

        const valtype& pubKeySerialized = stack.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stack);

        if (!EvalScript(stack, pubKey2, flags, checker, SIGVERSION_BASE, serror))
            // serror is set
            return false;
        if (stack.empty())
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (!CastToBool(stack.back()))
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

        // P2SH witness program
        if (flags & SCRIPT_VERIFY_WITNESS) {
            if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram)) {
                hadWitness = true;
                if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end())) {
                    // The scriptSig must be _exactly_ a single push of the redeemScript. Otherwise we
                    // reintroduce malleability.
                    return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
                }
                if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, serror)) {
                    return false;
                }
                // Bypass the cleanstack check at the end. The actual stack is obviously not clean
                // for witness programs.
                stack.resize(1);
            }
        }
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain). The same holds for witness evaluation.
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        // Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
        // would be possible, which is not a softfork (and P2SH should be one).
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        assert((flags & SCRIPT_VERIFY_WITNESS) != 0);
        if (stack.size() != 1) {
            return set_error(serror, SCRIPT_ERR_CLEANSTACK);
        }
    }

    if (flags & SCRIPT_VERIFY_WITNESS) {
        // We can't check for correct unexpected witness data if P2SH was off, so require
        // that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
        // possible, which is not a softfork.
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (!hadWitness && !witness->IsNull()) {
            return set_error(serror, SCRIPT_ERR_WITNESS_UNEXPECTED);
        }
    }

    return set_success(serror);
}

size_t static WitnessSigOps(int witversion, const std::vector<unsigned char>& witprogram, const CScriptWitness& witness, int flags)
{
    if (witversion == 0) {
        if (witprogram.size() == 20)
            return 1;

        if (witprogram.size() == 32 && witness.stack.size() > 0) {
            CScript subscript(witness.stack.back().begin(), witness.stack.back().end());
            return subscript.GetSigOpCount(true);
        }
    }

    // Future flags may be implemented here.
    return 0;
}

size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags)
{
    static const CScriptWitness witnessEmpty;

    if ((flags & SCRIPT_VERIFY_WITNESS) == 0) {
        return 0;
    }
    assert((flags & SCRIPT_VERIFY_P2SH) != 0);

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
    }

    if (scriptPubKey.IsPayToScriptHash() && scriptSig.IsPushOnly()) {
        CScript::const_iterator pc = scriptSig.begin();
        std::vector<unsigned char> data;
        while (pc < scriptSig.end()) {
            opcodetype opcode;
            scriptSig.GetOp(pc, opcode, data);
        }
        CScript subscript(data.begin(), data.end());
        if (subscript.IsWitnessProgram(witnessversion, witnessprogram)) {
            return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
        }
    }

    return 0;
}
