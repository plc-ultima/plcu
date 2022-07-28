//******************************************************************************
//******************************************************************************

#ifndef PLCCERTIFICATE_H
#define PLCCERTIFICATE_H

#include "uint256.h"
#include "amount.h"
#include "serialize.h"

#include <stdint.h>
#include <vector>

//******************************************************************************
//******************************************************************************
namespace plc
{

enum
{
    privateKeySize  = 32,
    publicKeySize   = 33,
    signatureSize   = 64
};

//******************************************************************************
//******************************************************************************
struct Certificate
{
    uint256  txid;
    uint32_t vout;
    uint32_t height;

    Certificate()
        : vout(0)
        , height(0)
    {
    }

    Certificate(const uint256 & _txid, const uint32_t & _vout)
        : txid(_txid)
        , vout(_vout)
        , height(0)
    {
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(txid);
        READWRITE(vout);
    }
};

//******************************************************************************
//******************************************************************************
// misk flags
enum
{
    hasDeviceKey          = 0x00000001,
    hasBeneficiaryKey     = 0x00000002,
    hasExpirationDate     = 0x00000004,
    hasMintingLimit       = 0x00000008,
    hasMaxload            = 0x00000010,
    hasBeneficiaryPercent = 0x00000020,
    hasFreeBenPercent     = 0x00000040,
    hasOtherData          = 0x00000800,
    fastMinting           = 0x00010000,
    freeBen               = 0x00020000,
    silverHoof            = 0x00040000,
    shadowEmperor         = 0x00080000,
    holyShovel            = 0x00100000,
    masterOfTime          = 0x00200000,
    generalFlags          = 0x0fff0000,
    localFlags            = 0x00000fff,
    pubkeyCountMask       = 0x0000f000,
    requireCountMask      = 0xf0000000,
};

//******************************************************************************
//******************************************************************************
struct MintingLimits
{
    CAmount              mintingCurrent;
    unsigned int         mintingTimestamp;
    CAmount              maxLoadCurrent;
    unsigned int         dailyTimestamp;

    MintingLimits()
        : mintingCurrent(0)
        , mintingTimestamp(0)
        , maxLoadCurrent(0)
        , dailyTimestamp(0)
    {
    }
};

struct CertParameters
{
    int32_t              version;
    int64_t              percent;
    uint32_t             flags;
    std::vector<uint160> pubkeyHashes;
    uint32_t             requiredCountOfSigs;
    uint160              deviceKeyHash;
    uint160              beneficiaryKeyHash;
    unsigned int         height;
    unsigned int         blockTimestamp;
    unsigned int         expirationDate;
    CAmount              mintingLimit;
    CAmount              maxLoad;
    MintingLimits        limits;


    CertParameters()
        : version(0)
        , percent(0)
        , flags(0)
        , requiredCountOfSigs(0)
        , height(0)
        , blockTimestamp(0)
        , expirationDate(std::numeric_limits<unsigned int>::max())
        , mintingLimit(std::numeric_limits<CAmount>::max())
        , maxLoad(std::numeric_limits<CAmount>::max())
    {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(version);
        READWRITE(percent);
        READWRITE(flags);
        READWRITE(requiredCountOfSigs);
        READWRITE(height);
        READWRITE(blockTimestamp);
        READWRITE(expirationDate);
        READWRITE(mintingLimit);
        READWRITE(maxLoad);
    }
};

} // namespace plc

#endif // PLCCERTIFICATE_H
