//******************************************************************************
//******************************************************************************

#ifndef PLCVALIDATOR_H
#define PLCVALIDATOR_H

#include "plccertificate.h"
#include "script/interpreter.h"
#include "uint256.h"
#include "amount.h"
#include "coins.h"

#include <vector>
#include <memory>

constexpr int oneDay = 24*60*60;

namespace plc
{

//******************************************************************************
//******************************************************************************
class Validator
{
    class Impl;

public:
    Validator();

public:
    // reqire cs_main!!!
    bool validateChainOfCerts(const std::vector<Certificate> & certs,
                              const std::vector<std::vector<unsigned char> > & pubkeys,
                              CertParameters & params) const;

    bool verifyCertSignatures(const std::vector<std::vector<unsigned char> > & signatures,
                              const std::vector<std::vector<unsigned char> > & pubkeys,
                              const CertParameters & params,
                              const CScript & scriptCode,
                              const BaseSignatureChecker & signatureChecker) const;

    // load valid (unspent) certivicate only
    bool loadCert(const Certificate & cert,
                  CertParameters    & params) const;

    // load all (spent or not), require txindex
    bool loadCertWithDb(const Certificate & cert,
                        CertParameters    & params) const;

private:
    std::shared_ptr<Impl> m_p;
};

} // namespace plc

#endif // PLCVALIDATOR_H
