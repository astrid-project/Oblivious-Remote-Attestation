#ifndef ORCHESTRATOR_H
#define ORCHESTRATOR_H

#include <csignal>
#include <thread>
#include <typeinfo>
#include <cxxabi.h>

#include "tpm.h"
#include "stdafx.h"

using namespace std;
using namespace web;
using namespace http;
using namespace utility;
using namespace web::http;
using namespace web::http::client;
using namespace concurrency::streams;

struct mPCR {
    unsigned char val[SHA256_DIGEST_SIZE];
    uint8_t       idx;
    bool          active = 0; // whether the PCR is currently used for attestation: inactive (0), active (1)
    };

struct mNVPCR {
    unsigned char    val[SHA256_DIGEST_SIZE];
    TPMI_RH_NV_INDEX idx;
    TPM2B_NAME       name;
    };

class Orchestrator {
    public:
        Orchestrator(TSS_CONTEXT* ctx, const bool verbose);
        bool deploy(utility::string_t url);
        bool update(utility::string_t url,
                    const UINT32   pcrIdx, 
                    const bool     nv, 
                    unsigned char* updateDigest, 
                    unsigned char* secretHmacKey, 
                    const int      keyLen);
        bool addPcr(utility::string_t url, 
                    const UINT32 pcrIdx, 
                    const bool   nv);
        bool delPcr(utility::string_t url, 
                    const UINT32 pcrIdx, 
                    const bool   nv);
        bool attest(utility::string_t url);

    private:
        TSS_CONTEXT* mCtx;

        vector<mPCR>   mPCRs;   // current state of normal PCRs appointed to the container
        vector<mNVPCR> mNVPCRs; // current state of NV PCRs appointed to the container
    	int mTrustState = 0;    // current trust state of the container: untrusted (0), trusted (1)

        bool verbose;

        const char* mSigningKeyPublicFilename   = "orchestratorSigningKeyPublic";
        const char* mSigningKeyPrivateFilename  = "orchestratorSigningKeyPrivate";
        const char* mVmSigningKeyPublicFilename = "vmSigningKeyPublic";

        TPM2B_PUBLIC mVmSigningKeyPublic; // public part of VM's signing key (endorsement key)
        TPM2B_PUBLIC mContainerAkPublic;  // public part of container's AK
        TPM2B_NAME   mSigningKeyName;     // name of Orchestrator's signing key (endorsement key)

        const TPMI_DH_PERSISTENT mPersistentSigningKeyHandle = 0x81001337;
        const TPMI_DH_PERSISTENT mPersistentStorageKeyHandle = 0x81001338;

        bool verifyAttestationKeyCreation(TPMT_SIGNATURE signature, 
                        TPM2B_ATTEST       certifyInfo,
                        const TPM2B_PUBLIC akPub, 
                        const TPM2B_PUBLIC signingKeyPub,
                        const TPM2B_DIGEST policyDigest,
                        const TPMA_OBJECT  objectAttributes);
        bool verifyNvPcrCreation(const TPMS_NV_PUBLIC expected,
                        TPMT_SIGNATURE     signature, 
                        TPM2B_ATTEST       certifyInfo,
                        const TPM2B_PUBLIC signingKeyPub,
                        const mNVPCR       mnvpcr,
                        TPM2B_NAME*        name);
        bool verifyAuditSessionExtend(TPMT_SIGNATURE signature, 
                        TPM2B_ATTEST       auditInfo,
                        const TPM2B_PUBLIC signingKeyPub,
                        const UINT32       pcrIdx,
                        const bool         nv,
                        unsigned char*     authenticUpdateDigest);
        TPM2B_NAME getNameFromPublic(const TPMT_PUBLIC* pubKey, const TPMS_NV_PUBLIC* pubNv);
};

#endif // ORCHESTRATOR_H
