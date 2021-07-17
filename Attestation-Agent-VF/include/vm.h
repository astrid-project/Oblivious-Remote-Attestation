#ifndef VM_H
#define VM_H

#include <typeinfo>
#include <cxxabi.h>

#include "tpm.h"
#include "stdafx.h"

using namespace std;
using namespace web;
using namespace http;
using namespace utility;
using namespace http::experimental::listener;

struct NVPCR {
    unsigned char    val[SHA256_DIGEST_SIZE];
    TPMI_RH_NV_INDEX idx;
    };

class VM {
    public:
        VM(TSS_CONTEXT* ctx, const bool verbose, unsigned char* secretHmacKey, const int keyLen);
        web::http::status_code createAttestationKey(const TPM2B_DIGEST* policyDigest, 
                    const TPMA_OBJECT objectAttributes,
                    json::value&      response);
        web::http::status_code addPcr(const UINT32 pcrIdx,
                    const bool                 nv,
                    const TPMA_NV*             attributes,
                    const TPM2B_DIGEST*        policyDigest,
                    const TPM2B_MAX_NV_BUFFER* iv,
                    json::value&               response);
        web::http::status_code initRemNvPcr(json::value& response);
        web::http::status_code remPcr(const UINT32 pcrIdx,
                    const bool            nv,
                    const TPM2B_DIGEST*   cpHashA,
                    const TPMT_SIGNATURE* aHashSignature,
                    const TPM2B_DIGEST*   policyDigest,
                    const TPM2B_DIGEST*   policyDigestSigned,
                    const TPMT_SIGNATURE* policyDigestSignature,
                    json::value&          response);
        web::http::status_code update(const TPM2B_DIGEST* policyDigest,
                    const TPM2B_DIGEST*   policyDigestSigned,
                    const TPMT_SIGNATURE* policyDigestSignature,
                    const UINT32          pcrIdx,
                    const bool            nv,
                    unsigned char*        tracerOutput,
                    json::value&          response);
        web::http::status_code attest(const TPM2B_DIGEST* nonceDigest, json::value& response);

        TPM2B_PUBLIC getSigningKeyPublic() const;
        TPM2B_PUBLIC getAttestationKeyPublic() const;

    private:
        TSS_CONTEXT* mCtx;

        bool verbose;

        unsigned char* secretHmacKey;
        const int keyLen;

        const char* mSigningKeyPublicFilename             = "vmSigningKeyPublic";
        const char* mSigningKeyPrivateFilename            = "vmSigningKeyPrivate";
        const char* mOrchestratorSigningKeyPublicFilename = "orchestratorSigningKeyPublic";

        TPM2B_PUBLIC mOrchestratorSigningKeyPublic;
        TPM2B_NAME   mOrchestratorSigningKeyName;

        const TPMI_DH_PERSISTENT mPersistentAttestationKeyHandle      = 0x81001336;
        const TPMI_DH_PERSISTENT mPersistentSigningKeyHandle          = 0x81001337;
        const TPMI_DH_PERSISTENT mPersistentStorageKeyHandle          = 0x81001338;

        std::vector<uint8_t> mPCRs;   // normal PCRs that are considered
        std::vector<NVPCR>   mNVPCRs; // NV PCRs that are considered

        StartAuthSession_Out mDelNvPcrAuthSession;

        TPMT_TK_VERIFIED mTicket;
        TPM2B_DIGEST     mApprovedPolicy;

        TPM2B_NAME getNameFromPublic(const TPMT_PUBLIC* publicKey, const TPMS_NV_PUBLIC* publicNv);
};

#endif // VM_H
