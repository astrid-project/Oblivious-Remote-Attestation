#include <openssl/hmac.h>
#include "vm.h"
#include "timing.h"

VM::VM(TSS_CONTEXT* ctx, const bool verbose, unsigned char* secretHmacKey, const int keyLen) 
	: mCtx(ctx), verbose(verbose), secretHmacKey(secretHmacKey), keyLen(keyLen) {
	// VM has an restricted decryption key (storage key)
	CreatePrimary_Out storageKey;
	TPM_RC rc = createPrimaryKey(this->mCtx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

	// make the storage key persistent
	rc = evictControl(this->mCtx, TPM_RH_OWNER, storageKey.objectHandle, this->mPersistentStorageKeyHandle);
	flushContext(this->mCtx, storageKey.objectHandle);

	/* load VM's signing key */
	Create_Out signingKey;
	Load_Out   signingKeyLoaded;

	// read public part of signing key from file
	TPM_RC rcPub = TSS_File_ReadStructureFlag(&signingKey.outPublic,
									(UnmarshalFunctionFlag_t)TSS_TPM2B_PUBLIC_Unmarshalu,
									FALSE,
									this->mSigningKeyPublicFilename);
	// read private part of signing key from file
	TPM_RC rcPriv = TSS_File_ReadStructure(&signingKey.outPrivate,
									(UnmarshalFunction_t)TSS_TPM2B_PRIVATE_Unmarshalu,
									this->mSigningKeyPrivateFilename);
	if (rcPub == TSS_RC_FILE_OPEN || rcPriv == TSS_RC_FILE_OPEN) { // if files aren't available

		// create an restricted signing key (endorsement key)
		TPMA_OBJECT objectAttributes;
		objectAttributes.val = (TPMA_OBJECT_NODA | TPMA_OBJECT_SENSITIVEDATAORIGIN 
				| TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN)
				& ~TPMA_OBJECT_ADMINWITHPOLICY & ~TPMA_OBJECT_DECRYPT 
				& ~TPMA_OBJECT_RESTRICTED;
		signingKey       = create(this->mCtx, this->mPersistentStorageKeyHandle, nullptr, objectAttributes, nullptr, nullptr);
		signingKeyLoaded = load(this->mCtx, this->mPersistentStorageKeyHandle, nullptr, signingKey);

		// make the signing key persistent
		rc = evictControl(this->mCtx, TPM_RH_OWNER, signingKeyLoaded.objectHandle, this->mPersistentSigningKeyHandle);
		flushContext(this->mCtx, signingKeyLoaded.objectHandle);

		// save VM's signing key to file
		TSS_File_WriteStructure(&signingKey.outPublic,
								(MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshalu,
								this->mSigningKeyPublicFilename);
		TSS_File_WriteStructure(&signingKey.outPrivate,
								(MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshalu,
								this->mSigningKeyPrivateFilename);
	} else {
		// load VM's signing key into TPM storage
		signingKeyLoaded = load(this->mCtx, this->mPersistentStorageKeyHandle, nullptr, signingKey);

		// make the signing key persistent
		rc = evictControl(this->mCtx, TPM_RH_OWNER, signingKeyLoaded.objectHandle, this->mPersistentSigningKeyHandle);
		flushContext(this->mCtx, signingKeyLoaded.objectHandle);
	}

	// read public part of signing key from file
	rc = TSS_File_ReadStructureFlag(&this->mOrchestratorSigningKeyPublic,
									(UnmarshalFunctionFlag_t)TSS_TPM2B_PUBLIC_Unmarshalu,
									FALSE,
									this->mOrchestratorSigningKeyPublicFilename);
	if (rc == TSS_RC_FILE_OPEN) { // if file isn't available
		printf("[-] An error occured in %s::%s: missing public part of Orchestrator's signing key\n",
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		exit(1);
	}

	this->mOrchestratorSigningKeyName = this->getNameFromPublic(&this->mOrchestratorSigningKeyPublic.publicArea, nullptr);
}

web::http::status_code VM::createAttestationKey(const TPM2B_DIGEST* policyDigest, const TPMA_OBJECT objectAttributes, json::value& response) {
	// evict the current attestation key
	TPM_RC rc = evictControl(this->mCtx, TPM_RH_OWNER, this->mPersistentAttestationKeyHandle, this->mPersistentAttestationKeyHandle);

#ifdef HIGHLEVELTIMINGS
    auto t1 = Clock::now();
#endif
#ifdef LOWLEVELTIMINGS
    auto _t1 = Clock::now();
    auto _t2 = Clock::now();
#endif

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
	// create attestation key bound to policyDigest
	Create_Out attestationKey = create(this->mCtx, this->mPersistentStorageKeyHandle, nullptr, objectAttributes, nullptr, policyDigest);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_Create", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif
#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
	// load attestation key into volatile memory
	Load_Out attestationKeyLoaded = load(this->mCtx, this->mPersistentStorageKeyHandle, nullptr, attestationKey);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_Load", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
	CertifyCreation_Out cert = certifyCreation(this->mCtx,
					attestationKeyLoaded.objectHandle, 
					this->mPersistentSigningKeyHandle,
					&attestationKey.creationHash, 
					&attestationKey.creationTicket, 
					nullptr,
					TPM_RS_PW, 0,
					TPM_RH_NULL, 0,
					TPM_RH_NULL, 0);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_CertifyCreation", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
    // make the new attestation key persistent
    rc = prettyRC(evictControl(this->mCtx, TPM_RH_OWNER, attestationKeyLoaded.objectHandle, this->mPersistentAttestationKeyHandle), 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_EvictControl", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
    flushContext(this->mCtx, attestationKeyLoaded.objectHandle);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_FlushContext", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

#ifdef HIGHLEVELTIMINGS
    auto t2 = Clock::now();
    writeTiming(__func__, (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	// marshal signature into char vector
    uint16_t written = 0;
    unsigned char *buffer = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer,
				&written,
				&cert.signature,
				(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> signature;
	for (int i = 0; i < written; i++) {
		signature.push_back(buffer[i]);
	}

	// marshal certification information into char vector
    unsigned char *buffer2 = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer2,
				&written,
				&cert.certifyInfo,
				(MarshalFunction_t)TSS_TPM2B_ATTEST_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> certifyInfo;
	for (int i = 0; i < written; i++) {
		certifyInfo.push_back(buffer2[i]);
	}

	// marshal AKpub into char vector
    unsigned char *buffer3 = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer3,
				&written,
				&this->getAttestationKeyPublic(),
				(MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> akPub;
	for (int i = 0; i < written; i++) {
		akPub.push_back(buffer3[i]);
	}

	free(buffer);
	free(buffer2);
	free(buffer3);

	// create the JSON object containing the key creation certification
	response[U("signature")]   = json::value::string(U(utility::conversions::to_base64(signature)));
	response[U("certifyInfo")] = json::value::string(U(utility::conversions::to_base64(certifyInfo)));
	response[U("akPub")]       = json::value::string(U(utility::conversions::to_base64(akPub)));

    return status_codes::Created;
}

web::http::status_code VM::addPcr(const UINT32 pcrIdx, 
				const bool                 nv,
				const TPMA_NV*             attributes,
				const TPM2B_DIGEST*        policyDigest,
				const TPM2B_MAX_NV_BUFFER* iv,
				json::value&               response)
{
#ifdef HIGHLEVELTIMINGS
    auto t1 = Clock::now();
#endif
#ifdef LOWLEVELTIMINGS
    auto _t1 = Clock::now();
    auto _t2 = Clock::now();
#endif

	if (nv) {
		int NVPCRidx = -1;
		for (auto it = this->mNVPCRs.begin(); it != this->mNVPCRs.end(); ++it) {
			if (it->idx == pcrIdx) {
				NVPCRidx = std::distance(this->mNVPCRs.begin(), it);
				break;
			}
		}
		if (NVPCRidx != -1) {
			printf("[-] An error occured in %s::%s: NV PCR %d already exists in considered NV PCRs.\n",
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return status_codes::Conflict;
		}

		// create the NV PCR
#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
		nvDefineSpace(this->mCtx, TPM_RH_PLATFORM, pcrIdx, TPM_ALG_SHA256, *attributes, SHA256_DIGEST_SIZE, nullptr, policyDigest);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_NV_DefineSpace", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif
		nvExtend(this->mCtx, pcrIdx, iv, pcrIdx, TPM_RS_PW, 0, TPM_RH_NULL, 0); // if we don't write, then we cannot read it (certify)

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
		NV_Certify_Out cert = nvCertify(this->mCtx, TPM_RH_PLATFORM, pcrIdx, 0, this->mPersistentSigningKeyHandle, SHA256_DIGEST_SIZE);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_NV_Certify", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

		// add the NV PCR to cache
		NVPCR nvpcr;
		nvpcr.idx = pcrIdx;

		unsigned char init[SHA256_DIGEST_SIZE];
		memset(init, 0, SHA256_DIGEST_SIZE);

		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, init, SHA256_DIGEST_SIZE);
		SHA256_Update(&sha256, iv->b.buffer, SHA256_DIGEST_SIZE);
		SHA256_Final(nvpcr.val, &sha256); // H(0 || iv)

		this->mNVPCRs.push_back(nvpcr);

#ifdef HIGHLEVELTIMINGS
        auto t2 = Clock::now();
        writeTiming(__func__, (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

		// convert signature into char vector
		uint16_t written = 0;
		unsigned char *buffer = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer,
					&written,
					&cert.signature,
					(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> signature;
		for (int i = 0; i < written; i++) {
			signature.push_back(buffer[i]);
		}

		// convert certification information into char vector
		unsigned char *buffer2 = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer2,
					&written,
					&cert.certifyInfo,
					(MarshalFunction_t)TSS_TPM2B_ATTEST_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> certifyInfo;
		for (int i = 0; i < written; i++) {
			certifyInfo.push_back(buffer2[i]);
		}

		free(buffer);
		free(buffer2);

		// create the JSON object containing the key creation certification
		response[U("signature")]   = json::value::string(U(utility::conversions::to_base64(signature)));
		response[U("certifyInfo")] = json::value::string(U(utility::conversions::to_base64(certifyInfo)));

	} else {
		int PCRidx = -1;
		for (auto it = this->mPCRs.begin(); it != this->mPCRs.end(); ++it) {
			if (*it == pcrIdx) {
				PCRidx = std::distance(this->mPCRs.begin(), it);
				break;
			}
		}
		if (PCRidx != -1) {
			printf("[-] An error occured in %s::%s: NV PCR %d already exists in considered PCRs.\n",
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return status_codes::Conflict;
		}
		this->mPCRs.push_back(pcrIdx);
	}

	return status_codes::Created;
}

web::http::status_code VM::initRemNvPcr(json::value& response) {
	TPM_RC rc = startAuthSession(this->mCtx, TPM_SE_POLICY, &this->mDelNvPcrAuthSession);
	if (rc != 0) {
		return status_codes::InternalError;
	}

	// marshal nonceTPM into char vector
    uint16_t written = 0;
    unsigned char *buffer = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer,
				&written,
				&this->mDelNvPcrAuthSession.nonceTPM,
				(MarshalFunction_t)TSS_TPM2B_NONCE_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> nonceTPMStr;
	for (int i = 0; i < written; i++) {
		nonceTPMStr.push_back(buffer[i]);
	}

	response[U("nonceTPM")] = json::value::string(U(utility::conversions::to_base64(nonceTPMStr)));

	return status_codes::OK;
}

web::http::status_code VM::remPcr(const UINT32 pcrIdx, 
				const bool            nv,
				const TPM2B_DIGEST*   cpHashA,
				const TPMT_SIGNATURE* aHashSignature,
				const TPM2B_DIGEST*   policyDigest,
				const TPM2B_DIGEST*   policyDigestSigned,
				const TPMT_SIGNATURE* policyDigestSignature,
				json::value&          response)
{
#ifdef HIGHLEVELTIMINGS
    auto t1 = Clock::now();
#endif
#ifdef LOWLEVELTIMINGS
    auto _t1 = Clock::now();
    auto _t2 = Clock::now();
#endif

	if (nv) {
		int NVPCRidx = -1;
		for (auto it = this->mNVPCRs.begin(); it != this->mNVPCRs.end(); ++it) {
			if (it->idx == pcrIdx) {
				NVPCRidx = std::distance(this->mNVPCRs.begin(), it);
				break;
			}
		}
		if (NVPCRidx == -1) {
			printf("[-] An error occured in %s::%s: NV PCR %d not found in considered NV PCRs.\n",
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
            return status_codes::NotFound;
		} else {
            // delete from cache
            this->mNVPCRs.erase(this->mNVPCRs.begin() + NVPCRidx);
		}

		// load public part of Orchestrator's signing key into TPM storage
		LoadExternal_Out orchestratorSigningKeyPublicLoaded = loadExternal(this->mCtx, 
					TPM_RH_OWNER, 
					nullptr, 
					&this->mOrchestratorSigningKeyPublic);

		TPMT_TK_VERIFIED validationPolicy = verifySignature(this->mCtx, 
					policyDigestSigned, 
					orchestratorSigningKeyPublicLoaded.objectHandle, 
					policyDigestSignature);

		if (validationPolicy.tag != TPM_ST_VERIFIED) {
			printf("[-] An error occured in %s::%s: validation unsuccessful\n",
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
			exit(1);
		}

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
		// the TPM internally sets session(H).cpHash = cpHash
		policySigned(this->mCtx, 
					aHashSignature, 
					orchestratorSigningKeyPublicLoaded.objectHandle, 
					cpHashA, 
					0, 
					&this->mDelNvPcrAuthSession.nonceTPM, 
					nullptr, 
					this->mDelNvPcrAuthSession.sessionHandle);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_PolicySigned", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif
		flushContext(this->mCtx, orchestratorSigningKeyPublicLoaded.objectHandle);

		TPM_RC rc = policyAuthorize(this->mCtx, 
					this->mDelNvPcrAuthSession.sessionHandle, 
					policyDigest, 
					nullptr,
					this->mOrchestratorSigningKeyName,
					&validationPolicy);
		if (rc != 0) return status_codes::Unauthorized;
#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
		policyCommandCode(this->mCtx, this->mDelNvPcrAuthSession.sessionHandle, TPM_CC_NV_UndefineSpaceSpecial);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_PolicyCommandCode", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
		// delete the NV PCR
		nvUndefineSpaceSpecial(this->mCtx, pcrIdx, nullptr, this->mDelNvPcrAuthSession.sessionHandle, 0);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_NV_UndefineSpaceSpecial", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif
	} else {
		int PCRidx = -1;
		for (auto it = this->mPCRs.begin(); it != this->mPCRs.end(); ++it) {
			if (*it == pcrIdx) {
				PCRidx = std::distance(this->mPCRs.begin(), it);
				break;
			}
		}
		if (PCRidx == -1) {
			printf("[-] An error occured in %s::%s: PCR %d not found in considered PCRs.\n",
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return status_codes::NotFound;
		}
		this->mPCRs.erase(this->mPCRs.begin() + PCRidx);
	}

#ifdef HIGHLEVELTIMINGS
    auto t2 = Clock::now();
    writeTiming(__func__, (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return status_codes::OK;
}

web::http::status_code VM::update(const TPM2B_DIGEST* policyDigest, 
				const TPM2B_DIGEST*   policyDigestSigned, 
				const TPMT_SIGNATURE* policyDigestSignature,
				const UINT32          pcrIdx, 
				const bool            nv,
				unsigned char*        tracerOutput,
				json::value&          response)
{
#ifdef HIGHLEVELTIMINGS
    auto t1 = Clock::now();
#endif
	// load public part of Orchestrator's signing key into TPM storage
	LoadExternal_Out orchestratorSigningKeyPublicLoaded = loadExternal(this->mCtx, TPM_RH_OWNER, nullptr, &this->mOrchestratorSigningKeyPublic);
#ifdef LOWLEVELTIMINGS
    auto _t1 = Clock::now();
    auto _t2 = Clock::now();
#endif

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
	TPMT_TK_VERIFIED validation = verifySignature(this->mCtx, 
				policyDigestSigned, 
				orchestratorSigningKeyPublicLoaded.objectHandle, 
				policyDigestSignature);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_VerifySignature", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif
	flushContext(this->mCtx, orchestratorSigningKeyPublicLoaded.objectHandle);

	if (validation.tag != TPM_ST_VERIFIED) {
		printf("[-] An error occured in %s::%s: validation unsuccessful\n",
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return status_codes::Unauthorized;
	}

	this->mApprovedPolicy = *policyDigest;
	this->mTicket         = validation;

	/**
	 * NOTE: tracerOutput should be replaced by a FQPN and the measurements should come from a secure tracer.
	 */
#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
	StartAuthSession_Out authSession;
	TPM_RC rc = startAuthSession(this->mCtx, TPM_SE_HMAC, &authSession);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_StartAuthSession", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

	if (nv) {
		int NVPCRidx = -1;
		for (auto it = this->mNVPCRs.begin(); it != this->mNVPCRs.end(); ++it) {
			if (it->idx == pcrIdx) {
				NVPCRidx = std::distance(this->mNVPCRs.begin(), it);
				break;
			}
		}
		if (NVPCRidx == -1) {
			printf("[-] An error occured in %s::%s: NV PCR %d not found in considered NV PCRs.\n",
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return status_codes::NotFound;
		}

		// authenticate the tracer output (measurement) using the shared HMAC key
		unsigned int len = SHA256_DIGEST_SIZE;
		HMAC_CTX* hmacCtx = HMAC_CTX_new();
		HMAC_Init_ex(hmacCtx, this->secretHmacKey, this->keyLen, EVP_sha256(), nullptr);
		HMAC_Update(hmacCtx, tracerOutput, SHA256_DIGEST_SIZE);
		HMAC_Final(hmacCtx, tracerOutput, &len);
		HMAC_CTX_free(hmacCtx);

		TPM2B_MAX_NV_BUFFER measurements;
		memcpy(measurements.b.buffer, tracerOutput, SHA256_DIGEST_SIZE);
		measurements.b.size = SHA256_DIGEST_SIZE;

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
		nvExtend(this->mCtx, pcrIdx, &measurements, pcrIdx, TPM_RS_PW, 0, authSession.sessionHandle, TPMA_SESSION_AUDIT | TPMA_SESSION_CONTINUESESSION);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_NV_Extend", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

		// update cache contents
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, this->mNVPCRs.at(NVPCRidx).val, SHA256_DIGEST_SIZE);
		SHA256_Update(&sha256, tracerOutput, SHA256_DIGEST_SIZE);
		SHA256_Final(this->mNVPCRs.at(NVPCRidx).val, &sha256); // H(prev || new)
	} else {
		int PCRidx = -1;
		for (auto it = this->mPCRs.begin(); it != this->mPCRs.end(); ++it) {
			if (*it == pcrIdx) {
				PCRidx = std::distance(this->mPCRs.begin(), it);
				break;
			}
		}
		if (PCRidx == -1) {
			printf("[-] An error occured in %s::%s: PCR %d not found in considered PCRs.\n",
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return status_codes::NotFound;
		}

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
		pcrExtend(this->mCtx, pcrIdx, tracerOutput, authSession.sessionHandle, TPMA_SESSION_AUDIT | TPMA_SESSION_CONTINUESESSION);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_PCR_Extend", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif
	}

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
	GetSessionAuditDigest_Out cert = getSessionAuditDigest(this->mCtx, nullptr, this->mPersistentSigningKeyHandle, authSession.sessionHandle);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_GetSessionAuditDigest", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

	flushContext(this->mCtx, authSession.sessionHandle);

#ifdef HIGHLEVELTIMINGS
    auto t2 = Clock::now();
    writeTiming(__func__, (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	// marshal signature into char vector
    uint16_t written = 0;
    unsigned char *buffer = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer,
				&written,
				&cert.signature,
				(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> signature;
	for (int i = 0; i < written; i++) {
		signature.push_back(buffer[i]);
	}

	// marshal audit information into char vector
    unsigned char *buffer2 = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer2,
				&written,
				&cert.auditInfo,
				(MarshalFunction_t)TSS_TPM2B_ATTEST_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> auditInfo;
	for (int i = 0; i < written; i++) {
		auditInfo.push_back(buffer2[i]);
	}

	free(buffer);
	free(buffer2);

	// create the JSON object containing the update certification
	response[U("signature")] = json::value::string(U(utility::conversions::to_base64(signature)));
	response[U("auditInfo")] = json::value::string(U(utility::conversions::to_base64(auditInfo)));

    return status_codes::OK;
}

web::http::status_code VM::attest(const TPM2B_DIGEST* nonceDigest, json::value& response) {
#ifdef HIGHLEVELTIMINGS
    auto t1 = Clock::now();
#endif
#ifdef LOWLEVELTIMINGS
    auto _t1 = Clock::now();
    auto _t2 = Clock::now();
#endif

	StartAuthSession_Out authSession;
	TPM_RC rc = startAuthSession(this->mCtx, TPM_SE_POLICY, &authSession);

	/**
	 * PHASE: VM accumulates the contents of the currently selected NV PCRs (NVPCR) into the session's policy digest.
	 */
	if (!this->mNVPCRs.empty()) {
		for (auto it = this->mNVPCRs.begin(); it != this->mNVPCRs.end(); ++it) {
			TPM2B_OPERAND operandB;
			memcpy(operandB.b.buffer, it->val, SHA256_DIGEST_SIZE);
			operandB.b.size = SHA256_DIGEST_SIZE;

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
			// try to satisfy the policy with the current cache contents
			policyNv(this->mCtx, it->idx, it->idx, 0, operandB, 0, authSession.sessionHandle, TPM_RS_PW, 0);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_PolicyNV", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif
		}
	}

	/**
	 * PHASE: VM accumulates all the currently active PCRs (PCR) into the session's policy digest.
	 */
	if (!this->mPCRs.empty()) {
		TPML_PCR_SELECTION pcrSelection; // reflects selected banks and PCR bit maps
		pcrSelection.count = 1; // consider single bank/hash algorithm
		pcrSelection.pcrSelections[0].hash         = TPM_ALG_SHA256;
		pcrSelection.pcrSelections[0].sizeofSelect = IMPLEMENTATION_PCR/8; // consider 24 PCRs (3 octets)

		// deselect all PCRs
		uint32_t pcrmask = 0x00000000;
		pcrSelection.pcrSelections[0].pcrSelect[0] = (pcrmask >>  0) & 0xff;
		pcrSelection.pcrSelections[0].pcrSelect[1] = (pcrmask >>  8) & 0xff;
		pcrSelection.pcrSelections[0].pcrSelect[2] = (pcrmask >> 16) & 0xff;

		for (auto it = this->mPCRs.begin(); it != this->mPCRs.end(); ++it)
		pcrSelection.pcrSelections[0].pcrSelect[(int)(*it / 8)] |= 1 << (int)(*it % 8); // use only currently active PCRs

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
		policyPCR(this->mCtx, nullptr, &pcrSelection, authSession.sessionHandle);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_PolicyPCR", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif
	}

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
	/**
	 * PHASE: VM tries to unlock PolicyAuthorize with the session's policy digest.
	 */
	rc = policyAuthorize(this->mCtx, 
				authSession.sessionHandle, 
				&this->mApprovedPolicy, 
				nullptr, 
				this->mOrchestratorSigningKeyName, 
				&this->mTicket);
	if (rc != 0) return status_codes::Unauthorized;
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_PolicyAuthorize", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

#ifdef LOWLEVELTIMINGS
    _t1 = Clock::now();
#endif
	/**
	 * PHASE: VM tries to use the attestation key, and if it can, then it proves that it has satisfied the policy.
	 */
	TPMT_SIGNATURE signature = sign(this->mCtx, nonceDigest, this->mPersistentAttestationKeyHandle, nullptr, authSession.sessionHandle, 1);
#ifdef LOWLEVELTIMINGS
    _t2 = Clock::now();
	writeTiming("TPM2_Sign", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(_t2 - _t1).count() / 1000000);
#endif

	flushContext(this->mCtx, authSession.sessionHandle);

#ifdef HIGHLEVELTIMINGS
    auto t2 = Clock::now();
    writeTiming(__func__, (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	// marshal signature into char vector
    uint16_t written = 0;
    unsigned char *buffer = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer,
				&written,
				&signature,
				(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> signatureStr;
	for (int i = 0; i < written; i++) {
		signatureStr.push_back(buffer[i]);
	}

	free(buffer);

	// create the JSON object containing the key creation certification
	response[U("signature")] = json::value::string(U(utility::conversions::to_base64(signatureStr)));

    return status_codes::OK;
}

TPM2B_PUBLIC VM::getSigningKeyPublic() const {
	return readPublic(this->mCtx, this->mPersistentSigningKeyHandle).outPublic;
}

TPM2B_PUBLIC VM::getAttestationKeyPublic() const {
	return readPublic(this->mCtx, this->mPersistentAttestationKeyHandle).outPublic;
}

TPM2B_NAME VM::getNameFromPublic(const TPMT_PUBLIC* publicKey, const TPMS_NV_PUBLIC* publicNv) {
	TPM2B_NAME     objectName;
	TPM2B_TEMPLATE marshaled;
	TPMT_HA        name;
	uint16_t       tmpWritten = 0;
	uint32_t       tmpSize    = sizeof(marshaled.t.buffer);
	BYTE*          tmpBuffer  = marshaled.t.buffer;

	// marshal publicArea through tmpBuffer into marshaled buffer
	if (publicKey != nullptr) {
		name.hashAlg = publicKey->nameAlg;
		prettyRC(TSS_TPMT_PUBLIC_Marshalu(publicKey, 
					&tmpWritten, 
					&tmpBuffer, 
					&tmpSize), 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	} else if (publicNv != nullptr) {
		name.hashAlg = publicNv->nameAlg;
		prettyRC(TSS_TPMS_NV_PUBLIC_Marshalu(publicNv, 
					&tmpWritten, 
					&tmpBuffer, 
					&tmpSize), 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	} else {
		objectName.b.size = 0;
		return objectName;
	}
	marshaled.t.size = tmpWritten;

	// generate digest over marshaled buffer
	prettyRC(TSS_Hash_Generate(&name, 
				marshaled.t.size, 
				marshaled.t.buffer, 0, nullptr), 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	// extract object name from digest
	objectName.b.buffer[0] = name.hashAlg >> 8;
	objectName.b.buffer[1] = name.hashAlg & 0xff;
	memcpy(&objectName.b.buffer[2], name.digest.tssmax, TSS_GetDigestSize(name.hashAlg));
	objectName.b.size = TSS_GetDigestSize(name.hashAlg)+2;

	return objectName;
}
