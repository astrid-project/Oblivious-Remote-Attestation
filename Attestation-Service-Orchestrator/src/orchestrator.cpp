#include <openssl/hmac.h>
#include "orchestrator.h"
#include "timing.h"

Orchestrator::Orchestrator(TSS_CONTEXT* ctx, const bool verbose) : mCtx(ctx), verbose(verbose) {
	// Orchestrator has an restricted decryption key (storage key)
	CreatePrimary_Out storageKey;
	TPM_RC rc = createPrimaryKey(this->mCtx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

	// make the storage key persistent
	rc = evictControl(this->mCtx, TPM_RH_OWNER, storageKey.objectHandle, this->mPersistentStorageKeyHandle);
	flushContext(this->mCtx, storageKey.objectHandle);

	/* load Orchestrator's signing key */
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

		// save Orchestrator's signing key to file
		TSS_File_WriteStructure(&signingKey.outPublic,
								(MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshalu,
								this->mSigningKeyPublicFilename);
		TSS_File_WriteStructure(&signingKey.outPrivate,
								(MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshalu,
								this->mSigningKeyPrivateFilename);
	} else {
		// load Orchestrator's signing key into TPM storage
		signingKeyLoaded = load(this->mCtx, this->mPersistentStorageKeyHandle, nullptr, signingKey);

		// make the signing key persistent
		rc = evictControl(this->mCtx, TPM_RH_OWNER, signingKeyLoaded.objectHandle, this->mPersistentSigningKeyHandle);
		flushContext(this->mCtx, signingKeyLoaded.objectHandle);
	}

	this->mSigningKeyName = this->getNameFromPublic(&signingKey.outPublic.publicArea, nullptr);

	// read public part of signing key from file
	rc = TSS_File_ReadStructureFlag(&this->mVmSigningKeyPublic,
									(UnmarshalFunctionFlag_t)TSS_TPM2B_PUBLIC_Unmarshalu,
									FALSE,
									this->mVmSigningKeyPublicFilename);
	if (rc == TSS_RC_FILE_OPEN) { // if file isn't available
		printf("[-] An error occured in %s::%s: missing public part of VM's signing key\n",
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		exit(1);
	}
}

bool Orchestrator::deploy(utility::string_t url) {
	/**
	 * The Orchestrator keeps an mock PCR (mPCR) structure to match the contents of the container's TPM.
	 * To enable synchronization, the structure is initially filled with the initial PCR values at the time of deployment.
	 */
	for (int pcr = 0; pcr < IMPLEMENTATION_PCR; pcr++) {
        mPCR apcr;
        apcr.idx = pcr;
		PCR_Read_Out currentVal = pcrRead(this->mCtx, pcr);
		memcpy(apcr.val, currentVal.pcrValues.digests[0].t.buffer, SHA256_DIGEST_SIZE);
        this->mPCRs.push_back(apcr);
	}

	// Orchestrator creates and binds a flexible policy to its signing key.
	// When the digest of the policy is bound to an object, it ensures that the object can only be operated 
	// on if the session fulfills some policy which the Orchestrator has signed using its private key.
	unsigned char ccPolicyAuthorize[4] = {0x00, 0x00 ,0x01, 0x6a}; // TPM_CC_PolicyAuthorize

	TPM2B_DIGEST policyDigest;
	policyDigest.b.size = SHA256_DIGEST_SIZE;
	memset(policyDigest.b.buffer, 0, SHA256_DIGEST_SIZE); // starts with zero digest

	// policyDigest' = H(policyDigest || CC || authName)
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, policyDigest.b.buffer, policyDigest.b.size);
	SHA256_Update(&sha256, ccPolicyAuthorize, 4);
	SHA256_Update(&sha256, this->mSigningKeyName.b.buffer, this->mSigningKeyName.b.size);
	SHA256_Final(policyDigest.b.buffer, &sha256);

	// policyDigest' = H(policyDigest || ref)
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, policyDigest.b.buffer, policyDigest.b.size);
	SHA256_Final(policyDigest.b.buffer, &sha256);

	// the AK's object attributes
    TPMA_OBJECT objectAttributes;
    objectAttributes.val = (TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY | TPMA_OBJECT_SIGN)
			& ~TPMA_OBJECT_USERWITHAUTH & ~TPMA_OBJECT_DECRYPT & ~TPMA_OBJECT_RESTRICTED; // unrestricted signing key
	// TSS_TPMA_OBJECT_Print("AK object atrributes", objectAttributes, 0);

	/**
	 * http://proverAddress:port/api/attestationKey
	 */
	// placeholders for parsed JSON response
	vector<unsigned char> signatureStr;
	vector<unsigned char> certifyInfoStr;
	vector<unsigned char> akPubStr;

	// marshal policy digest into char vector
    uint16_t written = 0;
    unsigned char *buffer = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer,
				&written,
				&policyDigest,
				(MarshalFunction_t)TSS_TPM2B_DIGEST_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> policyDigestStr;
	for (int i = 0; i < written; i++) {
		policyDigestStr.push_back(buffer[i]);
	}

	// marshal object attributes into char vector
    unsigned char *buffer2 = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer2,
				&written,
				&objectAttributes,
				(MarshalFunction_t)TSS_TPMA_OBJECT_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> objectAttributesStr;
	for (int i = 0; i < written; i++) {
		objectAttributesStr.push_back(buffer2[i]);
	}

	free(buffer);
	free(buffer2);

	// create the JSON object containing the key creation template
	json::value jsonObject;
	jsonObject[U("policyDigest")]     = json::value::string(U(utility::conversions::to_base64(policyDigestStr)));
	jsonObject[U("objectAttributes")] = json::value::string(U(utility::conversions::to_base64(objectAttributesStr)));

	// mock the request
	auto postJson = http_client(url)
		.request(methods::POST,
			uri_builder().append_path(U("attestationKey")).to_string(),
			jsonObject.serialize(), U("application/json"))
		.then([this](http_response response) {
			if (verbose) ucout << response.to_string() << endl;
			if (response.status_code() != status_codes::Created) {
				throw std::runtime_error("Returned " + std::to_string(response.status_code()));
			}

			return response.extract_json();
		})
		.then([&signatureStr, &certifyInfoStr, &akPubStr](json::value jsonResObject) {

	        // extract and decode data from JSON object
			utility::string_t signatureBase64   = jsonResObject[U("signature")].as_string();
			utility::string_t certifyInfoBase64 = jsonResObject[U("certifyInfo")].as_string();
			utility::string_t akPubBase64       = jsonResObject[U("akPub")].as_string();
			signatureStr   = utility::conversions::from_base64(signatureBase64);
			certifyInfoStr = utility::conversions::from_base64(certifyInfoBase64);
			akPubStr       = utility::conversions::from_base64(akPubBase64);
		});
 
	// send the request
	try {
		postJson.wait();
	} catch (const std::exception &e) {
		printf("[-] An error occured in %s::%s: %s\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, e.what());
		return false;
	}

	// unmarshal signature
	TPMT_SIGNATURE signature;
	BYTE*    tmpBuffer = &signatureStr[0];
	uint32_t tmpSize   = signatureStr.size();
	prettyRC(TSS_TPMT_SIGNATURE_Unmarshalu(&signature, 
				&tmpBuffer, 
				&tmpSize,
				YES), 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	// unmarshal certifyInfo
	TPM2B_ATTEST certifyInfo;
	tmpBuffer = &certifyInfoStr[0];
	tmpSize   = certifyInfoStr.size();
	prettyRC(TSS_TPM2B_ATTEST_Unmarshalu(&certifyInfo, 
				&tmpBuffer, 
				&tmpSize), 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	// unmarshal public part of attestation key
	TPM2B_PUBLIC akPub;
	tmpBuffer = &akPubStr[0];
	tmpSize   = akPubStr.size();
	prettyRC(TSS_TPM2B_PUBLIC_Unmarshalu(&akPub, 
				&tmpBuffer, 
				&tmpSize,
				YES), 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	// TSS_TPM2B_PUBLIC_Print("AKpub", &akPub, 0);

	// verify that the AK was created with the flexible policy digest
	if (!this->verifyAttestationKeyCreation(signature,
				certifyInfo, 
				akPub, 
				this->mVmSigningKeyPublic,
				policyDigest, 
				objectAttributes)) return false;

	this->mContainerAkPublic = akPub;

    return true;
}

bool Orchestrator::update(utility::string_t url, const UINT32 pcrIdx, const bool nv, unsigned char* updateDigest, unsigned char* secretHmacKey, const int keyLen) {
	// extend the update digest with the HMAC key (authenticate the PCR extension)
	unsigned int len = SHA256_DIGEST_SIZE;
	unsigned char authenticUpdateDigest[SHA256_DIGEST_SIZE]; // digest over the new update
    HMAC_CTX* hmacCtx = HMAC_CTX_new();
    HMAC_Init_ex(hmacCtx, secretHmacKey, keyLen, EVP_sha256(), nullptr);
    HMAC_Update(hmacCtx, updateDigest, SHA256_DIGEST_SIZE);
    HMAC_Final(hmacCtx, authenticUpdateDigest, &len);
    HMAC_CTX_free(hmacCtx);

    SHA256_CTX     sha256;
	TPM2B_DIGEST   policyDigest;
	TPM2B_DIGEST   policyDigestSigned;
	TPMT_SIGNATURE policyDigestSignature;

	policyDigest.t.size       = SHA256_DIGEST_SIZE;
	policyDigestSigned.t.size = SHA256_DIGEST_SIZE;

	memset(policyDigest.b.buffer, 0, policyDigest.b.size); // policyDigest starts with a value of 0

	unsigned char ccPolicyNv[4]  = {0x00, 0x00 ,0x01, 0x49}; // TPM_CC_PolicyNV
	unsigned char ccPolicyPcr[4] = {0x00, 0x00 ,0x01, 0x7f}; // TPM_CC_PolicyPCR

	/**
	 * PHASE: Orchestrator updates the specified mock (NV)PCR (pcrIdx) with the authenticated update digest
	 */
	if (nv) { // the update must be extended into a NV PCR
		int mNVPCRidx = -1;
		for (auto it = this->mNVPCRs.begin(); it != this->mNVPCRs.end(); ++it) {
			if (it->idx == pcrIdx) {
				mNVPCRidx = std::distance(this->mNVPCRs.begin(), it);
				break;
			}
		}
		if (mNVPCRidx == -1) {
			printf("[-] An error occured in %s::%s: mNVPCR %d not found.\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return false;
		}

		// simulate the effect of the update by extending the container's mNVPCR
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, this->mNVPCRs.at(mNVPCRidx).val, SHA256_DIGEST_SIZE);
		SHA256_Update(&sha256, authenticUpdateDigest, SHA256_DIGEST_SIZE);
		SHA256_Final(this->mNVPCRs.at(mNVPCRidx).val, &sha256); // H(old value || new value)
	} 
	else { // the update must be extended into a normal PCR
		int mPCRidx = -1;
		for (auto it = this->mPCRs.begin(); it != this->mPCRs.end(); ++it) {
			if (it->idx == pcrIdx) {
				mPCRidx = std::distance(this->mPCRs.begin(), it);
				break;
			}
		}
		if (mPCRidx == -1) {
			printf("[-] An error occured in %s::%s: mPCR %d not found.\n",
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return false;
		}

		// simulate the effect of the update by extending the container's mPCR
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, this->mPCRs.at(mPCRidx).val, SHA256_DIGEST_SIZE);
		SHA256_Update(&sha256, authenticUpdateDigest, SHA256_DIGEST_SIZE);
		SHA256_Final(this->mPCRs.at(mPCRidx).val, &sha256); // H(old value || new value)
	}

	/**
	 * PHASE: Orchestrator accumulates all the currently selected mock NV PCRs (mNVPCR) into the session's policy digest.
	 */
	for (auto it = this->mNVPCRs.begin(); it != this->mNVPCRs.end(); ++it) {

		// for NV_Extend, the args are: H(operandB.buffer || offset || operation)
		TPM2B_DIGEST args;

		unsigned char offset[2]    = {0x00, 0x00};
		unsigned char operation[2] = {0x00, 0x00};

		SHA256_Init(&sha256);
		SHA256_Update(&sha256, it->val, SHA256_DIGEST_SIZE);
		SHA256_Update(&sha256, offset, 2);
		SHA256_Update(&sha256, operation, 2);
		SHA256_Final(args.b.buffer, &sha256);
		args.b.size = SHA256_DIGEST_SIZE;

		// policyDigest' = H(policyDigest || TPM_CC_PolicyNV || args || nvIndex->name)
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, policyDigest.b.buffer, policyDigest.b.size);
		SHA256_Update(&sha256, ccPolicyNv, sizeof(TPM_CC));
		SHA256_Update(&sha256, args.b.buffer, args.b.size);
		SHA256_Update(&sha256, it->name.b.buffer, it->name.b.size);
		SHA256_Final(policyDigest.b.buffer, &sha256);
	}

	/**
	 * PHASE: Orchestrator accumulates all the currently active mock PCRs (mPCR) into the session's policy digest.
	 */
	bool usingNormalPCRs = false; // whether we currently consider any normal PCRs
	for (auto it = this->mPCRs.begin(); it != this->mPCRs.end(); ++it) {
		if (it->active) {
			usingNormalPCRs = true;
			break;
		}
	}
	if (usingNormalPCRs) {
		TPML_PCR_SELECTION pcrSelection; // reflects selected banks and PCR bit maps
		TPM2B_DIGEST       pcrDigest;    // digest over all active mPCRs

		pcrSelection.count = 1; // consider single bank/hash algorithm
		pcrSelection.pcrSelections[0].hash         = TPM_ALG_SHA256;
		pcrSelection.pcrSelections[0].sizeofSelect = IMPLEMENTATION_PCR/8; // consider 24 PCRs (3 octets)

		// deselect all PCRs
		uint32_t pcrmask = 0x00000000;
		pcrSelection.pcrSelections[0].pcrSelect[0] = (pcrmask >>  0) & 0xff;
		pcrSelection.pcrSelections[0].pcrSelect[1] = (pcrmask >>  8) & 0xff;
		pcrSelection.pcrSelections[0].pcrSelect[2] = (pcrmask >> 16) & 0xff;

		SHA256_Init(&sha256);

		for (auto it = this->mPCRs.begin(); it != this->mPCRs.end(); ++it) {
			if (it->active) {
				SHA256_Update(&sha256, it->val, SHA256_DIGEST_SIZE);
				pcrSelection.pcrSelections[0].pcrSelect[(int)(it->idx / 8)] |= 1 << (int)(it->idx % 8); // use only currently active PCRs
			}
		}

		SHA256_Final(pcrDigest.b.buffer, &sha256);
		pcrDigest.b.size = SHA256_DIGEST_SIZE;

		BYTE   pcrs[sizeof(TPML_PCR_SELECTION)];
		BYTE*  buffer  = pcrs;
		UINT16 written = 0;
		TSS_TPML_PCR_SELECTION_Marshal(&pcrSelection, &written, &buffer, nullptr);

		// policyDigest' = H(policyDigest || TPM_CC_PolicyPCR || pcrs || pcr digest)
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, policyDigest.b.buffer, policyDigest.b.size);
		SHA256_Update(&sha256, ccPolicyPcr, sizeof(TPM_CC));
	    SHA256_Update(&sha256, pcrs, written);
		SHA256_Update(&sha256, pcrDigest.b.buffer, pcrDigest.b.size);
		SHA256_Final(policyDigest.b.buffer, &sha256);
	}

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, policyDigest.t.buffer, SHA256_DIGEST_SIZE);
	SHA256_Final(policyDigestSigned.t.buffer, &sha256); // H(approvedPolicy || policyRef)

	policyDigestSignature = sign(this->mCtx, &policyDigestSigned, this->mPersistentSigningKeyHandle, nullptr, TPM_RS_PW, 0);

	/**
	 * http://proverAddress:port/api/update
	 */
	// placeholders for parsed JSON response
	vector<unsigned char> signatureStr;
	vector<unsigned char> auditInfoStr;

	// marshal policy digest into char vector
	uint16_t written = 0;
	unsigned char *buffer = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer,
				&written,
				&policyDigest,
				(MarshalFunction_t)TSS_TPM2B_DIGEST_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> policyDigestStr;
	for (int i = 0; i < written; i++) {
		policyDigestStr.push_back(buffer[i]);
	}

	// marshal signed policy digest into char vector
	unsigned char *buffer2 = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer2,
				&written,
				&policyDigestSigned,
				(MarshalFunction_t)TSS_TPM2B_DIGEST_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> policyDigestSignedStr;
	for (int i = 0; i < written; i++) {
		policyDigestSignedStr.push_back(buffer2[i]);
	}

	// marshal policy digest signature into char vector
	unsigned char *buffer3 = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer3,
				&written,
				&policyDigestSignature,
				(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> policyDigestSignatureStr;
	for (int i = 0; i < written; i++) {
		policyDigestSignatureStr.push_back(buffer3[i]);
	}

	// send also the expected (trusted) tracer output (this should actually be done locally on the prover usnig its secure tracer)
	vector<unsigned char> tracerOutputStr;
	for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
		tracerOutputStr.push_back(updateDigest[i]);
	}

	free(buffer);
	free(buffer2);
	free(buffer3);

	// create the JSON object
	json::value jsonObject;
	jsonObject[U("pcrIdx")]                = json::value::number(pcrIdx);
	jsonObject[U("nv")]                    = json::value::boolean(nv);
	jsonObject[U("policyDigest")]          = json::value::string(U(utility::conversions::to_base64(policyDigestStr)));
	jsonObject[U("policyDigestSigned")]    = json::value::string(U(utility::conversions::to_base64(policyDigestSignedStr)));
	jsonObject[U("policyDigestSignature")] = json::value::string(U(utility::conversions::to_base64(policyDigestSignatureStr)));
	jsonObject[U("tracerOutput")]          = json::value::string(U(utility::conversions::to_base64(tracerOutputStr)));

	// mock the request
	auto postJson = http_client(url)
		.request(methods::POST,
			uri_builder().append_path(U("update")).to_string(),
			jsonObject.serialize(), U("application/json"))
		.then([this](http_response response) {
			if (verbose) ucout << response.to_string() << endl;
			if (response.status_code() != status_codes::OK) {
				throw std::runtime_error("Returned " + std::to_string(response.status_code()));
			}

			return response.extract_json();
		})
		.then([&signatureStr, &auditInfoStr](json::value jsonResObject) {

			// extract and decode data from JSON object
			utility::string_t signatureBase64 = jsonResObject[U("signature")].as_string();
			utility::string_t auditInfoBase64 = jsonResObject[U("auditInfo")].as_string();
			signatureStr = utility::conversions::from_base64(signatureBase64);
			auditInfoStr = utility::conversions::from_base64(auditInfoBase64);
		});

	// send the request
	try {
		postJson.wait();
	} catch (const std::exception &e) {
		printf("[-] An error occured in %s::%s: %s\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, e.what());
		return false;
	}

	// unmarshal signature
	TPMT_SIGNATURE signature;
	BYTE*    tmpBuffer = &signatureStr[0];
	uint32_t tmpSize   = signatureStr.size();
	prettyRC(TSS_TPMT_SIGNATURE_Unmarshalu(&signature, 
				&tmpBuffer, 
				&tmpSize,
				YES), 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	// unmarshal audit information
	TPM2B_ATTEST auditInfo;
	tmpBuffer = &auditInfoStr[0];
	tmpSize   = auditInfoStr.size();
	prettyRC(TSS_TPM2B_ATTEST_Unmarshalu(&auditInfo, 
				&tmpBuffer, 
				&tmpSize), 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	// verify audit data
	if (!this->verifyAuditSessionExtend(signature, 
				auditInfo, 
				this->mVmSigningKeyPublic, 
				pcrIdx, 
				nv, 
				authenticUpdateDigest)) {
		this->mTrustState = 0; // container not ok
		return false;
	}

	this->mTrustState = 1; // container ok
	return true;
}

bool Orchestrator::addPcr(utility::string_t url, const UINT32 pcrIdx, const bool nv) {
	if (nv) { // if NV-based PCR
		mNVPCR mnvpcr;
		mnvpcr.idx = pcrIdx;

		// the NV-based PCR's object attributes
		TPMA_NV objectAttributes;
		objectAttributes.val = TPMA_NVA_AUTHREAD | TPMA_NVA_AUTHWRITE
			| TPMA_NVA_PPREAD  | TPMA_NVA_OWNERREAD | TPMA_NVA_NO_DA
			| TPMA_NVA_ORDERLY | TPMA_NVA_EXTEND    | TPMA_NVA_WRITEALL
			| TPMA_NVA_PLATFORMCREATE | TPMA_NVA_POLICY_DELETE;
		// TSS_TPMA_NV_Print(objectAttributes, 0);

		// create flexible policy bound to Orchestrator's signing key (endorsement key)
		unsigned char ccPolicyAuthorize[4]        = {0x00, 0x00 ,0x01, 0x6a}; // TPM_CC_PolicyAuthorize
		unsigned char ccPolicyCommandCode[4]      = {0x00, 0x00 ,0x01, 0x6c}; // TPM_CC_PolicyCommandCode
		unsigned char ccNvUndefineSpaceSpecial[4] = {0x00, 0x00 ,0x01, 0x1f}; // TPM_CC_NV_UndefineSpaceSpecial

		TPM2B_DIGEST policyDigest;
		policyDigest.b.size = SHA256_DIGEST_SIZE;

		memset(policyDigest.b.buffer, 0, SHA256_DIGEST_SIZE); // starts with zero digest

		// policyDigest' = H(policyDigest || CC || authName)
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, policyDigest.b.buffer, policyDigest.b.size);
		SHA256_Update(&sha256, ccPolicyAuthorize, 4);
		SHA256_Update(&sha256, this->mSigningKeyName.b.buffer, this->mSigningKeyName.b.size);
		SHA256_Final(policyDigest.b.buffer, &sha256);

		// policyDigest' = H(policyDigest || ref)
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, policyDigest.b.buffer, policyDigest.b.size);
		SHA256_Final(policyDigest.b.buffer, &sha256);

		// policyDigest' = H(policyDigest || CC )
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, policyDigest.b.buffer, policyDigest.b.size);
		SHA256_Update(&sha256, ccPolicyCommandCode, 4);
		SHA256_Update(&sha256, ccNvUndefineSpaceSpecial, 4);
		SHA256_Final(policyDigest.b.buffer, &sha256);

		// initialize NV PCR value
		unsigned char       init[SHA256_DIGEST_SIZE];
		TPM2B_MAX_NV_BUFFER iv;

		memset(init, 0, SHA256_DIGEST_SIZE);
		memcpy(iv.b.buffer, init, SHA256_DIGEST_SIZE);
		iv.b.size = SHA256_DIGEST_SIZE;

		// calculate expected NV PCR value
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, init, SHA256_DIGEST_SIZE);
		SHA256_Update(&sha256, init, SHA256_DIGEST_SIZE);
		SHA256_Final(mnvpcr.val, &sha256);

		/**
		 * http://proverAddress:port/api/pcr
		 */
		// placeholders for parsed JSON response
		vector<unsigned char> signatureStr;
		vector<unsigned char> certifyInfoStr;

		// marshal policy digest into char vector
		uint16_t written = 0;
		unsigned char *buffer = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer,
					&written,
					&policyDigest,
					(MarshalFunction_t)TSS_TPM2B_DIGEST_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> policyDigestStr;
		for (int i = 0; i < written; i++) {
			policyDigestStr.push_back(buffer[i]);
		}

		// marshal object attributes into char vector
		unsigned char *buffer2 = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer2,
					&written,
					&objectAttributes,
					(MarshalFunction_t)TSS_TPMA_NV_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> objectAttributesStr;
		for (int i = 0; i < written; i++) {
			objectAttributesStr.push_back(buffer2[i]);
		}

		// marshal IV into char vector
		unsigned char *buffer3 = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer3,
					&written,
					&iv,
					(MarshalFunction_t)TSS_TPM2B_MAX_NV_BUFFER_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> ivStr;
		for (int i = 0; i < written; i++) {
			ivStr.push_back(buffer3[i]);
		}

		free(buffer);
		free(buffer2);
		free(buffer3);

		// create the JSON object
		json::value jsonObject;
		jsonObject[U("pcrIdx")]           = json::value::number(pcrIdx);
		jsonObject[U("nv")]               = json::value::boolean(nv);
		jsonObject[U("policyDigest")]     = json::value::string(U(utility::conversions::to_base64(policyDigestStr)));
		jsonObject[U("objectAttributes")] = json::value::string(U(utility::conversions::to_base64(objectAttributesStr)));
		jsonObject[U("iv")]               = json::value::string(U(utility::conversions::to_base64(ivStr)));

		// mock the request
		auto postJson = http_client(url)
			.request(methods::POST,
				uri_builder().append_path(U("pcr")).to_string(),
				jsonObject.serialize(), U("application/json"))
			.then([this](http_response response) {
				if (verbose) ucout << response.to_string() << endl;
				if (response.status_code() != status_codes::Created) {
					throw std::runtime_error("Returned " + std::to_string(response.status_code()));
				}

				return response.extract_json();
			})
			.then([&signatureStr, &certifyInfoStr](json::value jsonResObject) {

				// extract and decode data from JSON object
				utility::string_t signatureBase64   = jsonResObject[U("signature")].as_string();
				utility::string_t certifyInfoBase64 = jsonResObject[U("certifyInfo")].as_string();
				signatureStr   = utility::conversions::from_base64(signatureBase64);
				certifyInfoStr = utility::conversions::from_base64(certifyInfoBase64);
			});
	
		// send the request
		try {
			postJson.wait();
		} catch (const std::exception &e) {
			printf("[-] An error occured in %s::%s: %s\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, e.what());
			return false;
		}

		// unmarshal signature
		TPMT_SIGNATURE signature;
		BYTE*    tmpBuffer = &signatureStr[0];
		uint32_t tmpSize   = signatureStr.size();
		prettyRC(TSS_TPMT_SIGNATURE_Unmarshalu(&signature, 
					&tmpBuffer, 
					&tmpSize,
					YES), 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

		// unmarshal certifyInfo
		TPM2B_ATTEST certifyInfo;
		tmpBuffer = &certifyInfoStr[0];
		tmpSize   = certifyInfoStr.size();
		prettyRC(TSS_TPM2B_ATTEST_Unmarshalu(&certifyInfo, 
					&tmpBuffer, 
					&tmpSize), 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

		// the expected name
		TPMS_NV_PUBLIC expected;
		expected.attributes     = objectAttributes;
		expected.attributes.val = expected.attributes.val | TPMA_NVA_WRITTEN;
		expected.authPolicy     = policyDigest;
		expected.dataSize       = SHA256_DIGEST_SIZE;
		expected.nameAlg        = TPM_ALG_SHA256;
		expected.nvIndex        = pcrIdx;

		if (!this->verifyNvPcrCreation(
					expected, 
					signature, 
					certifyInfo, 
					this->mVmSigningKeyPublic, 
					mnvpcr, 
					&mnvpcr.name)) return false;
		this->mNVPCRs.push_back(mnvpcr);
	} 
	else {
		int mPCRidx = -1;
		for (auto it = this->mPCRs.begin(); it != this->mPCRs.end(); ++it) {
			if (it->idx == pcrIdx) {
				mPCRidx = std::distance(this->mPCRs.begin(), it);
				break;
			}
		}
		if (mPCRidx == -1) {
			printf("[-] An error occured in %s::%s: mPCR %d not found.\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return false;
		}

		/**
		 * http://proverAddress:port/api/pcr
		 */

		// create the JSON object
		json::value jsonObject;
		jsonObject[U("pcrIdx")] = json::value::number(pcrIdx);
		jsonObject[U("nv")]     = json::value::boolean(nv);

		// mock the request
		auto postJson = http_client(url)
			.request(methods::POST,
				uri_builder().append_path(U("pcr")).to_string(),
				jsonObject.serialize(), U("application/json"))
			.then([this](http_response response) {
				if (verbose) ucout << response.to_string() << endl;
				if (response.status_code() != status_codes::Created) {
					throw std::runtime_error("Returned " + std::to_string(response.status_code()));
				}
			});
	
		// send the request
		try {
			postJson.wait();
		} catch (const std::exception &e) {
			printf("[-] An error occured in %s::%s: %s\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, e.what());
			return false;
		}

		this->mPCRs.at(mPCRidx).active = true;
	}

	return true;
}

bool Orchestrator::delPcr(utility::string_t url, const UINT32 pcrIdx, const bool nv) {
	if (nv) {
		int mNVPCRidx = -1;
		for (auto it = this->mNVPCRs.begin(); it != this->mNVPCRs.end(); ++it) {
			if (it->idx == pcrIdx) {
				mNVPCRidx = std::distance(this->mNVPCRs.begin(), it);
				break;
			}
		}

        TPM2B_NAME nvName;
		if (mNVPCRidx == -1) {
			printf("[-] An error occured in %s::%s: mNVPCR %d not found for container ID.\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return false;
		} else {
			nvName = this->mNVPCRs.at(mNVPCRidx).name;
			this->mNVPCRs.erase(this->mNVPCRs.begin() + mNVPCRidx);
		}

		/**
		 * http://proverAddress:port/api/initRemNvPcr
		 */
		// placeholders for parsed JSON response
		vector<unsigned char> nonceTPMStr;

		// mock the request to start a remote authorization session and retrieve the session's nonceTPM
		auto post = http_client(url)
			.request(methods::POST,
				uri_builder().append_path(U("initRemNvPcr")).to_string())
			.then([this](http_response response) {
				if (verbose) ucout << response.to_string() << endl;
				if (response.status_code() != status_codes::OK) {
					throw std::runtime_error("Returned " + std::to_string(response.status_code()));
				}

				return response.extract_json();
			})
			.then([&nonceTPMStr](json::value jsonResObject) {

				// extract and decode data from JSON object
				utility::string_t nonceTPMBase64 = jsonResObject[U("nonceTPM")].as_string();
				nonceTPMStr = utility::conversions::from_base64(nonceTPMBase64);
			});
	
		// send the request
		try {
			post.wait();
		} catch (const std::exception &e) {
			printf("[-] An error occured in %s::%s: %s\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, e.what());
			return false;
		}

		// unmarshal nonceTPM
		TPM2B_NONCE nonceTPM;
		BYTE*    tmpBuffer = &nonceTPMStr[0];
		uint32_t tmpSize   = nonceTPMStr.size();
		prettyRC(TSS_TPM2B_NONCE_Unmarshalu(&nonceTPM, 
					&tmpBuffer, 
					&tmpSize), 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

		unsigned char ccPolicyNvUndefineSpecial[4] = {0x00, 0x00 ,0x01, 0x1f}; // TPM_CC_NV_UndefineSpaceSpecial
		unsigned char platform[sizeof(TPM_HANDLE)]; // platform handle
		platform[3] = (TPM_RH_PLATFORM >>  0) & 0xff;
		platform[2] = (TPM_RH_PLATFORM >>  8) & 0xff;
		platform[1] = (TPM_RH_PLATFORM >> 16) & 0xff;
		platform[0] = (TPM_RH_PLATFORM >> 24) & 0xff;

		TPM2B_DIGEST cpHashA;
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, ccPolicyNvUndefineSpecial, 4);
		SHA256_Update(&sha256, nvName.b.buffer, nvName.b.size);
		SHA256_Update(&sha256, platform, sizeof(TPM_HANDLE));
		SHA256_Final(cpHashA.t.buffer, &sha256);
		cpHashA.t.size = SHA256_DIGEST_SIZE;

		PolicySigned_In in;
		in.nonceTPM         = nonceTPM;
		in.policyRef.b.size = 0;
		in.expiration       = 0;

		// calculate the digest from the 4 components according to the TPM spec Part 3.
		// aHash (authHash) = HauthAlg(nonceTPM || expiration || cpHashA || policyRef)	(13)
		TPM2B_DIGEST aHash;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, &in.nonceTPM.b.buffer, in.nonceTPM.b.size);
		SHA256_Update(&sha256, &in.expiration, sizeof(UINT32));
		SHA256_Update(&sha256, &cpHashA.b.buffer, SHA256_DIGEST_SIZE);
		SHA256_Update(&sha256, &in.policyRef.b.buffer, in.policyRef.b.size);
		SHA256_Final(aHash.t.buffer, &sha256);
		aHash.b.size = SHA256_DIGEST_SIZE;

		TPMT_SIGNATURE aHashSignature = sign(this->mCtx, &aHash, this->mPersistentSigningKeyHandle, nullptr, TPM_RS_PW, 0);

		/**
		 * Create the policy digest (PolicySigned).
		 */
		unsigned char ccPolicySigned[4] = {0x00, 0x00, 0x01, 0x60}; // TPM_CC_PolicySigned

		TPM2B_DIGEST policyDigest;
		policyDigest.b.size = SHA256_DIGEST_SIZE;

		memset(policyDigest.b.buffer, 0, SHA256_DIGEST_SIZE); // starts with zero digest

		// policyDigest' = H(policyDigest || CC || authName)
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, policyDigest.b.buffer, policyDigest.b.size);
		SHA256_Update(&sha256, ccPolicySigned, 4);
		SHA256_Update(&sha256, this->mSigningKeyName.b.buffer, this->mSigningKeyName.b.size);
		SHA256_Final(policyDigest.b.buffer, &sha256);

		// policyDigest' = H(policyDigest || ref)
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, policyDigest.b.buffer, policyDigest.b.size);
		SHA256_Final(policyDigest.b.buffer, &sha256);

		TPM2B_DIGEST policyDigestSigned; // H(policyDigest || ref)
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, policyDigest.t.buffer, SHA256_DIGEST_SIZE);
		SHA256_Final(policyDigestSigned.t.buffer, &sha256);
		policyDigestSigned.b.size = SHA256_DIGEST_SIZE;

		TPMT_SIGNATURE policyDigestSignature = sign(this->mCtx, &policyDigestSigned, this->mPersistentSigningKeyHandle, nullptr, TPM_RS_PW, 0);

		/**
		 * http://proverAddress:port/api/pcr
		 */
		// marshal cpHashA into char vector
		uint16_t written = 0;
		unsigned char *buffer = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer,
					&written,
					&cpHashA,
					(MarshalFunction_t)TSS_TPM2B_DIGEST_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> cpHashAStr;
		for (int i = 0; i < written; i++) {
			cpHashAStr.push_back(buffer[i]);
		}

		// marshal aHashSignature into char vector
		unsigned char *buffer2 = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer2,
					&written,
					&aHashSignature,
					(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> aHashSignatureStr;
		for (int i = 0; i < written; i++) {
			aHashSignatureStr.push_back(buffer2[i]);
		}

		// marshal policy digest into char vector
		unsigned char *buffer3 = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer3,
					&written,
					&policyDigest,
					(MarshalFunction_t)TSS_TPM2B_DIGEST_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> policyDigestStr;
		for (int i = 0; i < written; i++) {
			policyDigestStr.push_back(buffer3[i]);
		}

		// marshal signed policy digest into char vector
		unsigned char *buffer4 = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer4,
					&written,
					&policyDigestSigned,
					(MarshalFunction_t)TSS_TPM2B_DIGEST_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> policyDigestSignedStr;
		for (int i = 0; i < written; i++) {
			policyDigestSignedStr.push_back(buffer4[i]);
		}

		// marshal policy digest signature into char vector
		unsigned char *buffer5 = NULL;
		prettyRC(TSS_Structure_Marshal(&buffer5,
					&written,
					&policyDigestSignature,
					(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		vector<unsigned char> policyDigestSignatureStr;
		for (int i = 0; i < written; i++) {
			policyDigestSignatureStr.push_back(buffer5[i]);
		}

		free(buffer);
		free(buffer2);
		free(buffer3);
		free(buffer4);
		free(buffer5);

		// create the JSON object
		json::value jsonObject;
		jsonObject[U("pcrIdx")]                = json::value::number(pcrIdx);
		jsonObject[U("nv")]                    = json::value::boolean(nv);
		jsonObject[U("cpHashA")]               = json::value::string(U(utility::conversions::to_base64(cpHashAStr)));
		jsonObject[U("aHashSignature")]        = json::value::string(U(utility::conversions::to_base64(aHashSignatureStr)));
		jsonObject[U("policyDigest")]          = json::value::string(U(utility::conversions::to_base64(policyDigestStr)));
		jsonObject[U("policyDigestSigned")]    = json::value::string(U(utility::conversions::to_base64(policyDigestSignedStr)));
		jsonObject[U("policyDigestSignature")] = json::value::string(U(utility::conversions::to_base64(policyDigestSignatureStr)));

		// mock the request
		auto delJson = http_client(url)
			.request(methods::DEL,
				uri_builder().append_path(U("pcr")).to_string(),
				jsonObject.serialize(), U("application/json"))
			.then([this](http_response response) {
				if (verbose) ucout << response.to_string() << endl;
				if (response.status_code() != status_codes::OK) {
					throw std::runtime_error("Returned " + std::to_string(response.status_code()));
				}

				return response.extract_json();
			});

		// send the request
		try {
			delJson.wait();
		} catch (const std::exception &e) {
			printf("[-] An error occured in %s::%s: %s\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, e.what());
			return false;
		}
	} 
	else {
		int mPCRidx = -1;
		for (auto it = this->mPCRs.begin(); it != this->mPCRs.end(); ++it) {
			if (it->idx == pcrIdx) {
				mPCRidx = std::distance(this->mPCRs.begin(), it);
				break;
			}
		}
		if (mPCRidx == -1) {
			printf("[-] An error occured in %s::%s: mPCR %d not found.\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return false;
		}

		/**
		 * http://proverAddress:port/api/pcr
		 */
		// create the JSON object
		json::value jsonObject;
		jsonObject[U("pcrIdx")] = json::value::number(pcrIdx);
		jsonObject[U("nv")]     = json::value::boolean(nv);

		// mock the request
		auto delJson = http_client(url)
			.request(methods::DEL,
				uri_builder().append_path(U("pcr")).to_string(),
				jsonObject.serialize(), U("application/json"))
			.then([this](http_response response) {
				if (verbose) ucout << response.to_string() << endl;
				if (response.status_code() != status_codes::OK) {
					throw std::runtime_error("Returned " + std::to_string(response.status_code()));
				}

				return response.extract_json();
			});

		// send the request
		try {
			delJson.wait();
		} catch (const std::exception &e) {
			printf("[-] An error occured in %s::%s: %s\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, e.what());
			return false;
		}

		this->mPCRs.at(mPCRidx).active = false; // make mPCR inactive (if we erase we also loose the currently trusted PCR value)
	}

    return true;
}

bool Orchestrator::attest(utility::string_t url) {
	// generate nonce
	unsigned char nonce[SHA256_DIGEST_SIZE];
	TPM2B_DIGEST  nonceDigest;

	RAND_bytes(nonce, SHA256_DIGEST_SIZE);
	memcpy(&nonceDigest.t.buffer, nonce, SHA256_DIGEST_SIZE);
	nonceDigest.t.size = SHA256_DIGEST_SIZE;

	/**
	 * http://proverAddress:port/api/attest
	 */
	// placeholders for parsed JSON response
	vector<unsigned char> signatureStr;

	// marshal policy digest into char vector
    uint16_t written = 0;
    unsigned char *buffer = NULL;
	prettyRC(TSS_Structure_Marshal(&buffer,
				&written,
				&nonceDigest,
				(MarshalFunction_t)TSS_TPM2B_DIGEST_Marshalu),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	vector<unsigned char> nonceDigestStr;
	for (int i = 0; i < written; i++) {
		nonceDigestStr.push_back(buffer[i]);
	}

	free(buffer);

	// create the JSON object containing the key creation template
	json::value jsonObject;
	jsonObject[U("nonceDigest")] = json::value::string(U(utility::conversions::to_base64(nonceDigestStr)));

	// mock the request
	auto postJson = http_client(url)
		.request(methods::POST,
			uri_builder().append_path(U("attest")).to_string(),
			jsonObject.serialize(), U("application/json"))
		.then([this](http_response response) {
			if (verbose) ucout << response.to_string() << endl;
			if (response.status_code() != status_codes::OK) {
				throw std::runtime_error("Returned " + std::to_string(response.status_code()));
			}

			return response.extract_json();
		})
		.then([&signatureStr](json::value jsonResObject) {

	        // extract and decode data from JSON object
			utility::string_t signatureBase64 = jsonResObject[U("signature")].as_string();
			signatureStr = utility::conversions::from_base64(signatureBase64);
		});
 
	// send the request
	try {
		postJson.wait();
	} catch (const std::exception &e) {
		printf("[-] An error occured in %s::%s: %s\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, e.what());
		return false;
	}

	// unmarshal signature
	TPMT_SIGNATURE signature;
	BYTE*    tmpBuffer = &signatureStr[0];
	uint32_t tmpSize   = signatureStr.size();
	prettyRC(TSS_TPMT_SIGNATURE_Unmarshalu(&signature, 
				&tmpBuffer, 
				&tmpSize,
				YES), 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

#ifdef HIGHLEVELTIMINGS
    auto t1 = Clock::now();
#endif

	// verify signature
	EVP_PKEY* containerpk_evp = nullptr;
	TPM_RC rc = prettyRC(convertEcPublicToEvpPubKey(&containerpk_evp, &this->mContainerAkPublic.publicArea.unique.ecc),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	if (rc != 0) {
		this->mTrustState = 0;
		return false;
	}
	rc = prettyRC(verifyEcSignatureFromEvpPubKey(nonce, SHA256_DIGEST_SIZE, &signature, containerpk_evp),
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
	if (rc != 0) {
		this->mTrustState = 0;
		return false;
	}

#ifdef HIGHLEVELTIMINGS
    auto t2 = Clock::now();
    writeTiming("verifyAttestSignature", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return true;
}

bool Orchestrator::verifyAttestationKeyCreation(TPMT_SIGNATURE signature, 
				TPM2B_ATTEST       certifyInfo,
				const TPM2B_PUBLIC akPub, 
				const TPM2B_PUBLIC signingKeyPub, 
				const TPM2B_DIGEST policyDigest,
				const TPMA_OBJECT  objectAttributes)
{
#ifdef HIGHLEVELTIMINGS
    auto t1 = Clock::now();
#endif

	TPMS_ATTEST attestData;
	BYTE*       tmpBuffer = certifyInfo.b.buffer;
	uint32_t    tmpSize   = certifyInfo.b.size;

	// unmarshal certifyInfo through tmpBuffer into attestData
	prettyRC(TSS_TPMS_ATTEST_Unmarshalu(&attestData, 
				&tmpBuffer, 
				&tmpSize), 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	if (attestData.magic != TPM_GENERATED_VALUE) {
		printf("[-] An error occured in %s::%s: object not created by TPM\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

	if (akPub.publicArea.objectAttributes.val 
		!= objectAttributes.val) {
		printf("[-] An error occured in %s::%s: objectAttributes mismatch\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

	// check if the AK is bound to the expected authorization policy digest
	if (memcmp(policyDigest.b.buffer, 
				akPub.publicArea.authPolicy.b.buffer, 
				policyDigest.b.size) != 0) {
		printf("[-] An error occured in %s::%s: policyDigest mismatch\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

	// calculate name from public area
	TPM2B_NAME objectName = getNameFromPublic(&akPub.publicArea, nullptr);

	// check if name of object is reflected in the attestation key's certificate
	if (memcmp(attestData.attested.creation.objectName.b.buffer, 
				objectName.b.buffer, 
				SHA256_DIGEST_SIZE + 2) != 0) {
		printf("[-] An error occured in %s::%s: objectName mismatch\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

	TPMT_HA tmpHashAgile;	
	tmpHashAgile.hashAlg = akPub.publicArea.nameAlg;
	prettyRC(TSS_Hash_Generate(&tmpHashAgile, 
				certifyInfo.b.size, 
				certifyInfo.b.buffer, 0, nullptr),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	EVP_PKEY* evpPkey = nullptr;
	convertEcPublicToEvpPubKey(&evpPkey, &signingKeyPub.publicArea.unique.ecc);

	// check if the signature over certifyInfo is legitimate
	if (verifyEcSignatureFromEvpPubKey((unsigned char*)&tmpHashAgile.digest, 
				TSS_GetDigestSize(TPM_ALG_SHA256), 
				&signature, 
				evpPkey) != 0) {
		printf("[-] An error occured in %s::%s: illegitimate signature\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

#ifdef HIGHLEVELTIMINGS
    auto t2 = Clock::now();
    writeTiming(__func__, (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return TRUE;
}

bool Orchestrator::verifyNvPcrCreation(const TPMS_NV_PUBLIC expected,
				TPMT_SIGNATURE     signature, 
				TPM2B_ATTEST       certifyInfo, 
				const TPM2B_PUBLIC signingKeyPublic,
				const mNVPCR       mnvpcr,
				TPM2B_NAME*        name)
{
#ifdef HIGHLEVELTIMINGS
    auto t1 = Clock::now();
#endif

	TPMS_ATTEST attestData;
	BYTE*       tmpBuffer = certifyInfo.b.buffer;
	uint32_t    tmpSize   = certifyInfo.b.size;

	// unmarshal certifyInfo through tmpBuffer into attestData
	prettyRC(TSS_TPMS_ATTEST_Unmarshalu(&attestData, 
				&tmpBuffer, 
				&tmpSize),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	if (attestData.magic != TPM_GENERATED_VALUE) {
		printf("[-] An error occured in %s::%s: object not created by TPM\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

	if (memcmp(attestData.attested.nv.nvContents.b.buffer, mnvpcr.val, 
		SHA256_DIGEST_SIZE) != 0) {
		printf("[-] An error occured in %s::%s: NV PCR contents mismatch\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;		
	}

	// compute expected name
	*name = getNameFromPublic(nullptr, &expected);

	// check if name of object is same in certificate and NV public section
	if (memcmp(name->b.buffer, 
				attestData.attested.creation.objectName.b.buffer, 
				SHA256_DIGEST_SIZE + 2) != 0) {
		printf("[-] An error occured in %s::%s: objectName mismatch\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

	TPMT_HA tmpHashAgile;
	tmpHashAgile.hashAlg = expected.nameAlg;
	prettyRC(TSS_Hash_Generate(&tmpHashAgile, 
				certifyInfo.b.size, 
				certifyInfo.b.buffer, 0, nullptr),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	EVP_PKEY* evpPkey = nullptr;
	convertEcPublicToEvpPubKey(&evpPkey, &signingKeyPublic.publicArea.unique.ecc);

	// check if the signature over certifyInfo is legitimate
	if (verifyEcSignatureFromEvpPubKey((unsigned char*)&tmpHashAgile.digest, 
				TSS_GetDigestSize(TPM_ALG_SHA256), 
				&signature, 
				evpPkey) != 0) {
		printf("[-] An error occured in %s::%s: illegitimate signature\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

#ifdef HIGHLEVELTIMINGS
    auto t2 = Clock::now();
    writeTiming(__func__, (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return TRUE;
}

bool Orchestrator::verifyAuditSessionExtend(TPMT_SIGNATURE signature, 
				TPM2B_ATTEST       auditInfo,
				const TPM2B_PUBLIC signingKeyPub,
				const UINT32       pcrIdx,
				const bool         nv,
				unsigned char*     authenticUpdateDigest)
{
#ifdef HIGHLEVELTIMINGS
    auto t1 = Clock::now();
#endif

	TPM2B_DIGEST cpHash;      // cpHash = H(CC [ || authName1 [ || authName2 [ || authName 3 ]]] [ || parameters])
	TPM2B_DIGEST rpHash;      // rpHash = H(responseCode || commandCode || parameters)
	TPM2B_DIGEST auditDigest; // auditDigestnew = H(auditDigestOld || cpHash || rpHash)

	// comand codes for when we request to extend a NV or normal PCR
	unsigned char ccPcrExtend[4] = {0x00, 0x00 ,0x01, 0x82}; // TPM_CC_PCR_Extend
	unsigned char ccNvExtend[4]  = {0x00, 0x00 ,0x01, 0x36}; // TPM_CC_NV_Extend
	
	// require a successful execution of the command
	unsigned char responseCode[4] = {0x00, 0x00, 0x00, 0x00}; // TPM_RC_SUCCESS
	
	SHA256_CTX sha256;

	/**
	 * PHASE: compute cpHash
	 */
	if (nv) {
		int mNVPCRidx = -1;
		for (auto it = this->mNVPCRs.begin(); it != this->mNVPCRs.end(); ++it) {
			if (it->idx == pcrIdx) {
				mNVPCRidx = std::distance(this->mNVPCRs.begin(), it);
				break;
			}
		}
		if (mNVPCRidx == -1) {
			printf("[-] An error occured in %s::%s: mNVPCR %d not found.\n", 
					abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__, pcrIdx);
			return false;
		}

		// for NV_Extend, the parameters are: dataLength + digest
		unsigned char dataLength[2];
		unsigned char parameters[2 + SHA256_DIGEST_SIZE];
		dataLength[1] = (SHA256_DIGEST_SIZE >> 0) & 0xff;
		dataLength[0] = (SHA256_DIGEST_SIZE >> 8) & 0xff;
		memcpy(&parameters, dataLength, 2);
		memcpy(&parameters[2], authenticUpdateDigest, SHA256_DIGEST_SIZE);

		// compute the cpHash
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, ccNvExtend, 4);
		// NV index name twice since it is used for the authHandle and nvIndex
		SHA256_Update(&sha256, this->mNVPCRs.at(mNVPCRidx).name.b.buffer, this->mNVPCRs.at(mNVPCRidx).name.b.size);
		SHA256_Update(&sha256, this->mNVPCRs.at(mNVPCRidx).name.b.buffer, this->mNVPCRs.at(mNVPCRidx).name.b.size);
		SHA256_Update(&sha256, parameters, 2 + SHA256_DIGEST_SIZE);
		SHA256_Final(cpHash.b.buffer, &sha256);
	}
	else {
		unsigned char pcrHandleMarshalled[4]; // we only have one authName (the PCR handle)
		pcrHandleMarshalled[3] = (pcrIdx >>  0) & 0xff;
		pcrHandleMarshalled[2] = (pcrIdx >>  8) & 0xff;
		pcrHandleMarshalled[1] = (pcrIdx >> 16) & 0xff;
		pcrHandleMarshalled[0] = (pcrIdx >> 24) & 0xff;

		// session authHash
		UINT16 algId = TPM_ALG_SHA256;
		unsigned char algIdMarshalled[2];
		algIdMarshalled[1] = (algId >> 0) & 0xff;
		algIdMarshalled[0] = (algId >> 8) & 0xff;

		// for PCR_Extend, the parameters are: authName(s) + session authHash + digest
		unsigned char parameters[4 + 2 + SHA256_DIGEST_SIZE];
		memcpy(&parameters, pcrHandleMarshalled, 4);
		memcpy(&parameters[4], algIdMarshalled, 2);
		memcpy(&parameters[6], authenticUpdateDigest, SHA256_DIGEST_SIZE);

		// compute the cpHash
		SHA256_CTX sha256Ctx;
		SHA256_Init(&sha256Ctx);
		SHA256_Update(&sha256Ctx, ccPcrExtend, 4);
		SHA256_Update(&sha256Ctx, pcrHandleMarshalled, 4);
		SHA256_Update(&sha256Ctx, parameters, 4 + 2 + SHA256_DIGEST_SIZE);
		SHA256_Final(cpHash.b.buffer, &sha256Ctx);
	}

	cpHash.b.size = SHA256_DIGEST_SIZE;

	/**
	 * PHASE: compute rpHash
	 */
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, responseCode, 4);
	SHA256_Update(&sha256, nv ? ccNvExtend : ccPcrExtend, 4);
	SHA256_Final(rpHash.b.buffer, &sha256);
	rpHash.b.size = SHA256_DIGEST_SIZE;

	// compute the expected audit digest
	memset(auditDigest.b.buffer, 0, SHA256_DIGEST_SIZE); // original audit digest is always 0
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, auditDigest.b.buffer, SHA256_DIGEST_SIZE);
	SHA256_Update(&sha256, cpHash.b.buffer, SHA256_DIGEST_SIZE);
	SHA256_Update(&sha256, rpHash.b.buffer, SHA256_DIGEST_SIZE);
	SHA256_Final(auditDigest.b.buffer, &sha256);
	auditDigest.b.size = SHA256_DIGEST_SIZE;

	// unmarshal the audit digest from the actual session
	TPMS_ATTEST attestData;
	BYTE*       tmpBuffer = auditInfo.b.buffer;
	uint32_t    tmpSize   = auditInfo.b.size;
	prettyRC(TSS_TPMS_ATTEST_Unmarshalu(&attestData, 
				&tmpBuffer, 
				&tmpSize),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	// verify that the audit digests match
	if (memcmp(auditDigest.b.buffer, 
				attestData.attested.sessionAudit.sessionDigest.b.buffer, 
				auditDigest.b.size) != 0) {
		printf("[-] An error occured in %s::%s: audit digest mismatch\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

	TPMT_HA tmpHashAgile;
	tmpHashAgile.hashAlg = signingKeyPub.publicArea.nameAlg;
	prettyRC(TSS_Hash_Generate(&tmpHashAgile, 
				auditInfo.b.size, 
				auditInfo.b.buffer, 0, nullptr),
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

	EVP_PKEY* evpPkey = nullptr;
	convertEcPublicToEvpPubKey(&evpPkey, &signingKeyPub.publicArea.unique.ecc);

	// check if the signature over auditInfo is legitimate
	if (verifyEcSignatureFromEvpPubKey((unsigned char*)&tmpHashAgile.digest, 
				TSS_GetDigestSize(TPM_ALG_SHA256), 
				&signature, 
				evpPkey) != 0) {
		printf("[-] An error occured in %s::%s: illegitimate signature\n", 
				abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);
		return false;
	}

#ifdef HIGHLEVELTIMINGS
    auto t2 = Clock::now();
    writeTiming(__func__, (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return true;
}

TPM2B_NAME Orchestrator::getNameFromPublic(const TPMT_PUBLIC* publicKey, const TPMS_NV_PUBLIC* publicNv) {
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
