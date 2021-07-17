#include "handler.h"

handler::handler(utility::string_t url, const bool verbose, unsigned char* secretHmacKey, const int keyLen) 
    : listener(url), verbose(verbose), secretHmacKey(secretHmacKey), keyLen(keyLen) {
    listener.support(methods::GET, std::bind(&handler::handle_get, this, std::placeholders::_1));
    listener.support(methods::POST, std::bind(&handler::handle_post, this, std::placeholders::_1));
    listener.support(methods::DEL, std::bind(&handler::handle_delete, this, std::placeholders::_1));
}

void handler::handle_get(http_request message) {
    if (verbose) ucout << message.to_string() << endl;
    message.reply(status_codes::NotFound);
};

void handler::handle_post(http_request message) {
    if (verbose) ucout << message.to_string() << endl;

    // extract JSON object from request
    json::value temp;
    message.extract_json()
        .then([&temp](pplx::task<json::value> task) {
        temp = task.get();
    }).wait();

    json::value response;
    web::http::status_code sc;

    auto path = uri::split_path(uri::decode(message.relative_uri().path()));

    if (path[0] == "attestationKey") {

        // extract and decode data from JSON object
        utility::string_t policyDigestBase64     = temp.at(U("policyDigest")).as_string();
        utility::string_t objectAttributesBase64 = temp.at(U("objectAttributes")).as_string();
        vector<unsigned char> policyDigestStr     = utility::conversions::from_base64(policyDigestBase64);
        vector<unsigned char> objectAttributesStr = utility::conversions::from_base64(objectAttributesBase64);

        // unmarshal policy digest
        TPM2B_DIGEST policyDigest;
        BYTE*    tmpBuffer = &policyDigestStr[0];
        uint32_t tmpSize   = policyDigestStr.size();
        prettyRC(TSS_TPM2B_DIGEST_Unmarshalu(&policyDigest, 
                    &tmpBuffer, 
                    &tmpSize), 
                    abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

        // unmarshal object attributes
        TPMA_OBJECT objectAttributes;
        tmpBuffer = &objectAttributesStr[0];
        tmpSize   = objectAttributesStr.size();
        prettyRC(TSS_TPMA_OBJECT_Unmarshalu(&objectAttributes, 
                    &tmpBuffer, 
                    &tmpSize), 
                    abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

        // create the attestation key and generate a response
        sc = this->vm->createAttestationKey(&policyDigest, objectAttributes, response);

        message.reply(sc, response);
    } else if (path[0] == "pcr") {

        UINT32 pcrIdx = temp.at(U("pcrIdx")).as_integer();
        bool   nv     = temp.at(U("nv")).as_bool();

        if (nv) {
            // extract and decode data from JSON object
            utility::string_t policyDigestBase64     = temp.at(U("policyDigest")).as_string();
            utility::string_t objectAttributesBase64 = temp.at(U("objectAttributes")).as_string();
            utility::string_t ivBase64               = temp.at(U("iv")).as_string();
            vector<unsigned char> policyDigestStr     = utility::conversions::from_base64(policyDigestBase64);
            vector<unsigned char> objectAttributesStr = utility::conversions::from_base64(objectAttributesBase64);
            vector<unsigned char> ivStr               = utility::conversions::from_base64(ivBase64);

            // unmarshal policy digest
            TPM2B_DIGEST policyDigest;
            BYTE*    tmpBuffer = &policyDigestStr[0];
            uint32_t tmpSize   = policyDigestStr.size();
            prettyRC(TSS_TPM2B_DIGEST_Unmarshalu(&policyDigest, 
                        &tmpBuffer, 
                        &tmpSize), 
                        abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

            // unmarshal object attributes
            TPMA_NV objectAttributes;
            tmpBuffer = &objectAttributesStr[0];
            tmpSize   = objectAttributesStr.size();
            prettyRC(TSS_TPMA_NV_Unmarshalu(&objectAttributes, 
                        &tmpBuffer, 
                        &tmpSize), 
                        abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

            // unmarshal IV
            TPM2B_MAX_NV_BUFFER iv;
            tmpBuffer = &ivStr[0];
            tmpSize   = ivStr.size();
            prettyRC(TSS_TPM2B_MAX_NV_BUFFER_Unmarshalu(&iv, 
                        &tmpBuffer, 
                        &tmpSize), 
                        abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

            // add the NV-based PCR and generate a response
            sc = this->vm->addPcr(pcrIdx, nv, &objectAttributes, &policyDigest, &iv, response);
        } else {
            // add the PCR and generate a response
            sc = this->vm->addPcr(pcrIdx, nv, nullptr, nullptr, nullptr, response);
        }

        message.reply(sc, response);
    } else if (path[0] == "update") {

        UINT32 pcrIdx = temp.at(U("pcrIdx")).as_integer();
        bool   nv     = temp.at(U("nv")).as_bool();

        // extract and decode data from JSON object
        utility::string_t policyDigestBase64          = temp.at(U("policyDigest")).as_string();
        utility::string_t policyDigestSignedBase64    = temp.at(U("policyDigestSigned")).as_string();
        utility::string_t policyDigestSignatureBase64 = temp.at(U("policyDigestSignature")).as_string();
        utility::string_t tracerOutputBase64          = temp.at(U("tracerOutput")).as_string();
        vector<unsigned char> policyDigestStr          = utility::conversions::from_base64(policyDigestBase64);
        vector<unsigned char> policyDigestSignedStr    = utility::conversions::from_base64(policyDigestSignedBase64);
        vector<unsigned char> policyDigestSignatureStr = utility::conversions::from_base64(policyDigestSignatureBase64);
        vector<unsigned char> tracerOutputStr          = utility::conversions::from_base64(tracerOutputBase64);

        // unmarshal policy digest
        TPM2B_DIGEST policyDigest;
        BYTE*    tmpBuffer = &policyDigestStr[0];
        uint32_t tmpSize   = policyDigestStr.size();
        prettyRC(TSS_TPM2B_DIGEST_Unmarshalu(&policyDigest, 
                    &tmpBuffer, 
                    &tmpSize), 
                    abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

        // unmarshal signed policy digest
        TPM2B_DIGEST policyDigestSigned;
        tmpBuffer = &policyDigestSignedStr[0];
        tmpSize   = policyDigestSignedStr.size();
        prettyRC(TSS_TPM2B_DIGEST_Unmarshalu(&policyDigestSigned, 
                    &tmpBuffer, 
                    &tmpSize), 
                    abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

        // unmarshal policy digest signature
        TPMT_SIGNATURE policyDigestSignature;
        tmpBuffer = &policyDigestSignatureStr[0];
        tmpSize   = policyDigestSignatureStr.size();
        prettyRC(TSS_TPMT_SIGNATURE_Unmarshalu(&policyDigestSignature, 
                    &tmpBuffer, 
                    &tmpSize,
                    YES), 
                    abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

        // update and generate a response
        sc = this->vm->update(&policyDigest, &policyDigestSigned, &policyDigestSignature, pcrIdx, nv, &tracerOutputStr[0], response);

        message.reply(sc, response);
    } else if (path[0] == "attest") {

        // extract and decode data from JSON object
        utility::string_t nonceDigestBase64 = temp.at(U("nonceDigest")).as_string();
        vector<unsigned char> nonceDigestStr = utility::conversions::from_base64(nonceDigestBase64);

        // unmarshal nonce digest
        TPM2B_DIGEST nonceDigest;
        BYTE*    tmpBuffer = &nonceDigestStr[0];
        uint32_t tmpSize   = nonceDigestStr.size();
        prettyRC(TSS_TPM2B_DIGEST_Unmarshalu(&nonceDigest, 
                    &tmpBuffer, 
                    &tmpSize), 
                    abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

        // attest and generate a response
        sc = this->vm->attest(&nonceDigest, response);

        message.reply(sc, response);
    } else if (path[0] == "initRemNvPcr") {

        sc = this->vm->initRemNvPcr(response);
        message.reply(sc, response);
    } else {
        message.reply(status_codes::NotFound);
    }
};

void handler::handle_delete(http_request message) {
    if (verbose) ucout << message.to_string() << endl;

    // extract JSON object from request
    json::value temp;
    message.extract_json()
        .then([&temp](pplx::task<json::value> task) {
        temp = task.get();
    }).wait();

    json::value response;
    web::http::status_code sc;

    auto path = uri::split_path(uri::decode(message.relative_uri().path()));

    if (path[0] == "pcr") {

        UINT32 pcrIdx = temp.at(U("pcrIdx")).as_integer();
        bool   nv     = temp.at(U("nv")).as_bool();

        if (nv) {
            // extract and decode data from JSON object
            utility::string_t cpHashABase64               = temp.at(U("cpHashA")).as_string();
            utility::string_t aHashSignatureBase64        = temp.at(U("aHashSignature")).as_string();
            utility::string_t policyDigestBase64          = temp.at(U("policyDigest")).as_string();
            utility::string_t policyDigestSignedBase64    = temp.at(U("policyDigestSigned")).as_string();
            utility::string_t policyDigestSignatureBase64 = temp.at(U("policyDigestSignature")).as_string();
            vector<unsigned char> cpHashAStr               = utility::conversions::from_base64(cpHashABase64);
            vector<unsigned char> aHashSignatureStr        = utility::conversions::from_base64(aHashSignatureBase64);
            vector<unsigned char> policyDigestStr          = utility::conversions::from_base64(policyDigestBase64);
            vector<unsigned char> policyDigestSignedStr    = utility::conversions::from_base64(policyDigestSignedBase64);
            vector<unsigned char> policyDigestSignatureStr = utility::conversions::from_base64(policyDigestSignatureBase64);

            // unmarshal cpHashA
            TPM2B_DIGEST cpHashA;
            BYTE*    tmpBuffer = &cpHashAStr[0];
            uint32_t tmpSize   = cpHashAStr.size();
            prettyRC(TSS_TPM2B_DIGEST_Unmarshalu(&cpHashA, 
                        &tmpBuffer, 
                        &tmpSize), 
                        abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

            // unmarshal aHashSignature
            TPMT_SIGNATURE aHashSignature;
            tmpBuffer = &aHashSignatureStr[0];
            tmpSize   = aHashSignatureStr.size();
            prettyRC(TSS_TPMT_SIGNATURE_Unmarshalu(&aHashSignature, 
                        &tmpBuffer, 
                        &tmpSize,
                        YES), 
                        abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

            // unmarshal policy digest
            TPM2B_DIGEST policyDigest;
            tmpBuffer = &policyDigestStr[0];
            tmpSize   = policyDigestStr.size();
            prettyRC(TSS_TPM2B_DIGEST_Unmarshalu(&policyDigest, 
                        &tmpBuffer, 
                        &tmpSize), 
                        abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

            // unmarshal signed policy digest
            TPM2B_DIGEST policyDigestSigned;
            tmpBuffer = &policyDigestSignedStr[0];
            tmpSize   = policyDigestSignedStr.size();
            prettyRC(TSS_TPM2B_DIGEST_Unmarshalu(&policyDigestSigned, 
                        &tmpBuffer, 
                        &tmpSize), 
                        abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

            // unmarshal policy digest signature
            TPMT_SIGNATURE policyDigestSignature;
            tmpBuffer = &policyDigestSignatureStr[0];
            tmpSize   = policyDigestSignatureStr.size();
            prettyRC(TSS_TPMT_SIGNATURE_Unmarshalu(&policyDigestSignature, 
                        &tmpBuffer, 
                        &tmpSize,
                        YES), 
                        abi::__cxa_demangle(typeid(*this).name(), 0, 0, 0), __func__);

            // delete the NV-based PCR and generate a response
            sc = this->vm->remPcr(pcrIdx, nv, &cpHashA, &aHashSignature, &policyDigest, &policyDigestSigned, &policyDigestSignature, response);
        } else {
            // delete the PCR and generate a response
            sc = this->vm->remPcr(pcrIdx, nv, nullptr, nullptr, nullptr, nullptr, nullptr, response);
        }

        message.reply(sc, response);
    } else {
        message.reply(status_codes::NotFound);
    }
};
