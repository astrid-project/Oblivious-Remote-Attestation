#include "handler.h"

handler::handler(utility::string_t url, const bool verbose) : listener(url), verbose(verbose) {
    listener.support(methods::GET, std::bind(&handler::handle_get, this, std::placeholders::_1));
    listener.support(methods::POST, std::bind(&handler::handle_post, this, std::placeholders::_1));
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

    auto path = uri::split_path(uri::decode(message.relative_uri().path()));

    if (path[0] == "enroll") {

        // extract and decode data from JSON object
        utility::string_t url = temp.at(U("proverApi")).as_string();

        /* START OF demo variables */
        UINT32 pcr = 0x01001500;
        bool nv = true;
        // UINT32 pcr = 2;
        // bool nv = false;

        unsigned char updateDigest[SHA256_DIGEST_SIZE]; // digest over the new update
        unsigned char secretHmacKey[4] = {0x00, 0x00, 0x13, 0x37}; // shared HMAC key
        RAND_bytes(updateDigest, SHA256_DIGEST_SIZE); // simulate some arbitrary update
        /* END OF demo variables */

        if (this->orc->deploy(url)) {
            if (this->verbose) printf("Succesfull AK creation verification of container at %s\n", url.c_str());
        } else {
            if (this->verbose) printf("Failed to securely enroll container at %s\n", url.c_str());
            response[U("msg")] = json::value::string(U("Failed to establish AK on prover"));
            message.reply(status_codes::InternalError, response);
            return;
        }
        if (this->orc->addPcr(url, pcr, nv)) {
            if (nv) {
                if (this->verbose) printf("Added NV-based PCR %d to container at %s\n", pcr, url.c_str());
            } else {
                if (this->verbose) printf("Added PCR %d to container at %s\n", pcr, url.c_str());
            }
        } else {
            if (nv) {
                if (this->verbose) printf("Failed to add NV-based PCR to prover");
                response[U("msg")] = json::value::string(U("Failed to add NV-based PCR to prover"));
            } else {
                if (this->verbose) printf("Failed to add PCR to prover");
                response[U("msg")] = json::value::string(U("Failed to add PCR to prover"));
            }
            message.reply(status_codes::InternalError, response);
            return;
        }

        if (this->orc->update(url, pcr, nv, updateDigest, secretHmacKey, 4)) {
            if (this->verbose) printf("Succesfully updated container at %s\n", url.c_str());
        } else {
            if (this->verbose) printf("Failed to update container at %s\n", url.c_str());
            response[U("msg")] = json::value::string(U("Failed to update prover"));
            message.reply(status_codes::InternalError, response);

            if (this->orc->delPcr(url, pcr, nv)) {
                if (nv) {
                    if (this->verbose) printf("Removed NV-based PCR %d from container at %s\n", pcr, url.c_str());
                } else {
                    if (this->verbose) printf("Removed PCR %d from container at %s\n", pcr, url.c_str());
                }
            } else {
                if (nv) {
                    if (this->verbose) printf("Failed to remove NV-based PCR %d from container at %s\n", pcr, url.c_str());
                } else {
                    if (this->verbose) printf("Failed to remove PCR %d from container at %s\n", pcr, url.c_str());
                }
            }
            return;
        }

        // Oblivious Remote Attestation (ORA), i.e., verification with only knowledge about the prover's certified public key
        if (this->orc->attest(url)) {
            if (this->verbose) printf("Container at %s is in a correct state\n", url.c_str());
        } else {
            if (this->verbose) printf("Container at %s is in an incorrect state\n", url.c_str());
            response[U("msg")] = json::value::string(U("Attestation failed"));
            message.reply(status_codes::InternalError, response);

            if (this->orc->delPcr(url, pcr, nv)) {
                if (nv) {
                    if (this->verbose) printf("Removed NV-based PCR %d from container at %s\n", pcr, url.c_str());
                } else {
                    if (this->verbose) printf("Removed PCR %d from container at %s\n", pcr, url.c_str());
                }
            } else {
                if (nv) {
                    if (this->verbose) printf("Failed to remove NV-based PCR %d from container at %s\n", pcr, url.c_str());
                } else {
                    if (this->verbose) printf("Failed to remove PCR %d from container at %s\n", pcr, url.c_str());
                }
            }
            return;
        }

        if (this->verbose) printf("Securely enrolled container at %s\n", url.c_str());
        response[U("msg")] = json::value::string(U("Enrolled"));
        message.reply(status_codes::OK, response);

        if (this->orc->delPcr(url, pcr, nv)) {
            if (nv) {
                if (this->verbose) printf("Removed NV-based PCR %d from container at %s\n", pcr, url.c_str());
            } else {
                if (this->verbose) printf("Removed PCR %d from container at %s\n", pcr, url.c_str());
            }
        } else {
            if (nv) {
                if (this->verbose) printf("Failed to remove NV-based PCR %d from container at %s\n", pcr, url.c_str());
            } else {
                if (this->verbose) printf("Failed to remove PCR %d from container at %s\n", pcr, url.c_str());
            }
        }
    } else {
        message.reply(status_codes::NotFound);
    }
};
