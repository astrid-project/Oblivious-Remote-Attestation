#include <csignal>
#include <thread>

#include "stdafx.h"
#include "handler.h"

using namespace std;
using namespace web;
using namespace http;
using namespace utility;
using namespace http::experimental::listener;

std::unique_ptr<handler> httpHandler;

void start(const string_t &address, const bool verbose, unsigned char* secretHmacKey, const int keyLen) {
    uri_builder uri(address);
    auto addr = uri.to_uri().to_string();
    httpHandler = std::unique_ptr<handler>(new handler(addr, verbose, secretHmacKey, keyLen));
    httpHandler->open().wait();
    ucout << utility::string_t(U("Listening for requests at: ")) << addr << std::endl;
}

void on_shutdown(int signal) {
    try {
        httpHandler->close().wait();
    } catch(...) { }
    std::_Exit(0);
}

static void printUsage(void);

int main(int argc, char *argv[]) {
    utility::string_t address;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-api") == 0) {
            i++;
            if (i < argc) {
                address = argv[i];
            } else {
                printf("Missing argument for -api\n");
                printUsage();
            }
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
        }
    }
    if (address.empty()) {
        printf("REST API address to listen on is missing\n");
        printUsage();
    }

    unsigned char secretHmacKey[4] = {0x00, 0x00, 0x13, 0x37}; // shared HMAC key to authenticate measurements

    start(address, verbose, secretHmacKey, 4);
    std::signal(SIGTERM, on_shutdown);
    std::signal(SIGKILL, on_shutdown);
    while(true);
	return 0;
}

static void printUsage(void) {
    printf("\n");
    printf("Prover process\n");
    printf("\n");
    printf("\t-api\tlocal REST API address to listen on\n");
    printf("\t\thttp://0.0.0.0:8080/api\n");
    printf("\t-v\tverbose\n");
    exit(1);
}
