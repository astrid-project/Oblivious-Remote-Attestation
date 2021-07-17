#ifndef GCC_HANDLER_H
#define GCC_HANDLER_H

#include "vm.h"

class handler {
    public:
        handler() = default;
        explicit handler(utility::string_t url, const bool verbose, unsigned char* secretHmacKey, const int keyLen);
        virtual ~handler() = default;
        pplx::task<void> open() { 
            prettyRC(TSS_SetProperty(nullptr, TPM_TRACE_LEVEL, "1"), __func__);
            prettyRC(TSS_Create(&this->mCtx), __func__);
            boot(this->mCtx);
            this->vm = std::unique_ptr<VM>(new VM(this->mCtx, this->verbose, this->secretHmacKey, this->keyLen));
            return this->listener.open();
        }
        pplx::task<void> close() {
            TSS_Delete(this->mCtx);
            return this->listener.close();
        }

    private:
        void handle_get(http_request message);
        void handle_post(http_request message);
        void handle_delete(http_request message);

        http_listener listener;
        TSS_CONTEXT* mCtx = nullptr;
        std::unique_ptr<VM> vm;
        bool verbose;
        unsigned char* secretHmacKey;
        const int keyLen;
};

#endif //GCC_HANDLER_H
