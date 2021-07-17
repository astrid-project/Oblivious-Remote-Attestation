#ifndef GCC_HANDLER_H
#define GCC_HANDLER_H

#include "orchestrator.h"

using namespace http::experimental::listener;

class handler {
    public:
        handler() = default;
        explicit handler(utility::string_t url, const bool verbose);
        virtual ~handler() = default;
        pplx::task<void> open() { 
            prettyRC(TSS_SetProperty(nullptr, TPM_TRACE_LEVEL, "1"), __func__);
            prettyRC(TSS_Create(&this->mCtx), __func__);
            boot(this->mCtx);
            this->orc = std::unique_ptr<Orchestrator>(new Orchestrator(this->mCtx, this->verbose));
            return this->listener.open();
        }
        pplx::task<void> close() {
            TSS_Delete(this->mCtx);
            return this->listener.close();
        }

    private:
        void handle_get(http_request message);
        void handle_post(http_request message);

        http_listener listener;
        TSS_CONTEXT* mCtx = nullptr;
        std::unique_ptr<Orchestrator> orc;
        bool verbose;
};

#endif //GCC_HANDLER_H
