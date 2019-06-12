#pragma once

#include "cp_connection.h"
#include <librlcom/courier.h>

namespace rrl::rlc {

    class CryptoCourier final : public Courier {
    public:
        CryptoCourier(Connection &conn);

        virtual msg::Any receive() override;
        virtual void send(msg::Any const &msg) override;

        void init_as_client(RSA const &rsa);
        void init_as_server(RSA const &rsa);

    private:
        CPConnection conn_;
    };


}

