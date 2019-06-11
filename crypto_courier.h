#pragma once

#include "cp_connection.h"
#include <librlcom/courier.h>

namespace rrl::rlc {

    class CryptoCourier final : public Courier {
    public:
        CryptoCourier(Connection &conn);

        virtual msg::Any receive() override;
        virtual void send(msg::Any const& msg) override;

        void init_as_client(Bytes const &server_pk_modulus, Bytes const &server_pk_exponent);
        void init_as_server();

    private:
        CPConnection conn_;
    };


}

