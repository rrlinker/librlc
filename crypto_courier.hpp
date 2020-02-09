#pragma once

#include "crypto_connection.hpp"
#include <librrlcom/courier.hpp>

namespace rrl::rlc {

    class CryptoCourier final : public Courier {
    public:
        CryptoCourier(Connection &conn);
        virtual ~CryptoCourier() noexcept(false);

        virtual msg::Any receive() override;
        virtual void send(msg::Any const &msg) override;

        void init_as_client(RSA const &rsa);
        void init_as_server(RSA const &rsa);
        void init_with_key(Bytes const &key);

    private:
        CryptoConnection conn_;
    };


}

