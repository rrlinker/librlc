#pragma once

#include "bytes.h"

namespace rrl::rlc {

    class RSA final {
    public:
        RSA(unsigned bits, Bytes const& public_exponent);
        RSA(Bytes const& modulus, Bytes const& exponent);
        ~RSA();

        RSA(RSA&& other) = default;
        RSA& operator=(RSA&& rhs) = default;

        RSA(RSA const& other) = delete;
        RSA& operator=(RSA const& rhs) = delete;

        Bytes encrypt(Bytes const& bytes) const;
        Bytes decrypt(Bytes const& bytes) const;

        Bytes get_modulus() const;
        Bytes get_public_exponent() const;
        Bytes get_private_exponent() const;

    private:
        void free();

        void* rsa_;
    };

}

