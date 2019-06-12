#pragma once

#include "bytes.h"

namespace rrl::rlc {

    class RSA final {
    public:
        enum Mode {
            None = 0,
            Public = 1,
            Private = 2,
        };
        enum ModeBoth {
            Both = 3,
        };

        RSA(unsigned bits, Bytes const &public_exponent);
        RSA(Mode mode, Bytes const &modulus, Bytes const &exponent);
        RSA(ModeBoth mode, Bytes const &modulus, Bytes const &public_exponent, Bytes const &private_exponent);
        ~RSA();

        RSA(RSA &&other) = default;
        RSA& operator=(RSA &&rhs) = default;

        RSA(RSA const& other) = delete;
        RSA& operator=(RSA const &rhs) = delete;

        Bytes encrypt(Bytes const &bytes) const;
        Bytes decrypt(Bytes const &bytes) const;

        Bytes get_modulus() const;
        Bytes get_public_exponent() const;
        Bytes get_private_exponent() const;

        int const mode;

    private:
        void free();

        void *rsa_;
    };

}
