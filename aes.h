#pragma once

#include "bytes.h"
#include "operation.h"
#include "mode.h"

namespace rrl::rlc {

    class AES {
    public:
        AES(Bytes const &key);

        Bytes decrypt_ecb(Bytes const &buffer) const;
        Bytes encrypt_ecb(Bytes const &buffer) const;
        Bytes decrypt_cbc(Bytes const &buffer, Bytes const &iv) const;
        Bytes encrypt_cbc(Bytes const &buffer, Bytes const &iv) const;
        Bytes crypt(Bytes const &buffer, Operation operation, Bytes const &iv) const;

        Bytes const key;

    private:
        void const* get_cipher(Mode mode) const;
        void validate_alignment(Bytes const &buffer) const;
    };

}
