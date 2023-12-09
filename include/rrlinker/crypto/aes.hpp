#pragma once

#include <rrlinker/crypto/bytes.hpp>
#include <rrlinker/crypto/operation.hpp>
#include <rrlinker/crypto/mode.hpp>

namespace rrl::rlc {

    class AES {
    public:
        enum KeySize {
            MinKeySize = 16,
            MedKeySize = 24,
            MaxKeySize = 32,
        };

        AES(Bytes const &key);

        AES(AES const &other);
        AES(AES &&other) noexcept;

        AES& operator=(AES const &rhs);
        AES& operator=(AES &&rhs) noexcept;

        Bytes decrypt_ecb(Bytes const &buffer) const;
        Bytes encrypt_ecb(Bytes const &buffer) const;
        Bytes decrypt_cbc(Bytes const &buffer, Bytes const &iv) const;
        Bytes encrypt_cbc(Bytes const &buffer, Bytes const &iv) const;
        Bytes crypt(Bytes const &buffer, Operation operation, Bytes const &iv) const;

        size_t key_size() const;

    private:
        void const* get_cipher(Mode mode) const;
        void validate_alignment(Bytes const &buffer) const;

        Bytes key_;
    };

}
