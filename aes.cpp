#include "aes.hpp"
#include "evp_context.hpp"
#include "exception.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

using namespace rrl;
using namespace rrl::rlc;

AES::AES(Bytes const &key)
    : key_(key)
{
    switch (key_.size()) {
    case 16: break; // AES128
    case 24: break; // AES192
    case 32: break; // AES256
    default:
        throw std::runtime_error("unsupported AES key size");
    }
}

AES::AES(AES const &other)
    : key_(other.key_)
{}

AES::AES(AES &&other) noexcept
    : key_(std::move(other.key_))
{}

AES& AES::operator=(AES const &rhs) {
    key_ = rhs.key_;
    return *this;
}

AES& AES::operator=(AES &&rhs) noexcept {
    key_ = std::move(rhs.key_);
    return *this;
}

Bytes AES::decrypt_ecb(Bytes const &buffer) const {
    return crypt(buffer, Operation::Decrypt, {});
}

Bytes AES::encrypt_ecb(Bytes const &buffer) const {
    return crypt(buffer, Operation::Encrypt, {});
}

Bytes AES::decrypt_cbc(Bytes const &buffer, Bytes const &iv) const {
    if (!iv.empty())
        return crypt(buffer, Operation::Decrypt, iv);
    else
        return crypt(buffer, Operation::Decrypt, Bytes(key_.size()));
}

Bytes AES::encrypt_cbc(Bytes const &buffer, Bytes const &iv) const {
    if (!iv.empty())
        return crypt(buffer, Operation::Encrypt, iv);
    else
        return crypt(buffer, Operation::Encrypt, Bytes(key_.size()));
}

Bytes AES::crypt(Bytes const &buffer, Operation operation, Bytes const &iv) const {
    validate_alignment(buffer);

    Bytes cipher(buffer.size() + 32 /* maximum block size */);
    int result_size = static_cast<int>(cipher.size());

    int result;
    EVPContext context;

    result = EVP_CipherInit_ex(
        context,
        static_cast<EVP_CIPHER const*>(get_cipher(iv.empty() ? Mode::ECB : Mode::CBC)),
        NULL,
        reinterpret_cast<unsigned char const*>(key_.data()),
        reinterpret_cast<unsigned char const*>(iv.empty() ? NULL : iv.data()),
        static_cast<int>(operation)
    );
    if (!result)
        throw Exception(ERR_get_error());

    result = EVP_CIPHER_CTX_set_padding(context, 0);
    if (!result)
        throw Exception(ERR_get_error());

    result = EVP_CipherUpdate(
        context,
        reinterpret_cast<unsigned char*>(cipher.data()),
        &result_size,
        reinterpret_cast<unsigned char const*>(buffer.data()),
        static_cast<int>(buffer.size())
    );

    if (!result)
        throw Exception(ERR_get_error());

    result = EVP_CipherFinal_ex(context, reinterpret_cast<unsigned char*>(cipher.data() + result_size), &result_size);
    if (!result)
        throw Exception(ERR_get_error());

    cipher.resize(result_size);

    return cipher;
}

size_t AES::key_size() const {
    return key_.size();
}

void const* AES::get_cipher(Mode mode) const {
    switch (key_.size()) {
    case 16:
        return mode == Mode::ECB ? EVP_aes_128_ecb() : EVP_aes_128_cbc();
    case 24:
        return mode == Mode::ECB ? EVP_aes_192_ecb() : EVP_aes_192_cbc();
    case 32:
        return mode == Mode::ECB ? EVP_aes_256_ecb() : EVP_aes_256_cbc();
    default:
        throw std::runtime_error("unsupported AES key size");
    }
}

void AES::validate_alignment(Bytes const &buffer) const {
    if (buffer.size() % key_.size() != 0)
        throw std::invalid_argument("buffer must be aligned to key size");
}
