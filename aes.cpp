#include "aes.h"
#include "evp_context.h"
#include "exception.h"

#include <openssl/err.h>
#include <openssl/evp.h>

using namespace rrl;
using namespace rrl::rlc;

AES::AES(Bytes const &key)
    : key(key)
{
    switch (key.size()) {
    case 16: break; // AES128
    case 24: break; // AES192
    case 32: break; // AES256
    default:
        throw std::runtime_error("Unsupported AES key size");
    }
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
        return crypt(buffer, Operation::Decrypt, Bytes(key.size()));
}

Bytes AES::encrypt_cbc(Bytes const &buffer, Bytes const &iv) const {
    if (!iv.empty())
        return crypt(buffer, Operation::Encrypt, iv);
    else
        return crypt(buffer, Operation::Encrypt, Bytes(key.size()));
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
        reinterpret_cast<unsigned char const*>(key.data()),
        reinterpret_cast<unsigned char const*>(iv.empty() ? NULL : iv.data()),
        static_cast<int>(operation)
    );
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

void const* AES::get_cipher(Mode mode) const {
    switch (key.size()) {
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
    if (buffer.size() % key.size() != 0)
        throw std::invalid_argument("buffer must be aligned to key size");
}
