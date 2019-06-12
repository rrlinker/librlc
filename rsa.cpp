#include "rsa.h"
#include "exception.h"

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

using namespace rrl;
using namespace rrl::rlc;

rrl::rlc::RSA::RSA(unsigned bits, Bytes const &public_exponent)
    : mode(Both)
{
    rsa_ = RSA_new();
    auto BNpublicExponent = BN_bin2bn(reinterpret_cast<unsigned char const*>(public_exponent.data()), static_cast<int>(public_exponent.size()), NULL);
    int result = RSA_generate_key_ex(
        static_cast<::RSA*>(rsa_),
        bits,
        BNpublicExponent,
        NULL
    );
    if (!result) {
        free();
        throw Exception(result);
    }
}

rrl::rlc::RSA::RSA(Mode mode, Bytes const &modulus, Bytes const &exponent)
    : mode(mode)
{
    rsa_ = RSA_new();
    auto BNmodulus = BN_bin2bn(reinterpret_cast<unsigned char const*>(modulus.data()), static_cast<int>(modulus.size()), NULL);
    auto BNexponent = BN_bin2bn(reinterpret_cast<unsigned char const*>(exponent.data()), static_cast<int>(exponent.size()), NULL);
    int result;
    switch (mode) {
    case Mode::Public:
        result = RSA_set0_key(
            static_cast<::RSA *>(rsa_),
            BNmodulus,
            BNexponent,
            NULL
        );
        break;
    case Mode::Private:
        result = RSA_set0_key(
            static_cast<::RSA *>(rsa_),
            BNmodulus,
            NULL,
            BNexponent
        );
        break;
    default:
        free();
        throw std::runtime_error("unexpected mode");
    }
    if (!result) {
        free();
        throw Exception(result);
    }
}

rrl::rlc::RSA::RSA(ModeBoth mode, Bytes const &modulus, Bytes const &public_exponent, Bytes const &private_exponent)
    : mode(mode)
{
    if (mode != ModeBoth::Both)
        throw std::runtime_error("unexpected mode");
    rsa_ = RSA_new();
    auto BNmodulus = BN_bin2bn(reinterpret_cast<unsigned char const*>(modulus.data()), static_cast<int>(modulus.size()), NULL);
    auto BNpub_exponent = BN_bin2bn(reinterpret_cast<unsigned char const*>(public_exponent.data()), static_cast<int>(public_exponent.size()), NULL);
    auto BNpriv_exponent = BN_bin2bn(reinterpret_cast<unsigned char const*>(private_exponent.data()), static_cast<int>(private_exponent.size()), NULL);
    int result = RSA_set0_key(
        static_cast<::RSA *>(rsa_),
        BNmodulus,
        BNpub_exponent,
        BNpriv_exponent
    );
    if (!result) {
        free();
        throw Exception(result);
    }
}

rrl::rlc::RSA::~RSA() {
    free();
}

Bytes rrl::rlc::RSA::encrypt(Bytes const &bytes) const {
    if (!(mode & Public))
        throw std::runtime_error("RSA is not initialized with public key");
    Bytes result(RSA_size(static_cast<::RSA*>(rsa_)));
    if (
        RSA_public_encrypt(
            static_cast<int>(bytes.size()),
            reinterpret_cast<unsigned char const*>(bytes.data()),
            reinterpret_cast<unsigned char*>(result.data()),
            static_cast<::RSA*>(rsa_),
            RSA_PKCS1_OAEP_PADDING
        ) == -1
        ) {
        throw Exception(ERR_get_error());
    }
    return result;
}

Bytes rrl::rlc::RSA::decrypt(Bytes const &bytes) const {
    if (!(mode & Private))
        throw std::runtime_error("RSA is not initialized with private key");
    Bytes result(RSA_size(static_cast<::RSA*>(rsa_)));
    if (
        RSA_private_decrypt(
            static_cast<int>(bytes.size()),
            reinterpret_cast<unsigned char const*>(bytes.data()),
            reinterpret_cast<unsigned char*>(result.data()),
            static_cast<::RSA*>(rsa_),
            RSA_PKCS1_OAEP_PADDING
        ) == -1
        ) {
        throw Exception(ERR_get_error());
    }
    return result;
}

Bytes rrl::rlc::RSA::get_modulus() const {
    BIGNUM const* modulus = NULL;
    RSA_get0_key(static_cast<::RSA*>(rsa_), &modulus, NULL, NULL);
    if (!modulus)
        return {};
    Bytes result(BN_num_bytes(modulus));
    BN_bn2bin(modulus, reinterpret_cast<unsigned char*>(result.data()));
    return result;
}

Bytes rrl::rlc::RSA::get_public_exponent() const {
    BIGNUM const* exponent = NULL;
    RSA_get0_key(static_cast<::RSA*>(rsa_), NULL, &exponent, NULL);
    if (!exponent)
        return {};
    Bytes result(BN_num_bytes(exponent));
    BN_bn2bin(exponent, reinterpret_cast<unsigned char*>(result.data()));
    return result;
}

Bytes rrl::rlc::RSA::get_private_exponent() const {
    BIGNUM const* exponent = NULL;
    RSA_get0_key(static_cast<::RSA*>(rsa_), NULL, NULL, &exponent);
    if (!exponent)
        return {};
    Bytes result(BN_num_bytes(exponent));
    BN_bn2bin(exponent, reinterpret_cast<unsigned char*>(result.data()));
    return result;
}

void rrl::rlc::RSA::free() {
    if (rsa_) {
        RSA_free(static_cast<::RSA*>(rsa_));
        rsa_ = nullptr;
    }
    // RSA_free also frees modulus and exponent
}
