#include "rsa.h"
#include "exception.h"

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

using namespace rrl;
using namespace rrl::rlc;

rrl::rlc::RSA::RSA(unsigned bits, Bytes const& public_exponent) {
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

rrl::rlc::RSA::RSA(Bytes const& modulus, Bytes const& exponent) {
    rsa_ = RSA_new();
    auto BNmodulus = BN_bin2bn(reinterpret_cast<unsigned char const*>(modulus.data()), static_cast<int>(modulus.size()), NULL);
    auto BNexponent = BN_bin2bn(reinterpret_cast<unsigned char const*>(exponent.data()), static_cast<int>(exponent.size()), NULL);
    int result = RSA_set0_key(
        static_cast<::RSA*>(rsa_),
        static_cast<BIGNUM*>(BNmodulus),
        static_cast<BIGNUM*>(BNexponent),
        NULL
    );
    if (!result) {
        free();
        throw Exception(result);
    }
}

rrl::rlc::RSA::~RSA() {
    free();
}

Bytes rrl::rlc::RSA::encrypt(Bytes const& bytes) const {
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

Bytes rrl::rlc::RSA::decrypt(Bytes const& bytes) const {
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
