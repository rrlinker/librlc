#include <rrlinker/crypto/random.hpp>

#include <rrlinker/crypto/exception.hpp>

#include <openssl/rand.h>
#include <openssl/err.h>

using namespace rrl;
using namespace rrl::rlc;

Bytes rrl::rlc::random(size_t n) {
    Bytes result(n);
    if (!RAND_bytes(reinterpret_cast<unsigned char*>(result.data()), n))
        throw Exception(ERR_get_error());
    return result;
}
