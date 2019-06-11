#include "crypto_courier.h"

using namespace rrl;
using namespace rrl::rlc;


CryptoCourier::CryptoCourier(Connection &conn)
    : conn_(conn)
{}

msg::Any CryptoCourier::receive() {
    conn_.gather_and_decrypt();
    msg::Any msg;
    msg.read(conn_);
    return msg;
}

void CryptoCourier::send(msg::Any const& msg) {
    msg.write(conn_);
    conn_.encrypt_and_flush();
}

void CryptoCourier::init_as_client(Bytes const &server_pk_modulus, Bytes const &server_pk_exponent) {
    conn_.init_as_client(server_pk_modulus, server_pk_exponent);
}

void CryptoCourier::init_as_server() {
    conn_.init_as_server();
}
