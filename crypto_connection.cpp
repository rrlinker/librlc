#include "crypto_connection.hpp"
#include "random.hpp"

#include <iostream>

#include <librlcom/bound_check.hpp>

using namespace rrl;
using namespace rrl::rlc;

CryptoConnection::CryptoConnection(Connection &conn)
    : conn_(conn)
{
    reset_send_buffer();
    reset_recv_buffer();
}

CryptoConnection::~CryptoConnection() {
}

void CryptoConnection::connect(Address const&) {
    throw std::logic_error("`connect` member function of CryptoConnection class is not implemented");
}

void CryptoConnection::disconnect() {
}

void CryptoConnection::send(std::byte const *data, uint64_t length) {
    verify_size_bounds(length);
    auto size = static_cast<size_t>(length);
    auto offset = send_buffer_.size();
    send_buffer_.resize(offset + size);
    std::copy(data, data + size, send_buffer_.data() + offset);
}

void CryptoConnection::recv(std::byte *data, uint64_t length) {
    verify_size_bounds(length);
    auto size = static_cast<size_t>(length);
    if (size > recv_buffer_.size() - recv_offset_)
        throw std::length_error("recv_buffer_ holds not enough data");
    std::copy(recv_buffer_.data() + recv_offset_, recv_buffer_.data() + recv_offset_ + size, data);
    recv_offset_ += size;
    if (recv_offset_ >= recv_buffer_.size())
        reset_recv_buffer();
}

void CryptoConnection::init_as_client(RSA const &rsa) {
    if (!(rsa.mode & RSA::Public))
        throw std::runtime_error("rsa must be initialized with public key to be able to initialize as a client");

    reset_send_buffer();
    
    Bytes key = random(AES::MinKeySize);
    send(key.data(), key.size());
    set_send_buffer_size();
    send_buffer_ = rsa.encrypt(send_buffer_);
    conn_ << send_buffer_;

    aes_ = key;

    reset_send_buffer();
}

void CryptoConnection::init_as_server(RSA const &rsa) {
    if (!recv_buffer_.empty())
        throw std::runtime_error("recv_buffer_ is not empty");
    if (!(rsa.mode & RSA::Private))
        throw std::runtime_error("rsa must be initialized with private key to be able to initialize as a server");

    conn_ >> recv_buffer_;
    recv_buffer_ = rsa.decrypt(recv_buffer_);
    set_recv_buffer_size();
    Bytes key(recv_buffer_.size() - recv_offset_);
    recv(key.data(), key.size());

    aes_ = key;

    ensure_recv_buffer_empty();
}

void CryptoConnection::init_as_server(Bytes const &key) {
    aes_ = key;
}

void CryptoConnection::verify_initialized() {
    if (!aes_.has_value())
        throw std::runtime_error("CryptoConnection hasn't been initialized");
}

void CryptoConnection::reset_send_buffer() {
    send_buffer_.clear();
    send_buffer_.resize(sizeof(uint64_t));
}

void CryptoConnection::set_send_buffer_size() {
    *reinterpret_cast<uint64_t*>(send_buffer_.data()) = send_buffer_.size();
}

void CryptoConnection::encrypt() {
    set_send_buffer_size();
    verify_initialized();
    if (auto unaligned = send_buffer_.size() % aes_->key_size(); unaligned) {
        auto align_size = aes_->key_size() - unaligned;
        send_buffer_.resize(send_buffer_.size() + align_size);
    }
    send_buffer_ = aes_->encrypt_ecb(send_buffer_);
}

void CryptoConnection::flush() {
    conn_ << send_buffer_;
    reset_send_buffer();
}

void CryptoConnection::reset_recv_buffer() {
    recv_buffer_.clear();
    recv_offset_ = 0;
}

void CryptoConnection::set_recv_buffer_size() {
    auto size = *reinterpret_cast<uint64_t*>(recv_buffer_.data());
    verify_size_bounds(size);
    recv_buffer_.resize(static_cast<size_t>(size));
    recv_offset_ = sizeof(uint64_t);
}

void CryptoConnection::gather() {
    if (!recv_buffer_.empty())
        throw std::runtime_error("recv_buffer_ is not empty");
    conn_ >> recv_buffer_;
}

void CryptoConnection::decrypt() {
    verify_initialized();
    recv_buffer_ = aes_->decrypt_ecb(recv_buffer_);
    set_recv_buffer_size();
}

void CryptoConnection::encrypt_and_flush() {
    encrypt();
    flush();
}

void CryptoConnection::gather_and_decrypt() {
    gather();
    decrypt();
}

void CryptoConnection::ensure_send_buffer_empty() const {
    if (!send_buffer_.empty())
        throw std::length_error("send_buffer_ is not empty");
}

void CryptoConnection::ensure_recv_buffer_empty() const {
    if (!recv_buffer_.empty())
        throw std::length_error("recv_buffer_ is not empty");
}
