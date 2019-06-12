#include "cp_connection.h"
#include "random.h"

#include <iostream>

#include <librlcom/bound_check.h>

using namespace rrl;
using namespace rrl::rlc;

CPConnection::CPConnection(Connection &conn)
    : conn_(conn)
{
    reset_send_buffer();
    reset_recv_buffer();
}

CPConnection::~CPConnection() {
}

void CPConnection::connect(Address const&) {
    throw std::logic_error("`connect` member function of CPConnection class is not implemented");
}

void CPConnection::disconnect() {
}

void CPConnection::send(std::byte const *data, uint64_t length) {
    verify_size_bounds(length);
    auto size = static_cast<size_t>(length);
    auto offset = send_buffer_.size();
    send_buffer_.resize(offset + size);
    std::copy(data, data + size, send_buffer_.data() + offset);
}

void CPConnection::recv(std::byte *data, uint64_t length) {
    verify_size_bounds(length);
    auto size = static_cast<size_t>(length);
    if (size > recv_buffer_.size() - recv_offset_)
        throw std::length_error("recv_buffer_ holds not enough data");
    std::copy(recv_buffer_.data() + recv_offset_, recv_buffer_.data() + recv_offset_ + size, data);
    recv_offset_ += size;
    if (recv_offset_ >= recv_buffer_.size())
        reset_recv_buffer();
}

void CPConnection::init_as_client(RSA const &rsa) {
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

void CPConnection::init_as_server(RSA const &rsa) {
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

void CPConnection::verify_initialized() {
    if (!aes_.has_value())
        throw std::runtime_error("CPConnection hasn't been initialized");
}

void CPConnection::reset_send_buffer() {
    send_buffer_.clear();
    send_buffer_.resize(sizeof(uint64_t));
}

void CPConnection::set_send_buffer_size() {
    *reinterpret_cast<uint64_t*>(send_buffer_.data()) = send_buffer_.size();
}

void CPConnection::encrypt() {
    set_send_buffer_size();
    verify_initialized();
    if (auto unaligned = send_buffer_.size() % aes_->key_size(); unaligned) {
        auto align_size = aes_->key_size() - unaligned;
        send_buffer_.resize(send_buffer_.size() + align_size);
    }
    send_buffer_ = aes_->encrypt_ecb(send_buffer_);
}

void CPConnection::flush() {
    conn_ << send_buffer_;
    reset_send_buffer();
}

void CPConnection::reset_recv_buffer() {
    recv_buffer_.clear();
    recv_offset_ = 0;
}

void CPConnection::set_recv_buffer_size() {
    auto size = *reinterpret_cast<uint64_t*>(recv_buffer_.data());
    verify_size_bounds(size);
    recv_buffer_.resize(static_cast<size_t>(size));
    recv_offset_ = sizeof(uint64_t);
}

void CPConnection::gather() {
    if (!recv_buffer_.empty())
        throw std::runtime_error("recv_buffer_ is not empty");
    conn_ >> recv_buffer_;
}

void CPConnection::decrypt() {
    verify_initialized();
    recv_buffer_ = aes_->decrypt_ecb(recv_buffer_);
    set_recv_buffer_size();
}

void CPConnection::encrypt_and_flush() {
    encrypt();
    flush();
}

void CPConnection::gather_and_decrypt() {
    gather();
    decrypt();
}

void CPConnection::ensure_send_buffer_empty() const {
    if (!send_buffer_.empty())
        throw std::length_error("send_buffer_ is not empty");
}

void CPConnection::ensure_recv_buffer_empty() const {
    if (!recv_buffer_.empty())
        throw std::length_error("recv_buffer_ is not empty");
}
