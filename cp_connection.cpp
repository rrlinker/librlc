#include "cp_connection.h"

#include <iostream>

#include <librlcom/bound_check.h>

using namespace rrl;
using namespace rrl::rlc;

CPConnection::CPConnection(Connection &conn)
    : conn_(conn)
    , recv_offset_(0)
{}

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
        recv_buffer_.clear();
}

void CPConnection::init_as_client(Bytes const& server_pk_modulus, Bytes const& server_pk_exponent) {
}

void CPConnection::init_as_server() {
    if (!recv_buffer_.empty())
        throw std::runtime_error("recv_buffer_ is not empty");
    conn_ >> recv_buffer_;
}

void CPConnection::encrypt() {
}

void CPConnection::flush() {
    conn_ << send_buffer_;
    send_buffer_.clear();
}

void CPConnection::gather() {
    if (!recv_buffer_.empty())
        throw std::runtime_error("recv_buffer_ is not empty");
    conn_ >> recv_buffer_;
}

void CPConnection::decrypt() {
}

void CPConnection::encrypt_and_flush() {
    encrypt();
    flush();
}

void CPConnection::gather_and_decrypt() {
    gather();
    decrypt();
}
