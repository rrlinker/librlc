#include "bytes.hpp"

#include <stdexcept>

static bool is_hex_char(char c) {
    return (c >= '0' && c <= '9')
        || (c >= 'A' && c <= 'F')
        || (c >= 'a' && c <= 'f');
}

static uint8_t hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9')
        return static_cast<uint8_t>(c - '0');
    if (c >= 'A' && c <= 'F')
        return static_cast<uint8_t>(c - 'A' + 10);
    if (c >= 'a' && c <= 'f')
        return static_cast<uint8_t>(c - 'a' + 10);
    throw std::runtime_error("invalid hex character");
}

rrl::rlc::Bytes rrl::rlc::bytes_from_hex_string(std::string const &s) {
    rrl::rlc::Bytes bytes;
    size_t i = 0;
    while (true) {
        auto a = s[i];
        if (!a)
            break;
        i++;
        if (!is_hex_char(a))
            continue;
        auto b = s[i];
        if (!is_hex_char(b))
            throw std::runtime_error("invalid hex string");
        i++;
        bytes.emplace_back(static_cast<std::byte>(
            (hex_char_to_nibble(static_cast<char>(a)) << 4) |
            (hex_char_to_nibble(static_cast<char>(b)))
        ));
    }
    return bytes;
}
