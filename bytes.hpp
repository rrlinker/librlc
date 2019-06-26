#pragma once

#include <cstddef>
#include <vector>
#include <string>

namespace rrl::rlc {
    using Bytes = std::vector<std::byte>;
    Bytes bytes_from_hex_string(std::string const &s);
}
