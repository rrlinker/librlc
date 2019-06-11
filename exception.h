#pragma once

#include <stdexcept>

namespace rrl::rlc {

    class Exception : public std::runtime_error {
    public:
        Exception(unsigned long errcode);
        int const errcode;
        static std::string string_from_errcode(unsigned long errcode);
    };

}
