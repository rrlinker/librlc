#pragma once

#include <stdexcept>

namespace rrl::rlc {

    enum class Operation : bool {
        Decrypt = false,
        Encrypt = true,
    };

    inline static void validate_operation(Operation operation) {
        if (operation != Operation::Decrypt && operation != Operation::Encrypt)
            throw std::invalid_argument("invalid operation");
    }

}
