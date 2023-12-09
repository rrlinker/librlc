#pragma once

#include <stdexcept>

namespace rrl::rlc {

    enum class Mode : bool {
        ECB = false,
        CBC = true,
    };

    inline static void validate_mode(Mode mode) {
        if (mode != Mode::ECB && mode != Mode::CBC)
            throw std::invalid_argument("invalid mode");
    }

}
