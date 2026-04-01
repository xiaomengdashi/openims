#pragma once

#include <chrono>

namespace ims::core {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

inline TimePoint now() { return Clock::now(); }

} // namespace ims::core

