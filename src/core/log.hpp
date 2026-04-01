#pragma once

#include <memory>

#include <spdlog/logger.h>

namespace spdlog {
class logger;
}

namespace ims::core {

void init_logging();
std::shared_ptr<spdlog::logger> log();

} // namespace ims::core

