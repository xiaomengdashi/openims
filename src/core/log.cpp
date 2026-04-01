#include "src/core/log.hpp"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace ims::core {

static std::shared_ptr<spdlog::logger> g_logger;

void init_logging() {
  if (g_logger) return;
  g_logger = spdlog::stdout_color_mt("ims");
  g_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
  g_logger->set_level(spdlog::level::info);
}

std::shared_ptr<spdlog::logger> log() {
  if (!g_logger) init_logging();
  return g_logger;
}

} // namespace ims::core

