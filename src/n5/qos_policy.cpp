#include "src/n5/qos_policy.hpp"

#include <algorithm>
#include <unordered_map>

namespace ims::n5 {

namespace {

// Predefined QoS characteristics per 3GPP TS 23.501 Table 5.7.4-1
const std::unordered_map<FiveQI, QosCharacteristics> kQosCharacteristics = {
  {FiveQI::Voice, {
    FiveQI::Voice,
    "GBR",
    20,     // Priority
    2000,   // Default Maximum Data Burst Volume (bytes)
    2000    // Default Averaging Window (ms)
  }},
  {FiveQI::Video, {
    FiveQI::Video,
    "GBR",
    40,     // Priority
    10000,  // Default Maximum Data Burst Volume (bytes)
    2000    // Default Averaging Window (ms)
  }},
  {FiveQI::RealTimeGaming, {
    FiveQI::RealTimeGaming,
    "GBR",
    30,     // Priority
    1000,   // Default Maximum Data Burst Volume (bytes)
    2000    // Default Averaging Window (ms)
  }},
  {FiveQI::NonConversationalVideo, {
    FiveQI::NonConversationalVideo,
    "GBR",
    50,     // Priority
    10000,  // Default Maximum Data Burst Volume (bytes)
    2000    // Default Averaging Window (ms)
  }},
  {FiveQI::IMSSignaling, {
    FiveQI::IMSSignaling,
    "Non-GBR",
    10,     // Priority
    0,      // Not applicable for Non-GBR
    0       // Not applicable for Non-GBR
  }},
  {FiveQI::TCPVideoBuffered, {
    FiveQI::TCPVideoBuffered,
    "Non-GBR",
    60,     // Priority
    0,
    0
  }},
  {FiveQI::VoiceVideoInteractive, {
    FiveQI::VoiceVideoInteractive,
    "Non-GBR",
    70,     // Priority
    0,
    0
  }},
  {FiveQI::VideoBuffered, {
    FiveQI::VideoBuffered,
    "Non-GBR",
    80,     // Priority
    0,
    0
  }},
  {FiveQI::TCPApplication, {
    FiveQI::TCPApplication,
    "Non-GBR",
    90,     // Priority
    0,
    0
  }},
  {FiveQI::Default, {
    FiveQI::Default,
    "Non-GBR",
    90,     // Priority
    0,
    0
  }}
};

} // namespace

FiveQI getFiveQIForMediaType(const std::string& media_type, const QosMappingConfig& config) {
  const std::string normalized = normalizeMediaType(media_type);

  if (normalized == "audio") {
    return config.voice_5qi;
  } else if (normalized == "video") {
    return config.video_5qi;
  } else if (normalized == "application") {
    // IMS signaling (e.g., MSRP)
    return config.signaling_5qi;
  }

  // Default for unknown media types
  return FiveQI::Default;
}

QosCharacteristics getQosCharacteristics(FiveQI five_qi) {
  auto it = kQosCharacteristics.find(five_qi);
  if (it != kQosCharacteristics.end()) {
    return it->second;
  }
  // Return default characteristics
  return kQosCharacteristics.at(FiveQI::Default);
}

std::optional<FiveQI> fromFiveQI(uint8_t value) {
  switch (value) {
    case 1: return FiveQI::Voice;
    case 2: return FiveQI::Video;
    case 3: return FiveQI::RealTimeGaming;
    case 4: return FiveQI::NonConversationalVideo;
    case 5: return FiveQI::IMSSignaling;
    case 6: return FiveQI::TCPVideoBuffered;
    case 7: return FiveQI::VoiceVideoInteractive;
    case 8: return FiveQI::VideoBuffered;
    case 9: return FiveQI::TCPApplication;
    default: return std::nullopt;
  }
}

std::string normalizeMediaType(const std::string& media_type) {
  std::string normalized = media_type;

  // Convert to lowercase
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Trim whitespace
  size_t start = normalized.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  size_t end = normalized.find_last_not_of(" \t\r\n");
  normalized = normalized.substr(start, end - start + 1);

  return normalized;
}

bool isGBR(FiveQI five_qi) {
  const auto& chars = getQosCharacteristics(five_qi);
  return chars.resource_type == "GBR";
}

} // namespace ims::n5
