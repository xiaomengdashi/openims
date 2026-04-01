#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace ims::n5 {

// 5G QoS Identifier (5QI) values per 3GPP TS 23.501
// Standardized 5QI values for IMS services
enum class FiveQI : uint8_t {
  // Guaranteed Bitrate (GBR) services
  Voice = 1,              // Conversational Voice (GBR)
  Video = 2,              // Conversational Video (GBR)
  RealTimeGaming = 3,     // Real-time Gaming (GBR)
  NonConversationalVideo = 4, // Non-Conversational Video (GBR)

  // Non-GBR services
  IMSSignaling = 5,       // IMS Signaling (Non-GBR)

  // Additional standardized values
  TCPVideoBuffered = 6,   // TCP-based Video (Buffered Streaming)
  VoiceVideoInteractive = 7, // Voice, Video, Interactive Gaming
  VideoBuffered = 8,      // Video (Buffered Streaming)
  TCPApplication = 9,     // TCP-based applications

  // Default bearer
  Default = 9
};

// QoS characteristics for a 5QI value (3GPP TS 23.501)
struct QosCharacteristics {
  FiveQI five_qi;
  std::string resource_type;     // "GBR" or "Non-GBR"
  uint16_t default_priority;     // 1-255
  uint32_t default_max_data_burst_volume;  // bytes
  uint32_t default_averaging_window;       // ms
};

// Media type to 5QI mapping configuration
struct QosMappingConfig {
  FiveQI voice_5qi{FiveQI::Voice};
  FiveQI video_5qi{FiveQI::Video};
  FiveQI signaling_5qi{FiveQI::IMSSignaling};

  // Default bitrates for bandwidth allocation
  uint32_t default_voice_bitrate_kbps{64};
  uint32_t default_video_bitrate_kbps{384};
  uint32_t default_signaling_bitrate_kbps{64};
};

// QoS policy for a media stream
struct MediaQosPolicy {
  FiveQI five_qi;
  uint32_t guaranteed_bitrate_kbps{0};   // GBR
  uint32_t maximum_bitrate_kbps{0};      // MBR
  std::string media_type;                 // "audio", "video", "application"
  uint16_t port{0};
  std::string connection_address;
};

// Get 5QI for a given media type
FiveQI getFiveQIForMediaType(const std::string& media_type, const QosMappingConfig& config);

// Get QoS characteristics for a 5QI value
QosCharacteristics getQosCharacteristics(FiveQI five_qi);

// Convert 5QI enum to integer value
constexpr uint8_t toUnderlying(FiveQI five_qi) {
  return static_cast<uint8_t>(five_qi);
}

// Convert integer to 5QI enum
std::optional<FiveQI> fromFiveQI(uint8_t value);

// Convert media type string to standard format
std::string normalizeMediaType(const std::string& media_type);

// Check if 5QI is GBR (Guaranteed Bit Rate)
bool isGBR(FiveQI five_qi);

} // namespace ims::n5
