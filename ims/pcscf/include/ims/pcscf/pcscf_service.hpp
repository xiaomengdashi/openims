#pragma once

#include <memory>
#include <string>

namespace ims::sip {
class SipStack;
struct SipMessage;
} // namespace ims::sip

namespace ims::scscf {
class ScscfService;
} // namespace ims::scscf

namespace ims::icscf {
class IcscfService;
} // namespace ims::icscf

namespace ims::n5 {
class IN5Client;
struct N5ClientConfig;
} // namespace ims::n5

namespace ims::pcscf {

// P-CSCF service configuration
struct PcscfConfig {
  bool n5_enabled{false};
  // Additional P-CSCF specific config can be added here
};

class PcscfService {
public:
  PcscfService(ims::sip::SipStack& sip, ims::icscf::IcscfService& icscf);
  ~PcscfService();

  // Set N5 client for policy control (optional)
  void set_n5_client(std::unique_ptr<ims::n5::IN5Client> n5_client);

  void on_sip_message(const ims::sip::SipMessage& msg);

private:
  ims::sip::SipStack& sip_;
  ims::icscf::IcscfService& icscf_;
  std::unique_ptr<ims::n5::IN5Client> n5_client_;
};

} // namespace ims::pcscf

