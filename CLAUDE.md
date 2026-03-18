# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

**Full build (required):**
```bash
cmake -S . -B build -DIMS_WITH_EXOSIP=ON
cmake --build build -j
```

**Run all tests:
```bash
ctest --test-dir build
```

**Run a single test:
```bash
./build/ims_tests --gtest_filter=TestName
```

**Run the all-in-one daemon:**
```bash
./build/imsd ./config.yaml
```

**Run SIPp regression test (requires sipp):**
```bash
./tools/sipp_demo.sh
```

## Project Overview

This is a **Voice over New Radio (VoNR) IP Multimedia Subsystem (IMS) IMS core** - Minimum Viable Product (MVP) implementation.

*   **Language:** C++20
*   **Build System:** CMake 3.22+
*   **Key Features:**
    *   P-CSCF (Proxy-Call Session Control Function)
    *   I-CSCF (Interrogating-CSCF)
    *   S-CSCF (Serving-CSCF)
    *   IMS AKA (AKAv1-MD5) authentication with Milenage
    *   Digest MD5 authentication (for testing)
    *   Linux IPsec XFRM (static keys)
    *   RTPengine media plane integration
    *   QoS HTTP webhook notifications

## Code Architecture

```
apps/
├── imsd/          - All-in-one combined IMS daemon (all CSCF functions)
├── pcscfd/         - Standalone P-CSCF daemon
├── icscfd/         - Standalone I-CSCF daemon
└── scscfd/         - Standalone S-CSCF daemon

ims/
├── core/           - Config loading (YAML), logging, time utilities
├── auth/           - Pluggable auth provider (MD5 + IMS AKA/Milenage
├── storage/        - Location service (registration location storing)
├── sip/            - SIP stack wrapper (libosip2/exosip2), message parsing, proxy routing
├── pcscf/          - P-CSCF service implementation
├── icscf/          - I-CSCF service
├── scscf/          - S-CSCF service, registration state machine, call sessions
├── media/          - SDP rewriting, RTPengine client
├── ipsec/          - Linux XFRM IPsec configuration via netlink
├── policy/         - QoS HTTP webhook notifications
└── tests/          - GoogleTest unit tests
```

**Important architectural points:
*   `IMS_WITH_EXOSIP=ON` **must** always be used - building without eXosip2 is not supported (no stubs/mocks allowed)
*   Authentication has a clean pluggable interface in `ims/auth/include/ims/auth/auth_provider.hpp`
*   SIP stack is wrapped in `ims/sip/include/ims/sip/sip_stack.hpp` (pimpl pattern
*   Registration state machine in `scscf`
*   Can be deployed as all-in-one `imsd or split into separate daemons

## Dependencies

*   **OpenSSL** - Crypto (required for MD5, AKA, Milenage
*   **libosip2/libexosip2 5.3.0 - SIP stack (automatically built from included tarballs)
*   **spdlog 1.14.1 - Logging (via FetchContent)
*   **yaml-cpp 0.8.0 - YAML config parsing (via FetchContent)
*   **GoogleTest 1.14.0 - Testing framework (via FetchContent)

## Configuration

See `config.yaml` example with all options documented. Key sections:
*   `realm` - IMS realm name
*   `pcscf`, `icscf`, `scscf - bind addresses
*   `routing` - next-hop proxy routing between CSCF nodes
*   `auth` - auth mode (`aka` or `md5`) and user credentials
*   `ipsec` - static XFRM configuration
*   `rtpengine` - media plane control
*   `qos` - HTTP webhook for session events
