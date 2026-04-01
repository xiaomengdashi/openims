## VoNR IMS（MVP）

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

## 代码架构

```
apps/
├── imsd/          - All-in-one combined IMS daemon (all CSCF functions)
├── pcscfd/         - Standalone P-CSCF daemon
├── icscfd/         - Standalone I-CSCF daemon
└── scscfd/         - Standalone S-CSCF daemon

src/
├── core/           - Config loading (YAML), logging, time utilities
├── auth/           - Pluggable auth provider (MD5 + IMS AKA/Milenage)
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

**Important architectural points:**
*   `IMS_WITH_EXOSIP=ON` **must** always be used - building without eXosip2 is not supported (no stubs/mocks allowed)
*   Authentication has a clean pluggable interface in `src/auth/include/src/auth/auth_provider.hpp`
*   SIP stack is wrapped in `src/sip/include/src/sip/sip_stack.hpp` (pimpl pattern)
*   Registration state machine in `scscf`
*   Can be deployed as all-in-one `imsd` or split into separate daemons

## 依赖

*   **OpenSSL** - Crypto (required for MD5, AKA, Milenage)
*   **libosip2/libexosip2 5.3.0** - SIP stack (automatically built from included tarballs)
*   **spdlog 1.14.1** - Logging (via FetchContent)
*   **yaml-cpp 0.8.0** - YAML config parsing (via FetchContent)
*   **GoogleTest 1.14.0** - Testing framework (via FetchContent)

## 构建

**Full build (required):**
```bash
cmake -S . -B build -DIMS_WITH_EXOSIP=ON
cmake --build build -j
```

**Run all tests:**
```bash
ctest --test-dir build
```

**Run a single test:**
```bash
./build/ims_tests --gtest_filter=TestName
```

本项目禁止 stub/mock：构建必须启用并编译真实 SIP 栈（`IMS_WITH_EXOSIP=ON`）。

## 运行

**Run the all-in-one daemon:**
```bash
./build/imsd ./config.yaml
```

**Run SIPp regression test (requires sipp):**
```bash
./tools/sipp_demo.sh
```

### 代理/互通配置（P-CSCF/I-CSCF）

本项目默认以 **SIP proxy（而非纯 B2BUA）** 方式把 UE 侧请求转发到核心网侧，依赖 `SipMessage.raw` 进行代理级转发，并做最小的 P-CSCF 头域处理：

- **Record-Route**：对 INVITE 自动插入（保持后续对话内路由）。
- **Path**：对 REGISTER 自动插入（便于注册后回路）。
- **Via**：转发请求时会插入本节点 Via（sent-by 默认从 `self_uri` 推导，也可显式配置 `via_sent_by`）。
- **PANI/PVNI/PAI**：可配置缺省值，在 UE 未携带时注入。
- **topology_hiding**：开启后会剥离并重建部分路由相关头域（MVP：Route/Record-Route/Path）。

示例（见 `config.yaml`）：

```yaml
pcscf_proxy:
  topology_hiding: false
  # self_uri: "sip:pcscf.ims.local:5060;transport=udp;lr"
  # pani: '3GPP-NR;utran-cell-id-3gpp=00000000000000000000000000000000'
  # pvni: '"ims.mnc001.mcc460.3gppnetwork.org"'
  # pai: '<sip:+8613800138000@ims.mnc001.mcc460.3gppnetwork.org>'
```

### IMS IPsec（xfrm / 无 mock）

启用 `ipsec.enabled: true` 后，启动时会通过 `ip xfrm ...` 下发 **ESP transport** 的 state/policy（静态 key 模式），用于 UE<->P-CSCF 间的 SIP/UDP 保护。

- 需要 **root 或 CAP_NET_ADMIN**
- 需要系统安装 `iproute2`（提供 `ip xfrm`）

配置示例（见 `config.yaml`）：

```yaml
ipsec:
  enabled: true
  mode: "xfrm"
  local_ip: "192.168.1.10"
  remote_ip: "192.168.1.20"
  spi_in: "0x1001"
  spi_out: "0x1002"
  enc_algo: "cbc(aes)"
  enc_key_hex: "00112233445566778899aabbccddeeff"
  auth_algo: "hmac(sha256)"
  auth_key_hex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  local_port: 5060
```

### QoS / Policy hook（会话建立/拆除事件）

S-CSCF 会在以下时机触发事件：
- `setup`: 收到 INVITE 并向被叫侧发起呼叫后
- `established`: 收到被叫侧 200 OK（呼叫建立）
- `teardown`: 收到 BYE（拆除）

如配置 `qos.http_url`，会通过 `curl` 以 JSON POST 发送：

```yaml
qos:
  enabled: true
  http_url: "http://127.0.0.1:8080/src/qos"
  http_timeout_ms: 1500
```

### 最小回归（SIPp）

`tools/sipp_demo.sh` 提供一个最小 REGISTER 回归脚本（需要安装 `sipp`）。

### 鉴权（已去掉 mock）

当前默认启用 **IMS AKA (AKAv1-MD5)**，配置在 `config.yaml` 的 `auth.users_aka` 中（K/OPc/SQN/AMF）。
如需回归/演示可切回 `auth.mode: "md5"` 并使用 `auth.users`。

## 配置

See `config.yaml` example with all options documented. Key sections:
*   `realm` - IMS realm name
*   `pcscf`, `icscf`, `scscf` - bind addresses
*   `routing` - next-hop proxy routing between CSCF nodes
*   `auth` - auth mode (`aka` or `md5`) and user credentials
*   `ipsec` - static XFRM configuration
*   `rtpengine` - media plane control
*   `qos` - HTTP webhook for session events

