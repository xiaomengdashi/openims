## VoNR IMS（MVP）

### 构建

```bash
cmake -S . -B build -DIMS_WITH_EXOSIP=ON
cmake --build build -j
ctest --test-dir build
```

如果系统未安装 `osip2/exosip2`，会自动以 **stub 模式**编译（仍可跑单测与核心逻辑），需要联调真机/网络时再安装依赖并打开 `IMS_WITH_EXOSIP=ON`。
本项目禁止 stub/mock 路径：构建必须启用并编译真实 SIP 栈（`IMS_WITH_EXOSIP=ON`）。

### 运行

```bash
./build/imsd ./config.yaml
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
  http_url: "http://127.0.0.1:8080/ims/qos"
  http_timeout_ms: 1500
```

### 最小回归（SIPp）

`tools/sipp_demo.sh` 提供一个最小 REGISTER 回归脚本（需要安装 `sipp`）。

### 鉴权（已去掉 mock）

当前默认启用 **IMS AKA (AKAv1-MD5)**，配置在 `config.yaml` 的 `auth.users_aka` 中（K/OPc/SQN/AMF）。
如需回归/演示可切回 `auth.mode: "md5"` 并使用 `auth.users`。

