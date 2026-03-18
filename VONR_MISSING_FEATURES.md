# VoNR IMS 缺失功能分析

本文档分析当前 MVP 实现相对于 3GPP 标准 VoNR IMS 缺失的功能，并按优先级排序。

## 当前已实现功能

- ✅ P-CSCF (Proxy-Call Session Control Function)
- ✅ I-CSCF (Interrogating-Call Session Control Function)
- ✅ S-CSCF (Serving-Call Session Control Function)
- ✅ IMS AKA (AKAv1-MD5) 鉴权 + Milenage
- ✅ Digest MD5 鉴权（测试用）
- ✅ Linux IPsec XFRM（静态密钥）
- ✅ RTPengine 媒体面集成
- ✅ QoS HTTP Webhook 通知
- ✅ SIP 代理转发，基础头域处理
- ✅ DHCP-based P-CSCF Discovery (DHCPv4 Option 15 + Option 120)

---

## 高优先级缺失功能（必须实现以支持基本 VoNR 通话）

### 1. **DNS NAPTR/SRV 查询支持**
- **缺失描述**：当前 IMS 没有实现基于 DNS 的 NAPTR/SRV 查询来路由 IMS 公共业务标识（PSI）和归属网络。VoNR UE 需要通过 P-CSCF 发现，I-CSCF 需要通过 DNS 找到 S-CSCF。
- **3GPP 参考**：TS 23.228, TS 24.229
- **影响**：无法支持标准的 IMS 域名路由，只能静态配置 next-hop。
- **优先级**：P0 - 高

### 2. **DHCP Option 120 P-CSCF 发现**
- **缺失描述**：我们实现了 DHCPv4 Option 15 和 Option 120，标准 3GPP 指定使用 **Option 120** 来携带 P-CSCF 地址列表。
  - ✅ DHCPv4 Option 15 - 已实现（legacy 兼容）
  - ✅ DHCPv4 Option 120 - 已实现（single P-CSCF address）
  - ❌ DHCPv6 P-CSCF 选项 - 缺失
  - ❌ Multiple P-CSCF addresses - 不支持（MVP 支持单个）
- **3GPP 参考**：TS 24.166 6.4.3, RFC 3361
- **影响**：符合 3GPP 标准，支持只要求 Option 120 的 UE。DHCPv6 仍缺失。
- **状态**：已实现 MVP 版本

### 3. **HSS 接口（Cx 接口）**
- **缺失描述**：I-CSCF 和 S-CSCF 需要通过 Cx 接口与 HSS（Home Subscriber Server）通信，获取用户订阅数据和 S-CSCF 指派。当前实现使用静态用户配置，无标准 Cx 接口。
- **3GPP 参考**：TS 29.229（Cx 接口 Diameter 协议）
- **影响**：无法对接运营商 HSS，不支持动态用户数据。
- **优先级**：P0 - 高

### 4. **SIP 鉴权完整性（Authentication-Integrity）**
- **缺失描述**：IMS 需要对 SIP 消息做完整性保护，使用 `Authorization` / `WWW-Authenticate` 头域的 `integrity-protected` 参数。
- **3GPP 参考**：TS 24.229 5.4.1
- **影响**：存在安全隐患，不符合 3GPP 安全要求。
- **优先级**：P0 - 高

### 5. **IMS AKA 重同步**
- **缺失描述**：当 UE 检测到 SQN 序列号失步，会发送 AUTS 参数要求重同步。当前不处理此参数。
- **3GPP 参考**：TS 33.205
- **影响**：如果 UE 失步，认证会一直失败，需要 UE 重新发起注册。
- **优先级**：P0 - 高

---

## 中优先级缺失功能（基本通话后需要）

### 6. **P-CSCF 承载授权（Rx 接口）**
- **缺失描述**：P-CSCF 需要通过 Rx 接口（Diameter）与 PCRF 交互，进行承载授权和 QoS 绑定。当前仅通过 HTTP webhook 通知。
- **3GPP 参考**：TS 29.214（Rx 接口）
- **影响**：无法与 5G 核心网 SMF/PCRF 对接实现动态 QoS。
- **优先级**：P1 - 中

### 7. **IMS 计费（Ro/Rf 接口）**
- **缺失描述**：不支持离线计费（Rf）和在线计费（Ro）接口，都是基于 Diameter。
- **3GPP 参考**：TS 32.299, TS 32.240
- **影响**：无法商用，不支持话单生成。
- **优先级**：P1 - 中

### 8. **SLF 路由（Diameter）**
- **缺失描述**：在多 HSS 环境下需要 SLF 接口查询找到正确的 HSS。
- **影响**：不支持大型部署。
- **优先级**：P1 - 中

### 9. **Emergency 呼叫支持**
- **缺失描述**：VoNR 必须支持紧急呼叫，有特殊的 IMS 紧急承载处理。
- **3GPP 参考**：TS 22.101, TS 23.167
- **影响**：不符合运营商准入要求。
- **优先级**：P1 - 中

---

## 低优先级缺失功能（VoNR 增强特性）

### 10. **5G QoS 标识（5QI）处理**
- **缺失描述**：VoNR 语音需要 5QI=1，视频需要 5QI=2，当前没有与 5G 核心网配合映射 QoS。
- **影响**：无法保证语音媒体面质量。
- **优先级**：P2 - 低

### 11. **IMS 公共服务标识（PSI）和 IMS 公共用户标识（IMPU）处理**
- **缺失描述**：当前对用户标识的处理比较简化，需要完整支持 IMPU/IMPI 映射。
- **优先级**：P2 - 低

### 12. **Session Transfer 和连续性**
- **缺失描述**：不支持切换中的会话转移。
- **影响**：不支持移动性切换。
- **优先级**：P2 - 低

### 13. **SMS over IMS**
- **缺失描述**：VoNR 要求支持 SMS over IMS。
- **3GPP 参考**：TS 24.341
- **影响**：仅支持语音通话，不支持短信。
- **优先级**：P2 - 低

### 14. **Video Telephony (VT)**
- **缺失描述**：仅语音，不支持可视电话。
- **影响**：功能不完整。
- **优先级**：P2 - 低

### 15. **Encryption SRTP**
- **缺失描述**：当前依赖 RTPengine 处理，IMS 核心本身不参与 SRTP 密钥协商。
- **优先级**：P2 - 低

---

## VoNR 相对于 VoLTE 的特殊要求（当前全部缺失）

| 功能 | 当前状态 | 优先级 |
|------|---------|--------|
| 5G 核心网 N2/N6 接口交互 | ❌ 缺失 | P1 |
| Network Slicing 支持 | ❌ 缺失 | P1 |
| 5QI QoS 映射 | ❌ 缺失 | P1 |
| PDU Session 关联 | ❌ 缺失 | P1 |
| Edge 部署支持 | ❌ 缺失 | P2 |

---

## 总结优先级

**P0（必须尽快实现）：**
1. DNS NAPTR/SRV 路由
2. ~~DHCP Option 120 (标准 P-CSCF 发现)~~ ✅ 已完成 MVP
3. Cx 接口（Diameter）对接 HSS
4. SIP 鉴权完整性保护
5. IMS AKA 重同步

**P1（基本通话正常后实现）：**
6. Rx 接口对接 PCRF
7. 紧急呼叫
8. 计费接口
9. 5G QoS 映射

**P2（MVP 可以暂时不实现）：**
10. SMS over IMS
11. 可视电话
12. 会话连续性
13. 网络切片

---

## 更新日志

- **2026-03-18**：添加 DHCP Option 15 实现，更新文档。
- **2026-03-18**：添加 DHCP Option 120 实现，完成标准 3GPP P-CSCF 发现 MVP。
