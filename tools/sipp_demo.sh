#!/usr/bin/env bash
set -euo pipefail

# 依赖：
# - sipp
# - imsd 已运行（默认监听 0.0.0.0:5060）
#
# 注意：这是一个“回归/演示脚本”，并非真机 VoNR 联调脚本。
# 真机联调需要手机 IMS 配置、AKA、网络侧 P-CSCF 发现等都对齐。

IMS_IP="${IMS_IP:-127.0.0.1}"
IMS_PORT="${IMS_PORT:-5060}"

echo "[*] Register UA a -> ${IMS_IP}:${IMS_PORT}"
sipp -sf "$(dirname "$0")/uac_register.xml" "${IMS_IP}:${IMS_PORT}" -m 1 -trace_err -trace_msg

