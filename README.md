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

### 最小回归（SIPp）

`tools/sipp_demo.sh` 提供一个最小 REGISTER 回归脚本（需要安装 `sipp`）。

### 鉴权（已去掉 mock）

当前默认启用 **IMS AKA (AKAv1-MD5)**，配置在 `config.yaml` 的 `auth.users_aka` 中（K/OPc/SQN/AMF）。
如需回归/演示可切回 `auth.mode: "md5"` 并使用 `auth.users`。

