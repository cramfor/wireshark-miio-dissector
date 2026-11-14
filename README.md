# wireshark-miio-dissector

Wireshark Lua 插件，用于解析**小米米家（miIO）局域网二进制协议**（UDP 端口 54321）。
配合 `python-miio`、`miio` 命令行工具或任意米家 App 抓包使用，可在 Wireshark 中直接看到解密后的 JSON 指令与响应。

> 协议特征：UDP 54321，报文头 `0x2131`，前 32 字节为明文头（magic / length / deviceId / timestamp / checksum），其后为 AES-128-CBC 加密负载。

---

## 功能

- 自动识别并解析 miIO 报文头字段：
  - Magic (`0x2131`)
  - Length
  - Unknown
  - DeviceID
  - Timestamp
  - Checksum（16 字节 MD5）
- 识别 `Hello` / `Hello Ack` 握手包（32 字节、无负载）。
- **校验 checksum**：用设备 token 重新计算 MD5，若与报文不符会提示 `Token mismatch`，避免用错 token 得到乱码。
- **AES-128-CBC 解密**负载，密钥派生规则与官方/`python-miio` 一致：
  - `key = MD5(token)`
  - `iv  = MD5(key .. token)`
  - 自动去除 PKCS#7 填充与尾部 `\0`。
- 解密后：
  - 在 `miio.data` 字段显示明文 JSON；
  - 调用 Wireshark 内置 JSON 解析器展开结构化字段，可直接在协议树中查看 `id` / `method` / `params` 等。
- token 只计算一次并缓存，后续包复用，性能友好。
- 内置纯 Lua 的 MD5 实现，**无需额外依赖**（不依赖 OpenSSL/LuaCrypto）。

---

## 安装

1. 确认 Wireshark 版本 ≥ 3.0（需要 `GcryptCipher` 与 `string.pack`）。
2. 把 `miio.lua` 放到 Wireshark 的 Personal Lua Plugins 目录：

   | 平台 | 路径 |
   |------|------|
   | Windows | `%APPDATA%\Wireshark\plugins\` |
   | macOS | `~/.local/lib/wireshark/plugins/` 或 `~/.config/wireshark/plugins/` |
   | Linux | `~/.local/lib/wireshark/plugins/` |

   具体路径可在 Wireshark 菜单 **Help → About Wireshark → Folders → Personal Lua Plugins** 查看。
3. 重启 Wireshark（或 **Analyze → Reload Lua Plugins**，快捷键 `Ctrl+Shift+L`）。

---

## 使用

### 1. 配置设备 token

每个米家设备有独立的 32 位十六进制 token（128 bit）。获取方式见 `python-miio` 文档（`miiocli device --ip <ip> --token <token> info` 或从云端/备份中提取）。

在 Wireshark 中设置：

- 菜单 **Edit → Preferences → Protocols → MIIO**，
- 在 **Device token** 中填入 32 个十六进制字符（大小写均可，可含空格，插件会清理空白）。

> 设置是全局的，一次只能解一个设备的 token。如果同时抓多个设备，建议按设备分别保存抓包再解。

### 2. 抓包

- 开始抓包，过滤 `udp.port == 54321`。
- 插件会**自动**把符合格式的包识别为 `MIIO` 协议，无需手动 Decode As。

### 3. 查看结果

- 协议列显示 `MIIO`；
- Info 列显示 `Hello` / `Hello Ack` 或解密后的 JSON；
- 协议树中可见：
  - `Magic` / `Length` / `Unknown` / `DeviceID` / `Timestamp` / `Checksum`
  - `Encrypted data`
  - `Data`（明文 JSON）及其展开的 JSON 字段。

### 4. 排错

| 现象 | 原因 / 处理 |
|------|-------------|
| 协议列不是 `MIIO` | 端口不是 54321、magic 不是 `0x2131`，或 length 字段与实际长度不符。可用 **Analyze → Decode As → UDP port 54321 → MIIO** 手动指定。 |
| `Token mismatch! Checksum expected ...` | token 填错，或抓的是另一台设备的包。 |
| `Decrypt failed` | 报文负载不是 16 字节对齐 / 数据损坏，或非加密负载被误判。 |
| `Token length must be 32 hex chars` | token 未设置或长度不对。 |
| 明文 JSON 出现乱码 | token 正确但设备使用较新固件/特殊负载，欢迎提 issue 附抓包（**请先脱敏 token 与 deviceId**）。 |

---

## 抓包示例

仓库 `samples/` 目录可放脱敏后的 `miio-sample.pcapng`，演示：

- Hello / Hello Ack 握手；
- `get_prop` 查询（如 `["power"]`）；
- `set` 控制指令与响应。

> 提交抓包前请务必替换/删除真实 token 与 deviceId，避免泄露设备控制权。

---

## 工作原理简述

+----------------+----------------+----------------+----------------+
| magic (2B) | length (2B) | unknown (4B) | deviceId (4B) |
+----------------+----------------+----------------+----------------+
| timestamp (4B) | checksum (16B, MD5) |
+----------------+--------------------------------------------------+
| encrypted payload (AES-128-CBC, length-32 bytes) |
+-------------------------------------------------------------------+

- `checksum = MD5(header[0:16] || token || encrypted_payload)`
- `key = MD5(token)`，`iv = MD5(key || token)`
- 负载为 JSON（部分老固件为纯文本）。

---

## 兼容性

- Wireshark 3.x / 4.x
- 依赖 Wireshark 内置 `GcryptCipher` 与 `string.pack`（Lua 5.3+，Wireshark 自带）。
- 已在 Windows / macOS / Linux 下测试（欢迎补充你的环境）。

---

## 贡献

- 欢迎提交 issue / PR：新固件差异、特殊负载、字段补充、抓包样例。
- 提交抓包请脱敏：token、deviceId、MAC、时间戳可打码或替换。

---

## 免责声明

本项目仅用于**自有设备**的协议学习与调试。请勿用于未经授权的设备访问或控制。使用本插件产生的任何后果由使用者自行承担。

---

## License
