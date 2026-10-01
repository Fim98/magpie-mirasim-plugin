# opencode-mirasim-auth

[Mirasim](https://mirasim.ai) 的订阅，作为 OpenCode / magpie 的插件使用。

- 浏览器登录（GitHub / Google），或邮箱验证码登录
- 请求按官方桌面客户端的方式签名（Ed25519 设备密钥 + X25519/ChaCha20-Poly1305 密封）
- 模型列表与 reasoning 档位来自账号自己的 catalog / roster
- 用量（额度窗口）来自 relay 的 limits 路由
- Claude/DeepSeek/GLM/Kimi 走 Anthropic Messages，GPT 走 OpenAI Responses

## 安装（本地路径）

```
magpie plugin add /path/to/opencode-mirasim-auth
```

或发布为 npm 包后 `magpie plugin add <name>`。

协议移植自 magpie 的 `internal/mirasim`（其又移植自 CLIProxyAPI 的 mirasim 支持与 Mirasim 桌面客户端）。
