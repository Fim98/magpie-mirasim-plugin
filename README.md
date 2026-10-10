# magpie-mirasim-plugin

[Mirasim](https://mirasim.ai) 的订阅，作为 OpenCode / [magpie](https://github.com/yetone/magpie) 的插件使用，独立于 magpie 本体。

仓库：<https://github.com/Fim98/magpie-mirasim-plugin>

- 浏览器登录（GitHub / Google），或邮箱验证码登录
- 请求按官方桌面客户端的方式签名（Ed25519 设备密钥 + X25519/ChaCha20-Poly1305 密封）
- 模型列表与 reasoning 档位来自账号自己的 catalog / roster，并过滤 roster 下架的模型
- 用量（额度窗口）来自 relay 的 limits 路由
- Claude/DeepSeek/GLM/Kimi/Gemini 走 Anthropic Messages，GPT 走 OpenAI Responses
- 所有 relay 模型标注为支持图片输入
- Kimi 用中继自己的 id `kimi-k3`；旧写法 `kimi-code/k3` 仍可用，转发时改写回 `kimi-k3`
- DeepSeek 用中继自己的 id `deepseek-flash`；另发布 `deepseek-v4.1-flash`（与 aliyun 等同名，便于 magpie 路由分组），转发时改写回 `deepseek-flash`

## 安装

```
# 本机已有仓库
git clone git@github.com:Fim98/magpie-mirasim-plugin.git ~/Documents/magpie-mirasim-plugin
magpie plugin add ~/Documents/magpie-mirasim-plugin
```

本地路径安装的插件不会自动更新；改了 `index.mjs` 后在 magpie 里重启插件（或重启 magpie）即可生效，`git pull` 后同理。也可以发布成 npm 包后 `magpie plugin add <包名>`。

## 测试

```
bun test.mjs    # 与 magpie Go 实现的字节级交叉验证（cross-check.json 里的向量）
bun e2e.mjs     # 假 Mirasim 服务器驱动的端到端测试，258 项
```

`cross-check.json` 的向量由 magpie 源码仓库里 `internal/mirasim/cross_check_test.go` 生成（`go test ./internal/mirasim -run TestCross`，可用 `MIRASIM_CROSS_FILE` 指回本目录）；协议无改动时无需重新生成。

协议移植自 magpie 的 `internal/mirasim`（其又移植自 CLIProxyAPI 的 mirasim 支持与 Mirasim 桌面客户端）。

## 许可

[MIT License](LICENSE)。
