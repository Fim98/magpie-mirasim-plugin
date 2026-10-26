# 上游同步记录

本插件是 [cpa-plugin-mirasim](https://github.com/KIDA-MNESIA/cpa-plugin-mirasim)（CLIProxyAPI 的 Mirasim 插件，Go）行为在 OpenCode / magpie 上的 JS 移植。参考仓库默认在 `~/Documents/cpa-plugin-mirasim`。

上游是 CPA 的插件：它带协议翻译层、重置卡动作和额度管理页，这些在本插件里没有对应物（本插件只做 provider：签名/密封请求、catalog/roster、额度 hook）。所以每次同步都要逐条判断「上游改动是否适用于本插件」，而不是整体 cherry-pick。

## 上次同步到的上游 commit

**`5946c84`**（2026-10-12，Recognize client refusals in model probes）

同步时只取适用范围；未取的部分见下表状态列。

## 如何同步下一次

```sh
# 1. 看上次同步点之后有哪些新 commit
cd ~/Documents/cpa-plugin-mirasim
git log --oneline 5946c84..HEAD

# 2. 逐个看改了什么
git show <sha>

# 3. 判断是否适用：
#    - 签名/密封、请求头、重试、模型 catalog/roster、额度、家族与 thinking 表单 → 取
#    - 协议翻译层（Messages<->OpenAI/Gemini）、CPA 路由、重置卡、额度管理页、Go 插件版本 → 跳过
#
# 4. 取完后更新本文件的「上次同步到的上游 commit」和下面的对照表
```

## 对照表

| 上游 commit | 日期 | 摘要 | 本插件 | 状态 |
| --- | --- | --- | --- | --- |
| `fb13da3` | 2026-09-28 | 以 0.0.372 签名并刷新 fallback catalog | `9bb8a20` | 基线（初始移植） |
| `16438c0` | 2026-10-01 | 修复被翻译的 Codex 流失败 | — | 跳过：本插件无翻译层，宿主 SDK 读原生 wire |
| `367331f` | 2026-10-01 | 发布新 Claude 模型的 roster 思考能力 | `e23c4d4` | 已取 |
| `c430c4d` | 2026-10-04 | 客户端签名版本改为 0.0.403 | `efa0bb1` | 已取 |
| `d364969` | 2026-10-04 | 标准额度重置里兑换 Mirasim 重置卡 | — | 跳过：本插件无重置动作 |
| `e55aa94` | 2026-10-04 | Kimi 请求发往中继自己的 model id | `efa0bb1` | 已取（后按真实中继行为改了，见下） |
| `3acbce1` | 2026-10-04 | 本地插件版本对齐 release | — | 跳过：Go 插件自身的 pluginVersion |
| `781a6f5` | 2026-10-07 | 保留 Messages 流失败并检测截断 | — | 跳过：宿主 SDK 负责流，插件只转发 |
| `bc98853` | 2026-10-07 | roster 未声明 adaptive 时保留非 Claude 的 effort | `efa0bb1` | 已取 |
| `09ae4e0` | 2026-10-07 | 通过 Mirasim Messages 中继暴露 Gemini | `efa0bb1` | 已取 |
| `be070a1` | 2026-10-07 | 从实时/缓存/fallback catalog 过滤下架模型 | `efa0bb1` | 已取 |
| `920c034` | 2026-10-07 | 中继模型标注图片输入并验证协议转换 | `efa0bb1` | 已取 |
| `8e68390` | 2026-10-07 | 额度页一键测试所有模型 | — | 跳过：本插件无管理页 |
| `d43ef3f` | 2026-10-11 | 修复 Messages 响应翻译 + 中继排队重试 | 本次 | 部分取：取「排队 503 等待重发」与「401 换新 ticket 重试」；翻译部分跳过 |
| `5946c84` | 2026-10-12 | 额度探针识别客户端被拒 | — | 跳过：额度页探针专用 |

## 有意保留的差异

这些不是遗漏，是按真实中继行为做的取舍，上游若改动需重新核对：

- **Kimi 的 id**：上游 `e55aa94` 用中继的 `kimi-code/k3`；但真实中继以 `kimi-k3` 提供服务，`kimi-code/k3` 会被拒（"not supported at this time"）。本插件 `a1c00de` 起反过来：以 `kimi-k3` 为准，`kimi-code/k3` 作为别名发布，转发时改写回 `kimi-k3`。
- **DeepSeek 的别名**：另发布 `deepseek-v4.1-flash`（与 aliyun、WorkBuddy AI 同名，便于 magpie 路由分组），转发时改写回中继的 `deepseek-flash`。

## 本次同步的细节（`d43ef3f`）

- **排队重试**（`index.mjs` 的 `queueModelCall` / `queueRefused` / `queueRetryDelay` / `queueHold` / `waitQueueRetry` / `peekQueueBody` / `replayResponse`）：仅对 `POST /v1/messages`、`/v1/responses` 生效；只有明确的排队信号（`X-Router-Queue-Class` 头，或 body 里 `platform_queue_full`）才重发；间隔取 `Retry-After`（秒，夹在 1–60 秒，缺省 5 秒）；单次请求最多等约 4 分钟；调用方 abort 立即停止等待；每次重发都用新签名（新 nonce/时间戳/call id）。
- **401 换 ticket 重试**（`refuseTicket` + `ask` 循环）：中继 401 时清掉缓存的 ticket、重新 mint 后重发一次；30 秒内再次 401 则直接返回，避免 mint 风暴。
- **未取**：上游让 CPA 的非流式翻译去聚合 SSE（`messagesNonStreamPayload`、`Accept: text/event-stream`）。本插件不翻译，宿主 SDK 直接读中继的原生响应。

## 客户端 0.0.639 复核（2026-10-26）

`/Applications/Mirasim.app`（`@mirasim/desktop` 0.0.639，Electron 44.7.0）逐项对照的结果。结论：签名/密封协议没有换代，登录流程没有实质变化；请求头多出 turn/`traceparent`，客户端版本号该跟着走。对照代码在 `Contents/Resources/server-main.cjs`（中继侧，17 MB 打包），crypto core 是内嵌的 WASM（`cc_sign`/`cc_seal`）。

- **签名与密封仍是 `mrs-sig-v2` / `mrs-seal-v1`**：WASM 里只有这两个版本字符串，规范串仍是 `method\0path\0ts\0nonce\0deviceId\0clientVersion\0credential` + 元数据 + body，元数据在推理路由上封成 `x-mirasim-enc`（`x-mirasim-client` 与 envelope 本身留在明文）。**已取**：`x-mirasim-client` 从 0.0.403 改为 0.0.639。
- **登录**：`GET /auth/oauth/providers`、`GET {auth}/auth/oauth/{provider}/login?redirect_uri=&state=`、回环端口收 `access_token`/`token` + `refresh_token`、`POST /auth/code` + `POST /auth/verify`、`POST /auth/refresh {refresh_token}`、`GET /auth/me` —— 与插件实现一致（客户端把随机串放在回调**路径** `/callback/<random>` 上，插件用固定路径 + `state` 参数，语义等价）。设备身份仍是本地 `~/.mirasim/device.json` 的 UUID + 独立 Ed25519 密钥，没有设备注册接口。
- **请求头**：除插件已有的 `x-mirasim-session` / `-agent` / `-call` / `-account` / `-locale` / `-collect` 外，客户端每个被代理的调用还带 **`x-mirasim-turn`**（一轮对话的 id），并由它派生 **`traceparent`**（`00-<32hex>-<后16hex>-01`，非 UUID 则不派生）。**已取**：每次推理生成一个 turn（这里一次调用即一轮）与对应 traceparent。
- **`x-mirasim-repo` / `x-mirasim-git-head`**：只在 token 的 `tenant` 是 `internal`/`external`（官方/合作方账号）时发送，普通账号不发。**不取**。
- **描述性路由（models/roster/limits）**：客户端自己取 roster 与 limits 时用的是**不密封**的签名头（`/v1/model-roster` 直连、limits 探针带 `x-mirasim-probe: usage`），与插件现状一致。**不改**。
- **消耗上报**：客户端**不上报**中继计费的调用。它把调用记进本地账本（`session-usage-YYYY-MM.ndjson`，含 `callId`/`providerCallId`/`viaRelay`/`leg`），再用 `GET {relay}/usage/calls?ids=&from=&to=`（签名，`authorization: Bearer <ticket|access>`）回查中继自己的计费记录来补 token；只有当调用是 `leg === "direct"`（本机自带 key、不经中继）时才把按天聚合的 `{device, mode, from?, days:[{day,input,output,cacheRead,cacheWrite,calls,models,agents}]}` `POST {site}/api/leaderboard/usage`（还需先 `/join`，可 `/sync` 关掉）。中继计费的调用由中继自己记账，**重复上报反而会对不上账**。本插件没有 direct 调用，所以这里**不取**；需要核对时按客户端同样的读法用 `/usage/calls` 查即可。

## 测试

`node test.mjs`（签名/密封字节级交叉验证 + 归一化/别名/队列单元用例）
`node e2e.mjs`（假 Mirasim 驱动的端到端，含排队重试与 401 重试）

（本机没有 bun 时直接用 node 也可以，两者都只用标准 Web API 与 node: 内置模块。）