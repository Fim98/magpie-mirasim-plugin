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

## 测试

`node test.mjs`（签名/密封字节级交叉验证 + 归一化/别名/队列单元用例）
`node e2e.mjs`（假 Mirasim 驱动的端到端，含排队重试与 401 重试）

（本机没有 bun 时直接用 node 也可以，两者都只用标准 Web API 与 node: 内置模块。）