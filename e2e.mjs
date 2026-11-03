// The plugin driven end to end against a fake Mirasim: the authentication
// service's browser round, the relay's session, models, roster, limits and
// the two inference routes, every signature verified and the sealed header
// opened. Run: bun mirasim-plugin/e2e.mjs
import { createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, verify as cryptoVerify, randomUUID } from "node:crypto"
import { createServer } from "node:http"

// ---- the fake services -----------------------------------------------------------

const seal = generateKeyPairSync("x25519")
const sealPublicB64 = createPublicKey(seal.privateKey).export({ type: "spki", format: "der" }).subarray(-32).toString("base64")

const ADMIN_TOKEN = "adm-token-1"
const ADMIN_TOKEN_2 = "adm-token-2"
const REFRESH_1 = "refresh-1"
const REFRESH_2 = "refresh-2"
const TICKET = "ticket-abc"

const state = {
  refreshes: 0, // refresh-token trades the admin saw
  sessionMints: 0, // device sessions the relay minted
  messageCalls: [], // what /v1/messages got: {headers, body}
  responseCalls: [],
  ticketCalls: 0, // requests the relay answered with the ticket as the credential
  accessCalls: 0, // and with the access token itself
  queueAttempts: 0, // the queued model's refusals and final success
  queueCalls: [], // the sealed metadata the queued model's attempts carried
  plainAttempts: 0, // a 503 that is not a queue refusal
  ticketRefusals: 0, // relay 401s that ask for a fresh device ticket
  limitsRefused: false, // the allowance read answered with the region refusal
  creditsRefused: false, // the ledger read answered with a refusal of its own
}

// who signed in, and what it can call
const PROFILE = { email: "u@example.com", plan: "pro", plan_exp: Math.floor(Date.now() / 1000) + 86400 }
const MODELS = {
  data: [
    { id: "claude-sonnet-4-8", max_input_tokens: 180000 },
    { id: "claude-queue-503", max_input_tokens: 180000 },
    { id: "claude-plain-503", max_input_tokens: 180000 },
    { id: "claude-401-once", max_input_tokens: 180000 },
    { id: "claude-haiku-4-5-20251001", max_input_tokens: 180000 },
    { id: "claude-haiku-4-5", max_input_tokens: 180000 },
    { id: "gpt-6", max_input_tokens: 260000 },
    { id: "glm-5", max_input_tokens: 120000 },
    { id: "deepseek-flash", max_input_tokens: 1000000 },
    { id: "kimi-k3", max_input_tokens: 1048576 },
    { id: "gemini-3.1-pro-preview", max_input_tokens: 1048576 },
    { id: "claude-future-9", max_input_tokens: 1000000 },
    { id: "claude-future-10", max_input_tokens: 200000 },
    { id: "claude-future-11", max_input_tokens: 150000 },
    { id: "claude-retired-9", max_input_tokens: 100000 },
    { id: "provider/model", max_input_tokens: 1000 },
    { id: "*", max_input_tokens: 1000 },
  ],
}
const ROSTER = {
  version: "1",
  withdrawn: ["claude-retired-9"],
  agents: {
    claude: [{ id: "claude-sonnet-4-8", label: "Sonnet 4.8", contextWindow: 200000, maxOutput: 64000, effort: ["low", "high"], adaptive: true }],
    zcode: [{ id: "glm-5", contextWindow: 128000, adaptive: false }],
    kimi: [{ id: "kimi-k3", contextWindow: 1048576, effort: ["low", "high", "max"] }],
  },
  models: {
    "claude-future-9": { label: "Future 9", contextWindow: 1000000, maxOutput: 128000 },
    "claude-future-10": { contextWindow: 200000, effort: ["low", " HIGH ", "high", "off", "unsupported", "max"] },
    "claude-future-11": { adaptive: true },
  },
}
const LIMITS_NORMAL = {
  paid: true,
  windows: [
    { name: "5h", budget: 100, used: 42.5, reset_at: Math.floor(Date.now() / 1000) + 3600 },
    { name: "7d", budget: 500, used: 300, reset_at: null },
  ],
}
// what the relay has answered the 30d window since 2026-10-23: the window's
// own end plus a century, which the official client shows as-is
const LIMITS_CENTURY = { paid: false, windows: [{ name: "30d", budget: 8591, used: 193.604149, reset_at: 4945084567 }] }
let LIMITS = LIMITS_NORMAL
// the ledger the client's 个人额度 card reads: amounts are hundredths of a 额度
const CREDITS = {
  period: { resetAt: null },
  items: [
    { id: "grant:1", at: 1792742436218, kind: "grant", credits: 10000, state: "applied", title: "Original", source: { type: "platform" } },
    { id: "adjust:2", at: 1793260816839, kind: "adjust", credits: -4250, state: "applied", title: "Adjustment", source: { type: "platform" } },
  ],
  balance: { remaining: 5750, lots: [{ id: "1", credits: 10000, remaining: 5750, grantedAt: 1792742436218, expiresAt: 1808495999000, kind: "carry" }] },
}

const sha256hex = (v) => createHash("sha256").update(v ?? "").digest("hex")
const b64urlDec = (s) => Buffer.from(s, "base64url")

// unseal opens the x-mirasim-enc the plugin sealed: the same key the relay
// derives, the same keystream.
function unseal(packed, method, path) {
  const buf = b64urlDec(packed)
  const ephPublicRaw = buf.subarray(0, 32)
  const nonce = buf.subarray(32, 44)
  const ciphertext = buf.subarray(44, -16)
  const shared = diffieHellman({ privateKey: seal.privateKey, publicKey: createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), ephPublicRaw]), format: "der", type: "spki" }) })
  const key = Buffer.from(hkdfSync("sha256", shared, ephPublicRaw, Buffer.from("mrs-seal-v1"), 32))
  const aad = Buffer.from(["mrs-seal-v1", method, path].join("\n"))
  // the ChaCha20 keystream at counter 1, from the plugin's own primitives
  const { chacha20 } = e2eInternals
  const plaintext = chacha20(key, 1, nonce, ciphertext)
  void aad
  return JSON.parse(plaintext.toString("utf8"))
}

// checkSignature verifies a request the plugin signed: the Ed25519
// signature over the canonical payload, with the device public key the
// session named. On an inference route the transport headers (device, ts,
// nonce, sig) are sealed into x-mirasim-enc with the metadata, as the
// official client sends it; on a descriptive one they are clear.
function checkSignature(req, body, devicePublicB6, credential, t) {
  const enc = req.headers["x-mirasim-enc"]
  const sealed = enc ? unseal(enc, req.method, req.url) : {}
  const id = sealed["x-mirasim-device"] ?? req.headers["x-mirasim-device"]
  const ts = sealed["x-mirasim-ts"] ?? req.headers["x-mirasim-ts"]
  const nonce = sealed["x-mirasim-nonce"] ?? req.headers["x-mirasim-nonce"]
  const sig = sealed["x-mirasim-sig"] ?? req.headers["x-mirasim-sig"]
  const client = req.headers["x-mirasim-client"]
  t.ok(id && ts && nonce && sig, "the signature headers are on" + (enc ? " (sealed)" : ""))
  t.ok(client === "0.0.737", "the client version is reported")
  // on a sealed request only the client and the envelope are clear
  for (const name of Object.keys(req.headers)) {
    if (enc) {
      t.ok(!(name.startsWith("x-mirasim-") && name !== "x-mirasim-enc" && name !== "x-mirasim-client"), "no clear x-mirasim-* beside the envelope: " + name)
    } else {
      t.ok(name !== "x-mirasim-enc", "a descriptive route carries no envelope")
    }
  }
  // the metadata the payload signed: what the relay correlates a call by;
  // the transport fields (device, ts, nonce, sig) are kept out of the digest
  const transport = new Set(["x-mirasim-device", "x-mirasim-ts", "x-mirasim-nonce", "x-mirasim-sig"])
  const canonical = Object.keys(sealed)
    .filter((k) => sealed[k] && !transport.has(k))
    .sort()
    .map((k) => k + ":" + sealed[k])
    .join("\n")
  const payload = ["mrs-sig-v2", req.method, req.url, ts, nonce, id, client, sha256hex(credential), canonical ? sha256hex(canonical) : "", sha256hex(body)].join("\n")
  const pub = createPublicKey({ key: Buffer.from(devicePublicB6, "base64"), format: "der", type: "spki" })
  t.ok(cryptoVerify(null, Buffer.from(payload), pub, b64urlDec(sig)), "the Ed25519 signature verifies")
  const out = { ...sealed }
  for (const k of transport) delete out[k]
  return out
}
const devicePubB64 = (publicB6) => publicB6 // the SPKI DER, as base64

let devicePublicB6 = "" // what the last session mint named
let currentAccess = ADMIN_TOKEN
let currentRefresh = REFRESH_1

const admin = createServer((req, res) => {
  const json = (o) => {
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify(o))
  }
  const bearer = (req.headers.authorization ?? "").replace(/^Bearer /, "")
  switch (req.url) {
    case "/auth/oauth/providers":
      return json({ providers: ["github", "google"] })
    case "/auth/me":
      if (bearer !== currentAccess) {
        res.writeHead(401)
        return res.end()
      }
      return json(PROFILE)
    case "/auth/code":
      return json({})
    case "/auth/verify": {
      let body = ""
      req.on("data", (c) => (body += c))
      return req.on("end", () => {
        let ask = {}
        try {
          ask = JSON.parse(body)
        } catch {}
        const address = String(ask.email ?? "")
        if (address.startsWith("mfa")) {
          // an account with two-step verification on: the code is good, the
          // confirmation is still owed
          state.mfaTicket = "tkt_mfa_" + (state.mfaTickets + 1)
          state.mfaTickets++
          state.mfaPolls = 0
          state.mfaDeny = address.startsWith("mfa-denied@")
          res.writeHead(403, { "Content-Type": "application/json" })
          return res.end(
            JSON.stringify({
              code: "mfa_required",
              detail: {
                code: "mfa_required",
                mfa: {
                  ticket: state.mfaTicket,
                  url: state.mfaDeny ? "https://mirasim.ai/confirm/deny" : "https://mirasim.ai/confirm/abc",
                  code: "ABC-123",
                  expires_in: 30,
                  interval: 1,
                  enroll: false,
                },
              },
            }),
          )
        }
        return json({ access_token: currentAccess, refresh_token: currentRefresh })
      })
    }
    case "/auth/mfa/poll": {
      let body = ""
      req.on("data", (c) => (body += c))
      return req.on("end", () => {
        let ask = {}
        try {
          ask = JSON.parse(body)
        } catch {}
        if (!state.mfaTicket || ask.ticket !== state.mfaTicket) {
          res.writeHead(400, { "Content-Type": "application/json" })
          return res.end(JSON.stringify({ error: "bad ticket" }))
        }
        state.mfaPolls++
        if (state.mfaDeny) return json({ status: "denied" })
        if (state.mfaPolls < 2) return json({ status: "pending" })
        return json({ status: "confirmed", access_token: currentAccess, refresh_token: currentRefresh })
      })
    }
    case "/auth/refresh":
      if ((req.headers["content-type"] ?? "").includes("json")) {
        let body = ""
        req.on("data", (c) => (body += c))
        req.on("end", () => {
          state.refreshes++
          const ask = JSON.parse(body)
          if (ask.refresh_token !== currentRefresh) {
            res.writeHead(401)
            return res.end("bad refresh token")
          }
          currentAccess = currentAccess === ADMIN_TOKEN ? ADMIN_TOKEN_2 : ADMIN_TOKEN
          currentRefresh = currentRefresh === REFRESH_1 ? REFRESH_2 : REFRESH_1
          return json({ access_token: currentAccess, refresh_token: currentRefresh, expires_in: 3600 })
        })
      }
      return
    default:
      if (req.url.startsWith("/auth/oauth/github/login")) {
        const u = new URL(req.url, "http://x")
        const back = new URL(u.searchParams.get("redirect_uri"))
        back.searchParams.set("access_token", currentAccess)
        back.searchParams.set("refresh_token", currentRefresh)
        back.searchParams.set("state", u.searchParams.get("state"))
        res.writeHead(302, { Location: back.href })
        return res.end()
      }
      res.writeHead(404)
      return res.end()
  }
})

const relay = createServer((req, res) => {
  const json = (o) => {
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify(o))
  }
  let body = ""
  req.on("data", (c) => (body += c))
  req.on("end", () => {
    const credential = (req.headers.authorization ?? "").replace(/^Bearer /, "")
    if (req.url === "/v1/device/session" && req.method === "POST") {
      if (state.mintRegionBlocked) {
        res.writeHead(429, { "Content-Type": "application/json" })
        return res.end(
          JSON.stringify({
            error: { message: "云端中转未在当前网络区域提供服务。/ The cloud route is not served to this network region.", type: "shared_quota_unavailable" },
            type: "error",
          }),
        )
      }
      const ask = JSON.parse(body)
      devicePublicB6 = ask.publicKey
      state.sessionMints++
      return json({ ticket: TICKET, expiresIn: 600 })
    }
    if (credential === TICKET) state.ticketCalls++
    else if (credential === currentAccess || credential === ADMIN_TOKEN || credential === ADMIN_TOKEN_2) state.accessCalls++
    if (req.url === "/v1/models" && req.method === "GET") {
      checkSignature(req, "", devicePublicB6, credential, t)
      if (state.modelsRegionBlocked) {
        res.writeHead(429, { "Content-Type": "application/json" })
        return res.end(JSON.stringify({ error: { message: "not served to this network region", type: "shared_quota_unavailable" }, type: "error" }))
      }
      return json(MODELS)
    }
    if (req.url === "/v1/model-roster" && req.method === "GET") {
      return json(ROSTER)
    }
    if (req.url === "/v1/limits" && req.method === "GET") {
      if (state.limitsRefused) {
        res.writeHead(429, { "Content-Type": "application/json" })
        return res.end('{"error":{"message":"云端中转未在当前网络区域提供服务。","type":"shared_quota_unavailable"},"type":"error"}')
      }
      return json(LIMITS)
    }
    if (req.url.startsWith("/v1/credits/activity") && req.method === "GET") {
      t.eq(req.headers.authorization, "Bearer " + currentAccess, "the ledger is read with the account's access token, nothing signed")
      if (state.creditsRefused) {
        res.writeHead(403, { "Content-Type": "application/json" })
        return res.end('{"error":{"code":"token_invalid"}}')
      }
      return json(CREDITS)
    }
    if (req.url === "/v1/messages" && req.method === "POST") {
      if (process.env.E2E_DEBUG) console.error("MSGS HEADERS", JSON.stringify(req.headers), "BODY", body.slice(0, 200))
      const sealed = checkSignature(req, body, devicePublicB6, credential, t)
      const model = String(JSON.parse(body).model ?? "")
      if (model === "claude-queue-503") {
        state.queueAttempts++
        state.queueCalls.push(sealed)
        if (state.queueAttempts <= 2) {
          res.writeHead(503, { "Content-Type": "application/json", "X-Router-Queue-Class": "model", "Retry-After": "1" })
          return res.end('{"error":{"code":"platform_queue_full"}}')
        }
      }
      if (model === "claude-plain-503") {
        state.plainAttempts++
        res.writeHead(503, { "Content-Type": "application/json" })
        return res.end('{"error":{"code":"model_unavailable"}}')
      }
      if (model === "claude-401-once") {
        state.ticketRefusals++
        if (state.ticketRefusals === 1) {
          res.writeHead(401, { "Content-Type": "application/json" })
          return res.end('{"error":"Mirasim relay rejected the current device ticket"}')
        }
      }
      if (model.startsWith("gemini-")) t.ok(sealed["x-mirasim-agent"] === "pi", "the agent is pi for a Gemini model")
      else if (model.startsWith("kimi-")) t.ok(sealed["x-mirasim-agent"] === "kimi", "the agent is kimi for a Kimi model")
      else if (model.startsWith("deepseek-")) t.ok(sealed["x-mirasim-agent"] === "dsh", "the agent is dsh for a DeepSeek model")
      else t.ok(sealed["x-mirasim-agent"] === "claude", "the agent is claude for a Claude model")
      t.ok(sealed["x-mirasim-session"].startsWith("mirasim_"), "the session is named: " + sealed["x-mirasim-session"])
      t.ok(sealed["x-mirasim-call"], "the call is named")
      const turn = String(sealed["x-mirasim-turn"] ?? "").replace(/-/g, "")
      t.eq(turn.length, 32, "the call names its turn")
      t.eq(req.headers["traceparent"], "00-" + turn + "-" + turn.slice(16) + "-01", "the traceparent follows the turn")
      t.ok(!(req.headers["anthropic-beta"] ?? "").includes("oauth-2025-04-20"), "the OAuth beta is dropped")
      state.messageCalls.push({ headers: req.headers, body: JSON.parse(body) })
      res.writeHead(200, { "Content-Type": "text/event-stream" })
      for (const e of [
        `{"type":"message_start","message":{"id":"m","type":"message","role":"assistant","model":"claude-sonnet-4-8","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}`,
        `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
        `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi from fake mirasim"}}`,
        `{"type":"content_block_stop","index":0}`,
        `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`,
        `{"type":"message_stop"}`,
      ]) {
        res.write("data: " + e + "\n\n")
      }
      return res.end()
    }
    if (req.url === "/v1/responses" && req.method === "POST") {
      const sealed = checkSignature(req, body, devicePublicB6, credential, t)
      t.ok(sealed["x-mirasim-agent"] === "codex", "the agent is codex on the Responses route")
      state.responseCalls.push({ headers: req.headers, body: JSON.parse(body) })
      res.writeHead(200, { "Content-Type": "text/event-stream" })
      res.write(`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"m1"}}\n\n`)
      res.write(`data: {"type":"response.output_text.delta","item_id":"m1","delta":"hi from responses"}\n\n`)
      res.write(`data: {"type":"response.completed","response":{"id":"r","usage":{"input_tokens":1,"output_tokens":2}}}\n\n`)
      return res.end()
    }
    res.writeHead(404)
    res.end()
  })
})

// ---- the harness -------------------------------------------------------------------

let failed = 0
let passed = 0
const t = {
  ok(v, name) {
    if (v) passed++
    else {
      failed++
      console.error("✗ " + name)
    }
  },
  eq(got, want, name) {
    if (got === want) passed++
    else {
      failed++
      console.error(`✗ ${name}\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(want)}`)
    }
  },
}

const e2eInternals = {} // chacha20 for unseal, filled after the import

async function main() {
  process.env.MIRASIM_SEAL_PUBKEY = sealPublicB64
  await listen(admin)
  await listen(relay)
  process.env.MIRASIM_ADMIN_URL = `http://127.0.0.1:${admin.address().port}`
  process.env.MIRASIM_RELAY_URL = `http://127.0.0.1:${relay.address().port}`
  process.env.MIRASIM_CLIENT_VERSION = "0.0.737"
  // a two-step confirmation opens a page; the test must not open one
  process.env.MIRASIM_NO_OPEN = "1"

  const mod = await import("./index.mjs")
  const internals = mod._internal
  e2eInternals.chacha20 = internals.chacha20
  t.eq(internals.DEFAULT_CLIENT_VERSION, "0.0.737", "the plugin signs as the released desktop client")

  // ---- the browser sign-in
  let saved = null
  const client = { auth: { set: async (o) => (saved = o.body) } }
  const plugin = await mod.MirasimAuthPlugin({ client })
  const browser = plugin.auth.methods[0]
  const a = await browser.authorize({ provider: "github" })
  t.ok(a.url.includes("/auth/oauth/github/login"), "the login URL names the provider")
  t.ok(a.method === "auto", "the method is the browser's")
  // the browser: follow the login round to the loopback callback
  const page = await fetch(a.url, { redirect: "follow" })
  t.eq(page.status, 200, "the callback page answers")
  const result = await a.callback()
  t.eq(result.type, "success", "the sign-in finishes")
  t.eq(result.access, currentAccess, "the access token is kept")
  t.eq(result.refresh, currentRefresh, "the refresh token is kept")
  t.ok(result.deviceKey.includes("BEGIN PRIVATE KEY"), "a device key is made")
  t.ok(result.models.includes("claude-sonnet-4-8"), "the catalog is kept")
  t.ok(result.roster.includes("glm-5"), "the roster is kept")
  t.eq(result.email, PROFILE.email, "the email is kept")
  t.eq(result.plan, "pro", "the plan is kept")
  // as the host's save keeps it: the tokens and what the plugin named beside
  const { type: _t, provider: _p, ...record } = result
  saved = { type: "oauth", ...record }
  t.ok(saved.access && saved.deviceKey, "the record is saved")

  // the catalog, narrowed the way the official client narrows it: no dated
  // twin, no namespaced id, no placeholder
  const ids = internals.parseModels(result.models).map((m) => m.id)
  t.ok(!ids.includes("claude-haiku-4-5-20251001"), "the dated twin is dropped")
  t.ok(!ids.includes("provider/model"), "namespaced ids are dropped")
  t.ok(!ids.includes("*"), "the placeholder is dropped")
  t.ok(ids.includes("claude-haiku-4-5"), "the plain twin stays")
  t.ok(state.sessionMints === 1, "a device session was minted to validate the credential")

  // ---- a request through the loader
  const loader = await plugin.auth.loader(async () => saved)
  t.ok(loader.baseURL.endsWith("/v1"), "the base URL is the relay's /v1: " + loader.baseURL)
  const res = await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Anthropic-Version": "2023-06-01",
      "Anthropic-Beta": "oauth-2025-04-20,context-1m-2025-08-07",
    },
    body: JSON.stringify({ model: "claude-sonnet-4-8", max_tokens: 64000, thinking: { type: "enabled", budget_tokens: 20000 }, messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(res.status, 200, "the message request answers")
  t.eq(res.headers.get("x-mirasim-session") ?? "", "", "no x-mirasim-session header leaks back")
  t.eq(res.headers.get("X-Magpie-Sign-In"), "kept", "the answer says the sign-in is kept")
  const text = await res.text()
  t.ok(text.includes("hi from fake mirasim"), "the reply streams through")
  t.eq(state.messageCalls.length, 1, "one call was made")
  const sent = state.messageCalls[0].body
  t.eq(sent.thinking.type, "adaptive", "the budget became an effort")
  t.eq(sent.output_config.effort, "high", "20000 tokens map onto high")
  t.ok(!("budget_tokens" in sent.thinking), "the budget is gone")
  t.ok((sent.model = "claude-sonnet-4-8"), "the model is as asked")
  t.ok((state.messageCalls[0].headers["anthropic-beta"] ?? "").includes("context-1m-2025-08-07"), "the other beta stays")
  t.ok(state.ticketCalls >= 1, "the request was sent with the ticket")

  // the relay serves Messages only to the Mirasim client or Claude Code: a
  // host's own user-agent is renamed, a Claude Code call keeps its own
  t.ok(
    String(state.messageCalls[0].headers["user-agent"] ?? "").startsWith("Mirasim/"),
    "the caller's own user-agent is replaced with the client this plugin signs as",
  )
  await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "claude-cli/2.1.4 (external, cli)" },
    body: JSON.stringify({ model: "claude-sonnet-4-8", max_tokens: 8, messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(
    state.messageCalls[state.messageCalls.length - 1].headers["user-agent"],
    "claude-cli/2.1.4 (external, cli)",
    "a Claude Code call keeps its own user-agent",
  )

  // a GET through the same fetch: the model list, carrying no body at all
  const listRes = await loader.fetch(loader.baseURL + "/models", { method: "GET" })
  t.eq(listRes.status, 200, "a GET through the plugin answers")
  const listBody = await listRes.json()
  t.ok(Array.isArray(listBody.data), "the catalog comes back")

  // the relay refusing this network region: the mint's 429 is not turned into
  // a 502, and the reason says where to look
  const otherDevice = { ...saved, deviceKey: internals.newDeviceKey() }
  state.mintRegionBlocked = true
  const regionLoader = await plugin.auth.loader(async () => otherDevice)
  const region = await regionLoader.fetch(regionLoader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-sonnet-4-8", max_tokens: 8, messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(region.status, 429, "a region refusal keeps the relay's own status")
  t.ok((await region.text()).includes("network region"), "the answer says the relay isn't served here")
  state.mintRegionBlocked = false

  // a second request within the ticket's life mints nothing
  await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-sonnet-4-8", messages: [{ role: "user", content: "again" }] }),
  })
  t.eq(state.sessionMints, 1, "the ticket is reused")

  // ---- a Responses request, its effort folded
  const res2 = await loader.fetch(loader.baseURL + "/responses", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "gpt-6", instructions: "i", input: "x", reasoning: { effort: "minimal" } }),
  })
  t.eq(res2.status, 200, "the responses request answers")
  t.ok((await res2.text()).includes("hi from responses"), "the responses reply streams through")
  t.eq(state.responseCalls[0].body.reasoning.effort, "low", "minimal folds onto low")

  // ---- a Gemini request: the Messages wire, the relay's "pi" agent, and a
  // budget-default thinking form (off disables, minimal is the least budget)
  const resG = await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "gemini-3.1-pro-preview", max_tokens: 4096, thinking: { type: "adaptive" }, output_config: { effort: "off" }, messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(resG.status, 200, "the gemini request answers")
  const gSent = state.messageCalls.at(-1).body
  t.eq(gSent.thinking.type, "disabled", "gemini's off is the disabled form")
  t.eq("output_config" in gSent, false, "gemini's off drops the effort")
  await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "gemini-3.1-pro-preview", max_tokens: 4096, output_config: { effort: "minimal" }, messages: [{ role: "user", content: "hi" }] }),
  })
  const gMin = state.messageCalls.at(-1).body
  t.eq(gMin.thinking.type, "enabled", "gemini's minimal is a budget")
  t.eq(gMin.thinking.budget_tokens, 1024, "gemini's minimal budget")

  // ---- a request selecting Kimi's old selector sends the relay's own id
  await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "kimi-code/k3", messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(state.messageCalls.at(-1).body.model, "kimi-k3", "Kimi's old selector resolves to the relay id")

  // ---- a request naming DeepSeek's group name sends the relay's own id
  await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "deepseek-v4.1-flash", messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(state.messageCalls.at(-1).body.model, "deepseek-flash", "DeepSeek's group name resolves to the relay id")

  // ---- the usage hook
  const u = await plugin.auth.usage(async () => saved)
  t.eq(u.plan, "pro", "the usage names the plan")
  t.eq(u.renew, "auto", "a paid account renews")
  t.eq(u.windows.length, 2, "both windows")
  t.eq(u.windows[0].name, "5h", "the 5h window")
  t.eq(u.windows[0].used, 42.5, "the 5h percentage")
  t.ok(u.windows[0].resetSecs > 3500, "the reset seconds")
  t.eq(u.signIn, "kept", "a clean read keeps the sign-in")

  // ---- a reset a century out is the relay's "no reset scheduled": the window
  // keeps its use and loses a countdown nothing can wait for
  LIMITS = LIMITS_CENTURY
  const far = await plugin.auth.usage(async () => saved)
  t.eq(far.windows.length, 1, "the century-out window is still read")
  t.eq(far.windows[0].name, "30d", "the window keeps its name")
  t.eq(far.windows[0].used, 2.3, "and its use")
  t.eq(far.windows[0].resetsAt, undefined, "its century-out reset is dropped")
  t.eq(far.windows[0].resetSecs, undefined, "and its countdown with it")
  LIMITS = LIMITS_NORMAL

  // ---- a refused allowance read says what the refusal means, as the calls do
  state.limitsRefused = true
  const refused = await plugin.auth.usage(async () => saved)
  t.ok(/network region/.test(refused.error ?? ""), "the refusal keeps the relay's words")
  t.ok(/proxy/.test(refused.error ?? ""), "and says to point the provider at one that reaches the relay")
  t.eq(refused.signIn, "kept", "a refusal is not a lapsed sign-in")
  state.limitsRefused = false

  // ---- the ledger answers the amount the client's own card shows ("83.97 /
  // 85.91" in the 个人额度 panel): granted and spent 额度 on the account's
  // window, and only there
  const led = await plugin.auth.usage(async () => saved)
  t.eq(led.windows.length, 2, "both windows are still read")
  t.eq(led.windows[0].limit, 100, "the ledger's grant is the window's limit")
  t.eq(led.windows[0].amount, 42.5, "and its spend the window's amount")
  t.eq(led.windows[1].amount, undefined, "a window the ledger does not describe carries no amounts")
  t.eq(led.windows[0].resetsAt !== undefined, true, "a real reset still rides along")

  // ---- a ledger that cannot be read leaves the percentage card as it was
  state.creditsRefused = true
  const noLedger = await plugin.auth.usage(async () => saved)
  t.eq(noLedger.windows[0].amount, undefined, "no ledger, no amounts")
  t.eq(noLedger.windows[0].used, 42.5, "and the percentage is untouched")
  t.eq(noLedger.error, undefined, "a failed ledger read is not the allowance's failure")
  state.creditsRefused = false

  // ---- the limits route silent, the ledger alone still draws the card
  LIMITS = { paid: false, windows: [] }
  const ledgerOnly = await plugin.auth.usage(async () => saved)
  t.eq(ledgerOnly.windows.length, 1, "one window from the ledger alone")
  t.eq(ledgerOnly.windows[0].name, "credits", "named for what it counts")
  t.eq(ledgerOnly.windows[0].used, 42.5, "the spend is the percentage")
  t.eq(ledgerOnly.windows[0].limit, 100, "the grant is the limit")
  t.eq(ledgerOnly.windows[0].amount, 42.5, "the spent part the amount")
  LIMITS = LIMITS_NORMAL

  // ---- the models hook
  const providerListed = await plugin.provider.models({ models: {} }, { auth: saved })
  t.ok(providerListed["claude-sonnet-4-8"], "the hook lists Sonnet")
  t.eq(providerListed["claude-sonnet-4-8"].api.npm, "@ai-sdk/anthropic", "Claude on the Anthropic wire")
  t.eq(providerListed["gpt-6"].api.npm, "@ai-sdk/openai", "GPT on the Responses wire")
  t.eq(providerListed["glm-5"].api.npm, "@ai-sdk/anthropic", "GLM on the Anthropic wire")
  t.eq(providerListed["claude-sonnet-4-8"].name, "Sonnet 4.8", "the roster's label")
  t.eq(providerListed["claude-sonnet-4-8"].limit.context, 200000, "the roster's window")
  t.ok(providerListed["claude-sonnet-4-8"].capabilities.reasoning, "Sonnet reasons")
  t.eq(providerListed["glm-5"].limit.context, 128000, "GLM's window")
  // a catalog-only model the roster gives a shape gets that shape, rungs the
  // family doesn't take dropped; one the roster only describes gets nothing
  // invented; one off the roster keeps the family's ladder
  t.eq(providerListed["claude-future-9"].name, "Future 9", "a metadata-only roster entry still names the model")
  t.ok(!providerListed["claude-future-9"].capabilities.reasoning, "a metadata-only roster entry invents no reasoning")
  t.eq(JSON.stringify(Object.keys(providerListed["claude-future-9"].variants)), "[]", "a metadata-only roster entry lists no variants")
  t.eq(JSON.stringify(Object.keys(providerListed["claude-future-10"].variants)), JSON.stringify(["low", "high", "max"]), "rungs the family doesn't take are dropped")
  t.eq(JSON.stringify(Object.keys(providerListed["claude-future-11"].variants)), JSON.stringify(["low", "medium", "high", "xhigh", "max", "ultra"]), "a shape without a ladder takes the family's")
  t.eq(JSON.stringify(Object.keys(providerListed["gpt-6"].variants)), JSON.stringify(["low", "medium", "high", "xhigh", "max", "ultra"]), "a model off the roster takes the family's ladder")
  // the relay's own Kimi id is kept and the old selector is published beside
  // it; a withdrawn model is gone; every relay model takes image input
  t.ok(providerListed["kimi-k3"], "the relay's Kimi id is listed")
  t.eq(providerListed["kimi-k3"].api.npm, "@ai-sdk/anthropic", "Kimi on the Anthropic wire")
  t.ok(providerListed["kimi-code/k3"], "Kimi's old selector is published beside the relay id")
  t.eq(providerListed["kimi-code/k3"].api.id, "kimi-code/k3", "the alias carries its own selector")
  t.ok(providerListed["deepseek-flash"], "the relay's DeepSeek id is listed")
  t.ok(providerListed["deepseek-v4.1-flash"], "DeepSeek's group name is published beside it")
  t.eq(providerListed["deepseek-v4.1-flash"].api.id, "deepseek-v4.1-flash", "the DeepSeek alias carries its own selector")
  t.eq(providerListed["gemini-3.1-pro-preview"].api.npm, "@ai-sdk/anthropic", "Gemini on the Messages wire")
  t.eq(JSON.stringify(Object.keys(providerListed["gemini-3.1-pro-preview"].variants)), JSON.stringify(["off", "minimal", "low", "medium", "high"]), "Gemini's own ladder")
  t.eq(providerListed["claude-retired-9"], undefined, "a withdrawn model is dropped")
  t.ok(providerListed["claude-sonnet-4-8"].capabilities.input.image, "every relay model takes image input")

  // ---- the sign-in refreshed near its end
  saved = { ...saved, expires: Date.now() + 60 * 1000 } // inside the 15-minute lead
  const wasSaved = saved
  const res3 = await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-sonnet-4-8", messages: [{ role: "user", content: "refresh me" }] }),
  })
  t.eq(res3.status, 200, "the request after a refresh answers")
  t.eq(res3.headers.get("X-Magpie-Sign-In"), "renewed", "the answer says the tokens were renewed")
  t.eq(state.refreshes, 1, "the refresh token was traded once")
  t.ok(saved !== wasSaved && saved.access === currentAccess, "the record holds the new pair")
  t.ok(saved.expires > Date.now() + 3000 * 1000, "the new end is an hour out")

  // ---- the relay's queue refusal is waited out and resubmitted: each attempt
  // is freshly signed (a new call id), the body is the same, the ticket is
  // reused
  const beforeQueueMints = state.sessionMints
  const resQ = await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-queue-503", messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(resQ.status, 200, "the queued request finally answers")
  t.ok((await resQ.text()).includes("hi from fake mirasim"), "the queued reply streams through")
  t.eq(state.queueAttempts, 3, "two queue refusals then the answer")
  t.eq(state.queueCalls.length, 3, "every attempt was signed")
  t.ok(state.queueCalls[0]["x-mirasim-call"] !== state.queueCalls[1]["x-mirasim-call"], "the retry signs a new call")
  t.ok(state.queueCalls[1]["x-mirasim-call"] !== state.queueCalls[2]["x-mirasim-call"], "the second retry signs a new call")
  t.eq(state.sessionMints, beforeQueueMints, "a queue retry reuses the ticket")

  // ---- a 503 that is not the relay's queue signal is returned unretried
  const resP = await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-plain-503", messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(resP.status, 503, "an ordinary 503 is returned")
  t.ok((await resP.text()).includes("model_unavailable"), "its body is preserved")
  t.eq(state.plainAttempts, 1, "an ordinary 503 is not retried")

  // ---- a relay 401 invalidates the ticket and retries under a fresh one
  const before401Mints = state.sessionMints
  const res4 = await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-401-once", messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(res4.status, 200, "a relay 401 is retried under a fresh ticket")
  t.eq(state.ticketRefusals, 2, "the ticket was refused only once")
  t.eq(state.sessionMints, before401Mints + 1, "the 401 retry minted a new ticket")

  // ---- a refused catalog does not empty the provider
  state.modelsRegionBlocked = true
  const fellBack = await plugin.provider.models({ models: {} }, { auth: saved })
  const fellBackIDs = Object.keys(fellBack)
  t.ok(fellBackIDs.includes("claude-sonnet-4-8"), "a refused catalog falls back to the list the record keeps")
  t.ok(fellBackIDs.includes("gpt-6"), "the record's whole catalog is used, not an empty provider")
  t.eq(fellBack["kimi-k3"].api.id, "kimi-k3", "the fallback keeps the relay's own ids")
  state.modelsRegionBlocked = false

  // ---- an expired refresh marks the sign-in
  saved = { ...saved, refresh: "spent", expires: Date.now() - 1000 }
  const gone = await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "claude-sonnet-4-8", messages: [] }),
  })
  t.eq(gone.status, 401, "a refused refresh answers 401")
  t.eq(gone.headers.get("X-Magpie-Sign-In"), "expired", "the account is marked expired")
  t.ok((await gone.text()).includes("expired"), "the error says to sign in again")

  // ---- the email-code method
  const email = plugin.auth.methods[1]
  const e = await email.authorize({ email: "u@example.com" })
  t.eq(e.method, "code", "the email method asks for a pasted code")
  const codeResult = await e.callback("123456")
  t.eq(codeResult.type, "success", "the code finishes the sign-in")

  // ---- an account with two-step verification on (desktop 0.0.737's auth)
  const mfa = await email.authorize({ email: "mfa@example.com" })
  const mfaResult = await mfa.callback("123456")
  t.eq(mfaResult.type, "success", "a confirmed two-step sign-in finishes")
  t.ok(state.mfaPolls >= 2, "the challenge is polled until it confirms")
  t.eq(mfaResult.refresh, currentRefresh, "the polled pair is what is kept")

  const denied = await email.authorize({ email: "mfa-denied@example.com" })
  const deniedResult = await denied.callback("123456")
  t.eq(deniedResult.type, "failed", "a denied two-step sign-in fails")
  t.ok(String(deniedResult.error).includes("denied"), "the failure says the confirmation was refused")
  t.ok(String(deniedResult.error).includes("https://mirasim.ai/confirm/deny"), "the failure names the page to confirm on")

  console.log(`\n${passed} passed, ${failed} failed`)
  process.exit(failed ? 1 : 0)
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
