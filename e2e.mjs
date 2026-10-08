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
}

// who signed in, and what it can call
const PROFILE = { email: "u@example.com", plan: "pro", plan_exp: Math.floor(Date.now() / 1000) + 86400 }
const MODELS = {
  data: [
    { id: "claude-sonnet-4-8", max_input_tokens: 180000 },
    { id: "claude-haiku-4-5-20251001", max_input_tokens: 180000 },
    { id: "claude-haiku-4-5", max_input_tokens: 180000 },
    { id: "gpt-6", max_input_tokens: 260000 },
    { id: "glm-5", max_input_tokens: 120000 },
    { id: "kimi-code/k3", max_input_tokens: 1048576 },
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
    kimi: [{ id: "kimi-code/k3", contextWindow: 1048576, effort: ["low", "high", "max"] }],
  },
  models: {
    "claude-future-9": { label: "Future 9", contextWindow: 1000000, maxOutput: 128000 },
    "claude-future-10": { contextWindow: 200000, effort: ["low", " HIGH ", "high", "off", "unsupported", "max"] },
    "claude-future-11": { adaptive: true },
  },
}
const LIMITS = {
  paid: true,
  windows: [
    { name: "5h", budget: 100, used: 42.5, reset_at: Math.floor(Date.now() / 1000) + 3600 },
    { name: "7d", budget: 500, used: 300, reset_at: null },
  ],
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
  t.ok(client === "0.0.403", "the client version is reported")
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
    case "/auth/verify":
      return json({ access_token: currentAccess, refresh_token: currentRefresh })
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
      const ask = JSON.parse(body)
      devicePublicB6 = ask.publicKey
      state.sessionMints++
      return json({ ticket: TICKET, expiresIn: 600 })
    }
    if (credential === TICKET) state.ticketCalls++
    else if (credential === currentAccess || credential === ADMIN_TOKEN || credential === ADMIN_TOKEN_2) state.accessCalls++
    if (req.url === "/v1/models" && req.method === "GET") {
      checkSignature(req, "", devicePublicB6, credential, t)
      return json(MODELS)
    }
    if (req.url === "/v1/model-roster" && req.method === "GET") {
      return json(ROSTER)
    }
    if (req.url === "/v1/limits" && req.method === "GET") {
      return json(LIMITS)
    }
    if (req.url === "/v1/messages" && req.method === "POST") {
      if (process.env.E2E_DEBUG) console.error("MSGS HEADERS", JSON.stringify(req.headers), "BODY", body.slice(0, 200))
      const sealed = checkSignature(req, body, devicePublicB6, credential, t)
      const model = String(JSON.parse(body).model ?? "")
      if (model.startsWith("gemini-")) t.ok(sealed["x-mirasim-agent"] === "pi", "the agent is pi for a Gemini model")
      else if (model.startsWith("kimi-")) t.ok(sealed["x-mirasim-agent"] === "kimi", "the agent is kimi for a Kimi model")
      else t.ok(sealed["x-mirasim-agent"] === "claude", "the agent is claude for a Claude model")
      t.ok(sealed["x-mirasim-session"].startsWith("mirasim_"), "the session is named: " + sealed["x-mirasim-session"])
      t.ok(sealed["x-mirasim-call"], "the call is named")
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
  process.env.MIRASIM_CLIENT_VERSION = "0.0.403"

  const mod = await import("./index.mjs")
  const internals = mod._internal
  e2eInternals.chacha20 = internals.chacha20

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

  // ---- a request selecting Kimi's alias sends the relay's own id
  await loader.fetch(loader.baseURL + "/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "kimi-k3", messages: [{ role: "user", content: "hi" }] }),
  })
  t.eq(state.messageCalls.at(-1).body.model, "kimi-code/k3", "the Kimi alias resolves to the relay id")

  // ---- the usage hook
  const u = await plugin.auth.usage(async () => saved)
  t.eq(u.plan, "pro", "the usage names the plan")
  t.eq(u.renew, "auto", "a paid account renews")
  t.eq(u.windows.length, 2, "both windows")
  t.eq(u.windows[0].name, "5h", "the 5h window")
  t.eq(u.windows[0].used, 42.5, "the 5h percentage")
  t.ok(u.windows[0].resetSecs > 3500, "the reset seconds")
  t.eq(u.signIn, "kept", "a clean read keeps the sign-in")

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
  // the relay's own Kimi id is kept and its alias is published beside it; a
  // withdrawn model is gone; every relay model takes image input
  t.ok(providerListed["kimi-code/k3"], "the relay's Kimi id is listed")
  t.eq(providerListed["kimi-code/k3"].api.npm, "@ai-sdk/anthropic", "Kimi on the Anthropic wire")
  t.ok(providerListed["kimi-k3"], "Kimi's alias is published beside the relay id")
  t.eq(providerListed["kimi-k3"].api.id, "kimi-k3", "the alias carries its own selector")
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
