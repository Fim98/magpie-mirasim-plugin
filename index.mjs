// Mirasim's subscription (mirasim.ai) as an OpenCode provider plugin, for
// OpenCode and magpie.
//
// Mirasim is signed in to the way its desktop client is: a browser round
// through one of the providers its authentication service offers (GitHub,
// Google, …), back to a loopback port this plugin listens on, or a code
// mailed to the account's address. The access token is renewed before it
// runs out; every relay request is signed with the account's Ed25519 device
// key (the metadata sealed to the relay's X25519 key), and a short-lived
// device ticket is minted to sign with when the relay offers one.
//
// The relay serves Anthropic Messages for Claude, DeepSeek, GLM and Kimi
// models and OpenAI Responses for GPT ones, both rewritten here into the
// thinking form each model takes (an effort, or a token budget). The
// account's own model catalog and roster are listed as its models, and its
// allowance read from the limits route.
//
// The protocol (endpoints, signing envelope, sign-in flows) is ported from
// magpie's internal/mirasim, which ported it from CLIProxyAPI's mirasim
// support and the Mirasim desktop client.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID,
  sign as cryptoSign,
} from "node:crypto"
import { createServer } from "node:http"

const ID = "mirasim"
const DEFAULT_RELAY = "https://relay.mirasim.ai"
const DEFAULT_ADMIN = "https://auth.mirasim.ai"
// MIRASIM_ADMIN_URL and MIRASIM_RELAY_URL stand in another endpoint, as a
// test's does; an account's own record overrides both.
const ADMIN = () => (trim(process.env.MIRASIM_ADMIN_URL) || DEFAULT_ADMIN).replace(/\/+$/, "")
const RELAY = () => (trim(process.env.MIRASIM_RELAY_URL) || DEFAULT_RELAY).replace(/\/+$/, "")
const DEFAULT_CLIENT_VERSION = "0.0.372"

const SESSION_PATH = "/v1/device/session"
const MODELS_PATH = "/v1/models"
const ROSTER_PATH = "/v1/model-roster"
const LIMITS_PATH = "/v1/limits"
const AUTH_REFRESH = "/auth/refresh"
const AUTH_ME = "/auth/me"
const AUTH_PROVIDERS = "/auth/oauth/providers"
const AUTH_CODE = "/auth/code"
const AUTH_VERIFY = "/auth/verify"

const SIG_VERSION = "mrs-sig-v2"
const SEAL_VERSION = "mrs-seal-v1"
const SEAL_PUBKEY = "HlyNMMeGXryasYLJuYQ/9ksCD4AYVVy1zXKAtJdpJn4="
// a raw X25519 public key wrapped in its SPKI header
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex")

const ANTHROPIC = "@ai-sdk/anthropic"
const OPENAI = "@ai-sdk/openai"

const SIGN_IN_TIMEOUT = 15 * 60 * 1000
const REFRESH_LEAD = 15 * 60 * 1000
const OPAQUE_TTL = 30 * 60 * 1000
const TICKET_LEAD = 2 * 60 * 1000
const TICKET_BACKOFF_BASE = 1000
const TICKET_BACKOFF_MAX = 30 * 1000
const ABSENT_QUIET = 60 * 1000
const UNMINTABLE_QUIET = 15 * 60 * 1000
const ASK_TIMEOUT = 30 * 1000

const DAY = 24 * 60 * 60 * 1000
const DATED_SUFFIX = /-20\d{6}$/
const EMAIL = /^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$/
const RESERVED_IDS = new Set(["*", "gpt-4o-mini", "gpt-4o-mini-openrouter"])

const CLIENT_VERSION = () => (process.env.MIRASIM_CLIENT_VERSION || "").trim() || DEFAULT_CLIENT_VERSION
const LOCALE = () => (process.env.MIRASIM_LOCALE || "").trim()
const COLLECT_OFF = () => /^(off|false)$/i.test((process.env.MIRASIM_COLLECT || "").trim())

// locked serializes checking, rotating and saving tokens and minting
// tickets, as a refresh token is spent once: two refreshes would spend it
// twice.
let lock = Promise.resolve()
const locked = (fn) => {
  const run = lock.then(fn, fn)
  lock = run.catch(() => {})
  return run
}

// ---- helpers -------------------------------------------------------------------

class HTTPStatusError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

class SignInGone extends Error {
  constructor(message, expired = false) {
    super(message)
    this.expired = expired
  }
}

const sha256hex = (v) => createHash("sha256").update(v ?? "").digest("hex")
const b64url = (v) => Buffer.from(v).toString("base64url")
const trim = (v) => (typeof v === "string" ? v.trim() : "")

const uuid = () => randomUUID()

async function ask(url, init = {}) {
  const res = await fetch(url, { ...init, signal: init.signal ?? AbortSignal.timeout(ASK_TIMEOUT) })
  if (!res.ok) {
    const text = (await res.text()).trim().slice(0, 512)
    throw new HTTPStatusError(`mirasim: HTTP ${res.status}${text ? ": " + text : ""}`, res.status)
  }
  return res
}

async function askJSON(url, init = {}) {
  return JSON.parse(await (await ask(url, init)).text())
}

async function adminPost(path, body) {
  return askJSON(ADMIN() + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  })
}

async function adminGet(path) {
  return askJSON(ADMIN() + path, { headers: { Accept: "application/json" } })
}

// ---- the device key -------------------------------------------------------------

// newDeviceKey makes the Ed25519 identity a fresh sign-in keeps, as a
// PKCS#8 PEM.
function newDeviceKey() {
  const { privateKey } = generateKeyPairSync("ed25519")
  return privateKey.export({ type: "pkcs8", format: "pem" }).toString()
}

// loadDeviceKey reads one: the signing key, the public key in the SPKI form
// the device session names, and the device id derived from it.
function loadDeviceKey(pem) {
  try {
    const priv = createPrivateKey({ key: String(pem ?? ""), format: "pem" })
    if (priv.asymmetricKeyType !== "ed25519") return null
    const publicB6 = createPublicKey(priv).export({ type: "spki", format: "der" }).toString("base64")
    const id = createHash("sha256").update(publicB6).digest().toString("base64url").slice(0, 22)
    return { private: priv, publicB6, id }
  } catch {
    return null
  }
}

function shortDevice(pem) {
  const key = loadDeviceKey(pem)
  return key ? key.id.slice(0, 8) : "key"
}

// ---- ChaCha20-Poly1305, by hand (RFC 8439) ----------------------------------------
// Bun's node:crypto has no chacha20-poly1305, and the plugin host runs the
// plugins under Bun.

const rotl = (x, n) => (((x << n) | (x >>> (32 - n))) >>> 0)

function qr(x, a, b, c, d) {
  x[a] = (x[a] + x[b]) >>> 0
  x[d] = rotl(x[d] ^ x[a], 16)
  x[c] = (x[c] + x[d]) >>> 0
  x[b] = rotl(x[b] ^ x[c], 12)
  x[a] = (x[a] + x[b]) >>> 0
  x[d] = rotl(x[d] ^ x[a], 8)
  x[c] = (x[c] + x[d]) >>> 0
  x[b] = rotl(x[b] ^ x[c], 7)
}

function chachaBlock(key, counter, nonce) {
  const state = new Uint32Array(16)
  state[0] = 0x61707865
  state[1] = 0x3320646e
  state[2] = 0x79622d32
  state[3] = 0x6b206574
  for (let i = 0; i < 8; i++) state[4 + i] = key.readUInt32LE(i * 4)
  state[12] = counter >>> 0
  state[13] = nonce.readUInt32LE(0)
  state[14] = nonce.readUInt32LE(4)
  state[15] = nonce.readUInt32LE(8)
  const x = new Uint32Array(state)
  for (let i = 0; i < 10; i++) {
    qr(x, 0, 4, 8, 12)
    qr(x, 1, 5, 9, 13)
    qr(x, 2, 6, 10, 14)
    qr(x, 3, 7, 11, 15)
    qr(x, 0, 5, 10, 15)
    qr(x, 1, 6, 11, 12)
    qr(x, 2, 7, 8, 13)
    qr(x, 3, 4, 9, 14)
  }
  const out = Buffer.alloc(64)
  for (let i = 0; i < 16; i++) out.writeUInt32LE((x[i] + state[i]) >>> 0, i * 4)
  return out
}

function chacha20(key, counter, nonce, data) {
  const out = Buffer.from(data)
  for (let off = 0; off < data.length; off += 64) {
    const ks = chachaBlock(key, counter + Math.floor(off / 64), nonce)
    for (let i = 0; i < Math.min(64, data.length - off); i++) out[off + i] ^= ks[i]
  }
  return out
}

function poly1305(key, msg) {
  const P = (1n << 130n) - 5n
  const MASK = (1n << 128n) - 1n
  let r = 0n
  let s = 0n
  for (let i = 15; i >= 0; i--) r = (r << 8n) | BigInt(key[i])
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn
  for (let i = 31; i >= 16; i--) s = (s << 8n) | BigInt(key[i])
  let acc = 0n
  for (let i = 0; i < msg.length; i += 16) {
    const len = Math.min(16, msg.length - i)
    let n = 1n
    for (let j = len - 1; j >= 0; j--) n = (n << 8n) | BigInt(msg[i + j])
    acc = (acc + n) * r % P
  }
  let tag = (acc + s) & MASK
  const out = Buffer.alloc(16)
  for (let i = 0; i < 16; i++) {
    out[i] = Number(tag & 0xffn)
    tag >>= 8n
  }
  return out
}

const pad16 = (b) => (b.length % 16 ? Buffer.alloc(16 - (b.length % 16)) : Buffer.alloc(0))
const le64 = (n) => {
  const out = Buffer.alloc(8)
  out.writeBigUInt64LE(BigInt(n))
  return out
}

// chacha20poly1305Seal is RFC 8439's AEAD, as Go's x/crypto answers byte
// for byte.
function chacha20poly1305Seal(key, nonce, plaintext, aad) {
  const polyKey = chachaBlock(key, 0, nonce).subarray(0, 32)
  const ciphertext = chacha20(key, 1, nonce, plaintext)
  const macData = Buffer.concat([aad, pad16(aad), ciphertext, pad16(ciphertext), le64(aad.length), le64(ciphertext.length)])
  return Buffer.concat([ciphertext, poly1305(polyKey, macData)])
}

// ---- the signing envelope -------------------------------------------------------

// canonicalMetadata joins the metadata the way the signed payload reads it:
// lower-case names without empties, sorted, one "name:value" a line.
function canonicalMetadata(metadata) {
  const normalized = {}
  for (const [key, value] of Object.entries(metadata ?? {})) {
    if (value === "" || value == null) continue
    normalized[key.toLowerCase()] = String(value)
  }
  const keys = Object.keys(normalized).sort()
  return keys.length ? keys.map((k) => k + ":" + normalized[k]).join("\n") : ""
}

// signatureHeaders signs one request the way the official client does: an
// Ed25519 signature over the method, the path, the time, a nonce, the
// device identity, the client version, the credential, the metadata and
// the body.
function signatureHeaders(key, method, requestPath, credential, metadata, body) {
  const timestamp = String(Date.now())
  const nonceText = randomBytes(12).toString("base64url")
  const clientVersion = CLIENT_VERSION()
  const canonical = canonicalMetadata(metadata)
  const payload = [
    SIG_VERSION,
    method.toUpperCase(),
    requestPath,
    timestamp,
    nonceText,
    key.id,
    clientVersion,
    sha256hex(credential),
    canonical ? sha256hex(canonical) : "",
    sha256hex(body ?? ""),
  ].join("\n")
  const out = {}
  for (const [k, v] of Object.entries(metadata ?? {})) if (v !== "" && v != null) out[k] = String(v)
  out["x-mirasim-device"] = key.id
  out["x-mirasim-ts"] = timestamp
  out["x-mirasim-nonce"] = nonceText
  out["x-mirasim-sig"] = cryptoSign(null, Buffer.from(payload), key.private).toString("base64url")
  if (clientVersion) out["x-mirasim-client"] = clientVersion
  return out
}

// sealPublicKey is the relay's sealing key, from MIRASIM_SEAL_PUBKEY or the
// one the official client carries.
function sealPublicKey() {
  const encoded = trim(process.env.MIRASIM_SEAL_PUBKEY) || SEAL_PUBKEY
  const raw = Buffer.from(encoded, "base64")
  if (raw.length !== 32) throw new Error("mirasim: the relay's seal key is unreadable")
  return createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: "der", type: "spki" })
}

// seal folds the x-mirasim-* metadata into one sealed header: an ephemeral
// X25519 key agrees on a ChaCha20-Poly1305 key with the relay's own, the
// metadata sealed under the method and the path.
function seal(metadata, method, requestPath) {
  const { privateKey: ephPriv } = generateKeyPairSync("x25519")
  const ephPublicRaw = createPublicKey(ephPriv).export({ type: "spki", format: "der" }).subarray(-32)
  return sealWith(ephPublicRaw, ephPriv, sealPublicKey(), metadata, method, requestPath, randomBytes(12))
}

// sealWith packs one sealed header from the given ephemeral key and nonce,
// as the official client sends it: ephPublic, nonce, ciphertext, tag.
function sealWith(ephPublicRaw, ephPriv, recipient, metadata, method, requestPath, nonce) {
  const shared = diffieHellman({ privateKey: ephPriv, publicKey: recipient })
  const key = Buffer.from(hkdfSync("sha256", shared, ephPublicRaw, Buffer.from(SEAL_VERSION), 32))
  const aad = Buffer.from([SEAL_VERSION, method.toUpperCase(), requestPath].join("\n"))
  const packed = chacha20poly1305Seal(key, nonce, Buffer.from(JSON.stringify(metadata)), aad)
  return Buffer.concat([ephPublicRaw, nonce, packed]).toString("base64url")
}

// inferenceHeaders signs and seals one inference request (Messages or
// Responses): the metadata the relay correlates a call by — the session, the
// agent, the call's own id, the sub-account — goes on, is signed, and is
// sealed into one header before it leaves.
function inferenceHeaders(cred, key, credential, sessionID, requestPath, body) {
  const metadata = {
    "x-mirasim-session": sessionID,
    "x-mirasim-agent": agentFor(requestPath, body),
    "x-mirasim-call": uuid(),
  }
  const account = agentAccount(cred)
  if (account) metadata["x-mirasim-account"] = account
  if (LOCALE()) metadata["x-mirasim-locale"] = LOCALE()
  if (COLLECT_OFF()) metadata["x-mirasim-collect"] = "off"
  const headers = signatureHeaders(key, "POST", requestPath, credential, metadata, body)
  headers.Authorization = "Bearer " + credential
  // the metadata headers are sealed into one, as the official client sends
  // them on the inference routes
  const sealMeta = {}
  for (const name of Object.keys(headers)) {
    const lower = name.toLowerCase()
    if (!lower.startsWith("x-mirasim-") || lower === "x-mirasim-client" || lower === "x-mirasim-enc") continue
    if (headers[name]) {
      sealMeta[lower] = String(headers[name])
      delete headers[name]
    }
  }
  if (Object.keys(sealMeta).length) headers["x-mirasim-enc"] = seal(sealMeta, "POST", requestPath)
  return headers
}

// agentFor is the x-mirasim-agent value one request belongs to, as the
// official client names it: codex for its Responses routes, one of the
// others by the model family the body asks for, claude for the rest.
function agentFor(requestPath, body) {
  if (!requestPath.startsWith("/v1/messages")) {
    if (requestPath.startsWith("/v1/responses") || requestPath.startsWith("/v1/alpha/search") || requestPath.startsWith("/v1/images/")) {
      return "codex"
    }
    return "claude"
  }
  let model = ""
  try {
    model = String(JSON.parse(body).model ?? "")
  } catch {}
  const family = familyOf(model.toLowerCase())
  return family === "dsh" || family === "zcode" || family === "kimi" ? family : "claude"
}

// familyOf is the family a model id belongs to, named as the relay names
// its agents: dsh for DeepSeek, zcode for GLM, kimi for Kimi, codex for
// GPT, claude for Claude and anything else.
function familyOf(model) {
  if (model.startsWith("deepseek-")) return "dsh"
  if (model.startsWith("glm-")) return "zcode"
  if (model.startsWith("kimi-")) return "kimi"
  if (model.startsWith("gpt-")) return "codex"
  return "claude"
}

// ---- the tokens ------------------------------------------------------------------

// jwtClaims is the middle part of a JWT, read as JSON; a token that isn't
// one says nothing.
function jwtClaims(token) {
  const parts = String(token ?? "").trim().split(".")
  if (parts.length < 2) return null
  for (const enc of ["base64url", "base64"]) {
    try {
      const claims = JSON.parse(Buffer.from(parts[1], enc).toString("utf8"))
      if (claims && typeof claims === "object") return claims
    } catch {}
  }
  return null
}

const firstClaim = (claims, ...keys) => {
  for (const k of keys) {
    const v = trim(claims?.[k])
    if (v) return v
  }
  return ""
}

function jwtExpiryMs(token) {
  const exp = Number(jwtClaims(token)?.exp ?? 0)
  return exp > 0 ? exp * 1000 : 0
}

// agentAccount is the sub-account the access token itself names, which goes
// on relay requests as x-mirasim-account; "" when it names none.
function agentAccount(cred) {
  return firstClaim(jwtClaims(cred.access), "account_id", "accountId")
}

// expiryOf is when the access token ends: what the login or the last
// refresh recorded, else the token's own exp claim, else the half hour an
// opaque token is taken to run for.
function expiryOf(a) {
  if (Number(a.expires) > 0) return Number(a.expires)
  const jwt = jwtExpiryMs(a.access)
  return jwt > 0 ? jwt : Date.now() + OPAQUE_TTL
}

// withTokens is the record after a refresh or a sign-in: the new tokens,
// their end, and whatever identity the new access token names that the
// record doesn't have yet.
function withTokens(a, access, refresh, expiresIn) {
  const next = { ...a, access: trim(access) }
  if (trim(refresh)) next.refresh = trim(refresh)
  if (Number(expiresIn) > 0) next.expires = Date.now() + Number(expiresIn) * 1000
  else {
    const jwt = jwtExpiryMs(next.access)
    next.expires = jwt > 0 ? jwt : Date.now() + OPAQUE_TTL
  }
  const claims = jwtClaims(next.access)
  if (!next.accountId) next.accountId = firstClaim(claims, "account_id", "accountId", "user_id", "userId", "sub")
  if (!next.email) next.email = firstClaim(claims, "email")
  const plan = firstClaim(claims, "plan")
  if (plan) {
    next.plan = plan
    const exp = Number(claims.plan_exp ?? 0)
    if (exp > 0) next.planExpiresAt = exp
  }
  return next
}

// refreshTokens trades a refresh token for a new pair.
async function refreshTokens(refreshToken) {
  if (!trim(refreshToken)) throw new Error("mirasim: refresh token is required")
  return adminPost(AUTH_REFRESH, { refresh_token: trim(refreshToken) })
}

// profile is what /auth/me says about the signed-in account.
async function profile(accessToken) {
  const p = await askJSON(ADMIN() + AUTH_ME, { headers: { Authorization: "Bearer " + accessToken, Accept: "application/json" } })
  const planExp = Number(p.plan_exp ?? 0)
  return { email: trim(p.email), plan: trim(p.plan), planExp: planExp > 0 ? planExp : 0 }
}

// discoverProviders lists the sign-in providers the service offers.
async function discoverProviders() {
  const p = await adminGet(AUTH_PROVIDERS)
  const slug = /^[a-z][a-z0-9_-]{0,63}$/
  const out = []
  const seen = new Set()
  for (let id of p.providers ?? []) {
    id = String(id ?? "").toLowerCase().trim()
    if (!id || !slug.test(id) || seen.has(id)) continue
    seen.add(id)
    out.push(id)
  }
  return out
}

async function emailCode(address) {
  return adminPost(AUTH_CODE, { email: address })
}

async function emailVerify(address, code) {
  return adminPost(AUTH_VERIFY, { email: address, code })
}

// ---- the relay's descriptive routes ---------------------------------------------

// mintTicket trades the account's access token for a device ticket: the
// device's public key and id, signed with the access token itself.
async function mintTicket(cred, key) {
  const body = JSON.stringify({ publicKey: key.publicB6, deviceId: key.id })
  const headers = signatureHeaders(key, "POST", SESSION_PATH, cred.access, null, body)
  headers.Authorization = "Bearer " + cred.access
  headers["Content-Type"] = "application/json"
  headers.Accept = "application/json"
  const res = await fetch((relayOf(cred)) + SESSION_PATH, { method: "POST", headers, body, signal: AbortSignal.timeout(ASK_TIMEOUT) })
  if (!res.ok) {
    const text = (await res.text()).trim().slice(0, 512)
    throw new HTTPStatusError(`mirasim: HTTP ${res.status}${text ? ": " + text : ""}`, res.status)
  }
  const p = JSON.parse(await res.text())
  const ticket = trim(p.ticket)
  if (!ticket) throw new Error("mirasim: device ticket response is missing ticket")
  let expiresAt = Date.now() + 10 * 60 * 1000
  if (Number(p.expiresIn) > 0) expiresAt = Date.now() + Number(p.expiresIn) * 1000
  else if (Number(p.expiresAt) > 0) {
    const ms = Number(p.expiresAt)
    expiresAt = ms > 1e12 ? ms : ms * 1000
  }
  return { value: ticket, expiresAt }
}

// signedGet asks one of the relay's descriptive routes (the catalog, the
// roster, the allowance) the way the official client does: signed with the
// ticket, its metadata left empty, nothing sealed.
async function signedGet(cred, key, credential, requestPath, probe = "") {
  const headers = signatureHeaders(key, "GET", requestPath, credential, null, null)
  headers.Authorization = "Bearer " + credential
  headers.Accept = "application/json"
  if (probe) headers["x-mirasim-probe"] = probe
  const res = await fetch(relayOf(cred) + requestPath, { headers, signal: AbortSignal.timeout(ASK_TIMEOUT) })
  if (!res.ok) {
    const text = (await res.text()).trim().slice(0, 512)
    throw new HTTPStatusError(`mirasim: HTTP ${res.status}${text ? ": " + text : ""}`, res.status)
  }
  return res
}

const relayOf = (a) => (trim(a?.relayUrl) || RELAY()).replace(/\/+$/, "")

// ---- the account's catalog and roster ---------------------------------------------

// parseModels reads the account's catalog, narrowed the way the official
// client narrows it: no placeholders, no namespaced ids, and a dated twin
// dropped when the plain id it duplicates is served beside it.
function parseModels(raw) {
  if (typeof raw === "string") {
    try {
      raw = JSON.parse(raw)
    } catch {
      throw new Error("mirasim: model catalog contains no models")
    }
  }
  const payload = raw ?? {}
  const items = Array.isArray(payload.data) && payload.data.length ? payload.data : payload.models
  if (!Array.isArray(items)) throw new Error("mirasim: model catalog contains no models")
  const parsed = []
  for (const item of items) {
    let model
    if (typeof item === "string") model = { id: item }
    else if (item && typeof item === "object") model = item
    else continue
    model.id = trim(model.id)
    if (!model.id) continue
    const max = Number(model.max_input_tokens ?? 0)
    model.max_input_tokens = max < 0 ? 0 : max
    parsed.push(model)
  }
  const undated = new Set()
  for (const m of parsed) {
    if (!m.id.includes("/") && !DATED_SUFFIX.test(m.id)) undated.add(m.id)
  }
  const out = []
  const seen = new Set()
  for (const m of parsed) {
    if (seen.has(m.id) || RESERVED_IDS.has(m.id) || m.id.includes("/")) continue
    if (DATED_SUFFIX.test(m.id) && undated.has(m.id.replace(DATED_SUFFIX, ""))) continue
    seen.add(m.id)
    out.push(m)
  }
  if (!out.length) throw new Error("mirasim: model catalog contains no models")
  return out
}

const paidVariant = (id) => /-paid$/i.test(trim(id))

// parseSpec reads one roster entry.
function parseSpec(entry) {
  if (!entry || typeof entry !== "object") return null
  const spec = {
    id: trim(entry.id),
    label: trim(entry.label),
    contextWindow: Number(entry.contextWindow ?? 0),
    maxOutput: Number(entry.maxOutput ?? 0),
    adaptive: entry.adaptive === true,
    adaptiveSet: entry.adaptive !== undefined,
    effort: [],
  }
  if (spec.contextWindow < 0) spec.contextWindow = 0
  if (spec.maxOutput < 0) spec.maxOutput = 0
  if (Array.isArray(entry.effort)) {
    const seen = new Set()
    for (let level of entry.effort) {
      level = String(level ?? "").toLowerCase().trim()
      if (level && !seen.has(level)) {
        spec.effort.push(level)
        seen.add(level)
      }
    }
  }
  return spec
}

// parseRoster reads the signed roster: per model, its window, its reasoning
// levels, and whether its thinking takes an effort (adaptive) or a token
// budget.
function parseRoster(raw) {
  if (typeof raw === "string") {
    try {
      raw = JSON.parse(raw)
    } catch {
      throw new Error("mirasim: invalid model roster")
    }
  }
  const envelope = raw ?? {}
  if (!trim(envelope.version)) throw new Error("mirasim: invalid model roster")
  const roster = { agents: {}, models: {} }
  const prefix = { claude: "claude-", codex: "gpt-", dsh: "deepseek-", zcode: "glm-", kimi: "kimi-" }
  for (const family of ["claude", "codex", "dsh", "zcode", "kimi"]) {
    const seen = new Set()
    for (const entry of envelope.agents?.[family] ?? []) {
      const spec = parseSpec(entry)
      if (!spec) continue
      spec.id = spec.id.toLowerCase()
      if (family === "kimi" && spec.id === "kimi-code/k3") spec.id = "kimi-k3"
      if (!spec.id.startsWith(prefix[family]) || seen.has(spec.id) || spec.contextWindow <= 0 || paidVariant(spec.id)) continue
      if (!spec.label) spec.label = spec.id
      seen.add(spec.id)
      ;(roster.agents[family] ??= []).push(spec)
    }
  }
  for (const [id, entry] of Object.entries(envelope.models ?? {})) {
    const key = String(id).toLowerCase().trim()
    if (!key || paidVariant(key)) continue
    const spec = parseSpec(entry)
    if (!spec) continue
    roster.models[key] = spec
  }
  if (!Object.keys(roster.agents).length && !Object.keys(roster.models).length) {
    throw new Error("mirasim: model roster contains no valid supported models")
  }
  return roster
}

// specOf merges model-wide metadata with every family entry naming the
// model.
function specOf(roster, modelID) {
  const id = String(modelID ?? "").toLowerCase().trim()
  let spec = null
  let found = false
  if (roster.models[id]) {
    spec = { ...roster.models[id] }
    found = true
  }
  for (const entries of Object.values(roster.agents ?? {})) {
    for (const agent of entries) {
      if (agent.id !== id) continue
      found = true
      spec ??= { effort: [] }
      if (agent.label) spec.label = agent.label
      if (agent.contextWindow > 0) spec.contextWindow = agent.contextWindow
      if (agent.maxOutput > 0) spec.maxOutput = agent.maxOutput
      if (agent.effort?.length) spec.effort = [...agent.effort]
      if (agent.adaptiveSet) {
        spec.adaptive = agent.adaptive
        spec.adaptiveSet = true
      }
    }
  }
  if (!found) return null
  spec.id = id
  return spec
}

// thinkingAdaptive is the roster's answer to which Claude thinking form the
// model takes: true is the effort form. known is false when the roster
// carries no entry, which leaves the form to the caller's default (the
// effort form, like every Claude model the relay publishes).
function thinkingAdaptive(roster, modelID) {
  const spec = specOf(roster, modelID)
  if (!spec) return { adaptive: false, known: false }
  return { adaptive: spec.adaptive, known: spec.adaptiveSet }
}

// ---- the thinking forms -----------------------------------------------------------

// familyEfforts is the reasoning ladder a family takes when the roster says
// nothing narrower.
function familyEfforts(family) {
  switch (family) {
    case "codex":
    case "claude":
      return ["low", "medium", "high", "xhigh", "max"]
    case "dsh":
    case "zcode":
    case "kimi":
      return ["low", "high", "max"]
  }
  return []
}

// levelBudget and budgetLevel are the two ends of the mapping between the
// ladder and the token budgets it stands for, as the official client's own
// table has it.
function levelBudget(level) {
  switch (level) {
    case "low":
      return 1024
    case "medium":
      return 8192
    case "high":
      return 24576
    case "xhigh":
      return 32768
    case "max":
      return 128000
  }
  return 0
}

function budgetLevel(budget) {
  if (budget <= 0) return ""
  if (budget <= 1024) return "low"
  if (budget <= 8192) return "medium"
  if (budget <= 24576) return "high"
  if (budget <= 32768) return "xhigh"
  return "max"
}

// acceptsEffort clamps a level onto what the model takes: the roster's list
// when it has one, else the family's. "" when the level isn't one the model
// takes at all, which leaves the body as it came.
function acceptsEffort(roster, model, level) {
  let ladder = ["low", "medium", "high", "xhigh", "max"]
  switch (model.split("-")[0]) {
    case "deepseek":
    case "glm":
    case "kimi":
      ladder = ["low", "high", "max"]
  }
  const spec = roster ? specOf(roster, model) : null
  if (spec?.effort?.length) ladder = spec.effort
  if (ladder.includes(level)) return level
  // DeepSeek's off is the one rung below low.
  if (level === "off" && model.startsWith("deepseek-")) return "off"
  return ""
}

// normalizeBody applies the thinking shapes to one body. The wire is told
// by the shape: a Responses request carries input/instructions, a Messages
// request messages and a system.
function normalizeBody(body, roster) {
  let o
  try {
    o = JSON.parse(body)
  } catch {
    return body
  }
  if (!o || typeof o !== "object") return body
  const wire = "instructions" in o || ("input" in o && !("messages" in o)) ? "codex" : "claude"
  return JSON.stringify(wire === "codex" ? codexBody(o) : claudeBody(o, roster))
}

// codexBody folds an effort the relay's ladder doesn't carry onto the rung
// under it. Effort none and auto are the relay's own; the rest of the ladder
// the model list already declared.
function codexBody(o) {
  const effort = String(o.reasoning?.effort ?? "").trim().toLowerCase()
  if (effort === "minimal") o.reasoning = { ...o.reasoning, effort: "low" }
  else if (effort === "ultra") o.reasoning = { ...o.reasoning, effort: "max" }
  else if (effort === "") {
    // an effort the caller didn't name is the relay's to choose
    if (o.reasoning_effort !== undefined) {
      const inner = String(o.reasoning_effort).trim().toLowerCase()
      if (inner === "minimal") o.reasoning_effort = "low"
      else if (inner === "ultra") o.reasoning_effort = "max"
    }
  }
  return o
}

// claudeBody rewrites the thinking controls a Claude-shaped body carries
// into the form the model takes, and says nothing about thinking when the
// request didn't either.
function claudeBody(o, roster) {
  const model = String(o.model ?? "").trim().toLowerCase()
  if (!model) return o
  const { adaptive, known } = roster ? thinkingAdaptive(roster, model) : { adaptive: false, known: false }
  const takesAdaptive = known ? adaptive : true // every Claude model the relay publishes takes the effort form
  const thinkingType = String(o.thinking?.type ?? "").trim().toLowerCase()
  const effort = String(o.output_config?.effort ?? "").trim().toLowerCase()
  const budget = Number(o.thinking?.budget_tokens ?? 0)

  if (thinkingType === "disabled") {
    // DeepSeek takes a plain effort for it; the rest take the word.
    if (model.startsWith("deepseek-")) {
      delete o.thinking
      o.output_config = { ...o.output_config, effort: "off" }
    }
    return o
  }
  if (thinkingType === "adaptive" || effort !== "") {
    let level = effort
    if (!level) return o // the model thinks as much as it likes
    if (level === "ultra") level = "max"
    if (!takesAdaptive) {
      const b = levelBudget(level)
      if (!b) return o
      return setBudget(o, b)
    }
    const accepted = acceptsEffort(roster, model, level)
    if (accepted) level = accepted
    o.thinking = { ...o.thinking, type: "adaptive" }
    delete o.thinking.budget_tokens
    o.output_config = { ...o.output_config, effort: level }
    return o
  }
  if (thinkingType === "enabled") {
    if (takesAdaptive) {
      // a token budget asked of an effort-form model is mapped onto the
      // ladder rather than refused
      let level = budgetLevel(budget)
      if (!level) return o
      const accepted = acceptsEffort(roster, model, level)
      if (accepted) level = accepted
      o.thinking = { ...o.thinking, type: "adaptive" }
      delete o.thinking.budget_tokens
      o.output_config = { ...o.output_config, effort: level }
      return o
    }
    return setBudget(o, budget)
  }
  return o
}

// setBudget puts an enabled budget on the body, kept inside the form's own
// bounds: at least 1024, and under max_tokens when it says one.
function setBudget(o, budget) {
  if (budget < 1024) budget = 1024
  const maxTokens = Number(o.max_tokens ?? 0)
  if (maxTokens > 0 && budget >= maxTokens) {
    budget = maxTokens - 1
    if (budget < 1024) return o
  }
  o.thinking = { ...o.thinking, type: "enabled" }
  o.thinking.budget_tokens = budget
  return o
}

// dropBeta removes one entry from a comma-separated anthropic-beta header
// — the one naming Claude Code's own OAuth client, which the relay refuses.
function dropBeta(headers, beta) {
  for (const [name, value] of [...headers.entries()]) {
    if (name.toLowerCase() !== "anthropic-beta") continue
    const kept = value
      .split(",")
      .map((e) => e.trim())
      .filter((e) => e && e.toLowerCase() !== beta)
    if (!kept.length) headers.delete(name)
    else headers.set(name, kept.join(","))
  }
}

// ---- the limits -------------------------------------------------------------------

// parseLimits reads the structured limits: the account's windows and
// whether it is on a paid plan. A window without both a budget and a use is
// skipped.
function parseLimits(raw) {
  const payload = raw ?? {}
  const out = { paid: undefined, degraded: false, windows: [] }
  if (payload.paid !== undefined) out.paid = payload.paid === true
  out.degraded = payload.degraded === true
  for (const w of payload.windows ?? []) {
    const name = trim(w?.name)
    if (!name) continue
    const budget = Number(w?.budget)
    const used = Number(w?.used)
    if (!isFinite(budget) || budget < 0 || !isFinite(used)) continue
    const window = { name, budget, used, resetAt: resetTime(w?.reset_at), modelScoped: w?.model_scoped === true, status: "allowed" }
    if (budget > 0) {
      const percent = roundPercent((used / budget) * 100)
      window.usedPercent = percent
      if (percent >= 100) window.status = "limit_reached"
      else if (percent >= 80) window.status = "warning"
    }
    out.windows.push(window)
  }
  return out
}

// resetTime reads a reset the way the client does: seconds or milliseconds,
// or an RFC 3339 moment.
function resetTime(value) {
  if (value == null || value === "") return null
  const n = Number(value)
  if (isFinite(n) && n > 0) {
    const ms = n > 1e12 ? n : n * 1000
    const d = new Date(ms)
    return isNaN(d) ? null : d
  }
  const d = new Date(String(value))
  return isNaN(d) ? null : d
}

// roundPercent rounds a percentage once, then saturates at 99, matching the
// official client: rounding twice would carry 79.9495 up to 80.0, a tenth
// the account has not spent.
function roundPercent(value) {
  value = Math.max(0, Math.min(100, Math.round(value * 10) / 10))
  return value >= 99 ? 100 : value
}

// ---- finishing a sign-in -----------------------------------------------------------

// successWith keeps an account from its token pair: a device key of its own
// is made for it, the pair is traded for what it names, the relay is asked
// for the account's catalog — which proves the credential before it is kept
// — and the result is the auth record magpie saves.
async function successWith(access, refresh) {
  access = trim(access)
  refresh = trim(refresh)
  if (!access || !refresh) return { type: "failed", error: "Mirasim sent back no token" }
  const deviceKey = newDeviceKey()
  let a = { type: "oauth", access, refresh, deviceKey }
  a = withTokens(a, access, refresh, 0)
  // who the account is: what its token claims, then what the service's
  // profile route says, then its id
  try {
    const p = await profile(a.access)
    if (p.email) a.email = p.email
    if (p.plan) {
      a.plan = p.plan
      if (p.planExp) a.planExpiresAt = p.planExp
    }
  } catch {}
  const who = a.email || a.accountId || "Mirasim device " + shortDevice(deviceKey)
  // the account's own list, so the picker has it before its first request,
  // and the relay's answer that the credential is good
  let models = ""
  let roster = ""
  try {
    const s = stateOf(a)
    const credential = await locked(() => mintCredential(s, a))
    const raw = await signedGet(a, s.key, credential, MODELS_PATH)
    models = await raw.text()
    parseModels(JSON.parse(models)) // throws on a catalog with nothing servable
    try {
      roster = await (await signedGet(a, s.key, credential, ROSTER_PATH)).text()
      parseRoster(JSON.parse(roster))
    } catch {
      roster = "" // the roster is metadata: a route that says nothing leaves it out
    }
  } catch (e) {
    return { type: "failed", error: "Mirasim: " + String(e?.message ?? e) }
  }
  return {
    type: "success",
    provider: ID,
    access,
    refresh,
    expires: a.expires,
    ...(a.accountId ? { accountId: a.accountId } : {}),
    ...(a.email ? { email: a.email } : {}),
    ...(a.plan ? { plan: a.plan } : {}),
    ...(a.planExpiresAt ? { planExpiresAt: a.planExpiresAt } : {}),
    deviceKey,
    models,
    roster,
  }
}

// browserSignIn is the authentication service's browser round: the login
// page through one of the providers it offers, back to a callback on
// 127.0.0.1 this plugin listens on, with the tokens on its query.
async function browserSignIn(inputs) {
  let offered
  try {
    offered = await discoverProviders()
  } catch (e) {
    throw new Error("Mirasim sign-in: " + String(e?.message ?? e))
  }
  if (!offered.length) throw new Error("Mirasim is not offering any sign-in provider right now")
  let provider = String(inputs?.provider ?? "").toLowerCase()
  if (provider && !offered.includes(provider)) {
    throw new Error(`Mirasim is not offering a "${provider}" sign-in; it offers ${offered.join(", ")}`)
  }
  if (!provider) {
    provider = "github"
    if (!offered.includes(provider)) provider = offered[0]
  }
  const state = randomUUID().replace(/-/g, "")
  let over = false
  let settle
  const done = new Promise((r) => (settle = r))
  const finish = (result) => {
    if (over) return result
    over = true
    settle(result)
    return result
  }
  let server
  try {
    server = createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1")
      const html = (ok, title, message) => {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" })
        res.end(`<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font:15px/1.5 system-ui;padding:48px;text-align:center"><h1>${title}</h1><p>${message}</p></body>`)
      }
      if (url.pathname !== "/oauth/callback") return res.writeHead(404).end()
      const q = url.searchParams
      const error = q.get("error") || q.get("error_description")
      if (error) {
        finish({ type: "failed", error: "Mirasim: " + error })
        return html(false, "Sign-in didn't finish", "Mirasim: " + error)
      }
      if (q.get("state") !== state) {
        return html(false, "This link isn't from this sign-in", "Start it again.")
      }
      const r = await successWith(q.get("access_token"), q.get("refresh_token"))
      finish(r)
      if (r.type === "success") html(true, "You're signed in", "Mirasim is added. You can close this tab.")
      else html(false, "Sign-in didn't finish", r.error ?? "the sign-in didn't finish")
    })
    await new Promise((resolve, reject) => {
      server.once("error", reject)
      server.listen(0, "127.0.0.1", resolve)
    })
  } catch (e) {
    throw new Error("Mirasim sign-in: " + String(e?.message ?? e))
  }
  const callback = `http://127.0.0.1:${server.address().port}/oauth/callback?state=${encodeURIComponent(state)}`
  const login = new URL(ADMIN() + "/auth/oauth/" + encodeURIComponent(provider) + "/login")
  login.searchParams.set("redirect_uri", callback)
  login.searchParams.set("state", state)
  const timer = setTimeout(() => finish({ type: "failed", error: "the sign-in timed out; start again" }), SIGN_IN_TIMEOUT)
  done.finally(() => {
    clearTimeout(timer)
    setTimeout(() => server.close(), 5000).unref?.()
  })
  return {
    url: login.href,
    instructions: "Sign in to Mirasim in the browser.",
    method: "auto",
    callback: () => done,
  }
}

// emailSignIn mails a sign-in code to the address, which finishes it pasted
// back.
async function emailSignIn(inputs) {
  const address = String(inputs?.email ?? "").trim()
  if (!EMAIL.test(address) || address.length > 254) {
    throw new Error("that isn't an email address a sign-in code can go to")
  }
  await emailCode(address)
  return {
    url: "",
    instructions: `A sign-in code was emailed to ${address}. Paste it back to finish.`,
    method: "code",
    async callback(code) {
      code = String(code ?? "").trim()
      if (!code || code.length > 64 || /[\r\n\0]/.test(code)) return { type: "failed", error: "that isn't a Mirasim sign-in code" }
      let tokens
      try {
        tokens = await emailVerify(address, code)
      } catch (e) {
        return { type: "failed", error: String(e?.message ?? e) }
      }
      return successWith(tokens.access_token, tokens.refresh_token)
    },
  }
}

// ---- the account's runtime ---------------------------------------------------------

// states is each account's runtime, keyed by its device key: the loaded
// signing key, the session the relay correlates its calls by, and the ticket
// those calls are signed with.
const states = new Map()

function stateOf(a) {
  let s = states.get(a.deviceKey)
  if (!s || s.keyLoaded !== a.deviceKey) {
    const key = loadDeviceKey(a.deviceKey)
    s = {
      keyLoaded: a.deviceKey,
      key,
      sessionID: "mirasim_" + uuid(),
      ticket: "",
      ticketExpiry: 0,
      ticketRetryAt: 0,
      ticketFails: 0,
      unmintableUntil: 0,
    }
    states.set(a.deviceKey, s)
  }
  return s
}

// mintCredential is what the next request is signed and sent with: a device
// ticket when the relay mints one here, the access token itself for as long
// as it reports none. The caller holds the lock.
async function mintCredential(s, a) {
  if (!s.key) throw new Error("Mirasim: the account's device key is unreadable; sign in again")
  const now = Date.now()
  if (s.ticket && now < s.ticketExpiry - TICKET_LEAD) return s.ticket
  if (now < s.unmintableUntil) return a.access
  if (now < s.ticketRetryAt) {
    if (s.ticket && now < s.ticketExpiry) return s.ticket
    throw new Error(
      `mirasim: device ticket mint is backing off for ${Math.max(1, Math.round((s.ticketRetryAt - now) / 1000))}s: ` +
        (s.ticketFails ? `${s.ticketFails} mint attempts have failed` : "no ticket"),
    )
  }
  try {
    const t = await mintTicket(a, s.key)
    s.ticket = t.value
    s.ticketExpiry = t.expiresAt
    s.ticketFails = 0
    return t.value
  } catch (e) {
    if (e instanceof HTTPStatusError) {
      if (e.status === 404) {
        s.unmintableUntil = now + ABSENT_QUIET
        return a.access
      }
      if (e.status === 501) {
        s.unmintableUntil = now + UNMINTABLE_QUIET
        return a.access
      }
      if (e.status === 401) throw e // the access token is stale: the caller's refresh-on-use sees the same answer next round
      if (e.status === 429 || e.status >= 500) {
        noteFailure(s, now)
        if (s.ticket && now < s.ticketExpiry) return s.ticket
      }
    }
    throw e
  }
}

function noteFailure(s, now) {
  const wait = Math.min(TICKET_BACKOFF_BASE << Math.min(s.ticketFails, 5), TICKET_BACKOFF_MAX)
  s.ticketFails++
  s.ticketRetryAt = now + wait
}

// errorResponse is a failure as OpenAI's API gives it. signIn is what it
// means for the account's sign-in: "expired" marks it lapsed, as the
// built-in's refused refresh token did.
const errorResponse = ({ status, message, signIn }) =>
  new Response(JSON.stringify({ error: { message, type: "mirasim_error", code: status } }), {
    status,
    headers: { "Content-Type": "application/json", ...(signIn ? { "X-Magpie-Sign-In": signIn } : {}) },
  })

const signedInError = (e) =>
  errorResponse({
    status: e instanceof SignInGone ? 401 : 502,
    message: String(e?.message ?? e).replace(/^Mirasim: /, ""),
    signIn: e instanceof SignInGone ? (e.expired ? "expired" : "kept") : undefined,
  })

// signed is res saying what it means for the sign-in, as the built-in's
// answer did: a renewed token pair cleared the mark whatever came of the
// request; without one, a success left the mark as it was.
function signed(res, renewed) {
  const said = renewed ? "renewed" : res.ok ? "kept" : null
  if (!said) return res
  const headers = new Headers(res.headers)
  headers.set("X-Magpie-Sign-In", said)
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers })
}

// ---- the plugin ---------------------------------------------------------------------

export async function MirasimAuthPlugin({ client }) {
  // the auth records whose tokens this plugin renewed
  const renewals = new WeakSet()

  // fresh is the account with a live access token, refreshed and saved
  // before its end. Only the service refusing the refresh token ends the
  // account (a 401 or a 403); a hiccup is an error, not a lapse.
  const fresh = (getAuth) =>
    locked(async () => {
      const a = await getAuth()
      if (a?.type !== "oauth" || !a.access || !a.deviceKey) throw new SignInGone("Mirasim: not signed in")
      if (expiryOf(a) - Date.now() > REFRESH_LEAD) return a
      if (!a.refresh) throw new SignInGone("this Mirasim account is signed out; sign in again")
      let p
      try {
        p = await refreshTokens(a.refresh)
      } catch (e) {
        if (e instanceof HTTPStatusError && (e.status === 401 || e.status === 403)) {
          throw new SignInGone(`${a.email || a.accountId || "the account"}'s Mirasim sign-in has expired — sign in again`, true)
        }
        throw new SignInGone("Mirasim: " + String(e?.message ?? e))
      }
      const next = withTokens(a, p.access_token, p.refresh_token, p.expires_in)
      renewals.add(next)
      await client.auth.set({ path: { id: ID }, body: next })
      return next
    })

  // models lists the account's catalog, with the roster beside it, both
  // kept in the auth record so the requests know the thinking form each
  // model takes without another ask.
  const models = async (cred, again = false) => {
    const s = stateOf(cred)
    const credential = await locked(() => mintCredential(s, cred))
    const raw = JSON.parse(await (await signedGet(cred, s.key, credential, MODELS_PATH)).text())
    const parsed = parseModels(raw)
    let roster = ""
    try {
      roster = await (await signedGet(cred, s.key, credential, ROSTER_PATH)).text()
      parseRoster(JSON.parse(roster))
    } catch {
      roster = ""
    }
    await client.auth.set({ path: { id: ID }, body: { ...cred, models: JSON.stringify(raw), roster } }).catch(() => {})
    return { parsed, roster: roster ? parseRoster(JSON.parse(roster)) : null }
  }

  // usage is the account's allowance, magpie's own hook: what the relay's
  // limits route says about the windows the account runs its calls through.
  const usage = async (getAuth) => {
    let signIn = "kept"
    try {
      const cred = await fresh(getAuth)
      if (renewals.has(cred)) signIn = "renewed"
      const s = stateOf(cred)
      const credential = await locked(() => mintCredential(s, cred))
      const raw = JSON.parse(await (await signedGet(cred, s.key, credential, LIMITS_PATH, "usage")).text())
      const limits = parseLimits(raw)
      const windows = limits.windows.map((w) => ({
        name: w.name,
        used: w.usedPercent ?? (w.budget > 0 ? roundPercent((w.used / w.budget) * 100) : 0),
        ...(w.resetAt ? { resetsAt: w.resetAt.toISOString(), resetSecs: Math.max(0, Math.round((w.resetAt.getTime() - Date.now()) / 1000)) } : {}),
        ...(w.status === "limit_reached" ? { display: "used up" } : {}),
      }))
      return {
        plan: cred.plan || "",
        until: Number(cred.planExpiresAt) > 0 ? new Date(Number(cred.planExpiresAt) * 1000).toISOString() : "",
        renew: limits.paid === true ? "auto" : limits.paid === false ? "off" : "",
        windows,
        signIn,
      }
    } catch (e) {
      return { error: String(e?.message ?? e), signIn: e instanceof SignInGone && e.expired ? "expired" : signIn }
    }
  }

  // ask signs and sends one inference request the gateway made: fresh
  // tokens, a ticket under them, the body rewritten into the thinking form
  // the model takes, the metadata sealed, and any x-mirasim-* the caller
  // sent taken off — the relay refuses one it didn't see signed.
  const ask = async (url, init, getAuth) => {
    const u = new URL(url)
    const path = u.pathname
    const body = typeof init.body === "string" ? init.body : ""
    let cred
    try {
      cred = await fresh(getAuth)
    } catch (e) {
      return signedInError(e)
    }
    const wasRenewed = renewals.has(cred)
    let s
    let credential
    let signedHeaders
    let out = body
    try {
      s = stateOf(cred)
      credential = await locked(() => mintCredential(s, cred))
      out = normalizeBody(body, cred.roster ? parseRoster(JSON.parse(cred.roster)) : null)
      signedHeaders = inferenceHeaders(cred, s.key, credential, s.sessionID, path, out)
    } catch (e) {
      // a stale access token on the mint route fails the request without
      // marking the account: the next round refreshes, as the built-in's
      // refresh-on-use did
      return errorResponse({
        status: e instanceof HTTPStatusError && e.status === 401 ? 401 : 502,
        message: String(e?.message ?? e),
        signIn: e instanceof SignInGone ? (e.expired ? "expired" : "kept") : e instanceof HTTPStatusError && e.status === 401 ? "kept" : undefined,
      })
    }
    const h = new Headers(init.headers)
    for (const name of [...h.keys()]) {
      const lower = name.toLowerCase()
      if (lower.startsWith("x-mirasim-")) h.delete(name)
      // the host's AI SDK key headers: the relay would read one as the
      // user's token and refuse it
      else if (lower === "x-api-key" || lower === "authorization") h.delete(name)
    }
    dropBeta(h, "oauth-2025-04-20")
    for (const [name, value] of Object.entries(signedHeaders)) h.set(name, value)
    let res
    try {
      res = await fetch(url, { method: init.method ?? "POST", headers: h, body: out, signal: init.signal })
    } catch (e) {
      return errorResponse({ status: 502, message: String(e?.message ?? e) })
    }
    return signed(res, wasRenewed)
  }

  return {
    auth: {
      provider: ID,
      async loader(getAuth) {
        const a = await getAuth()
        if (a?.type !== "oauth" || !a.access || !a.deviceKey) return {}
        return {
          baseURL: relayOf(a) + "/v1",
          apiKey: "mirasim",
          // every request signed and sealed as the official client's own
          async fetch(input, init = {}) {
            const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url
            return ask(url, init, getAuth)
          },
        }
      },
      methods: [
        {
          type: "oauth",
          label: "Mirasim (browser)",
          prompts: [
            {
              type: "select",
              key: "provider",
              message: "Sign in with",
              options: [
                { label: "GitHub", value: "github" },
                { label: "Google", value: "google" },
              ],
            },
          ],
          authorize: browserSignIn,
        },
        {
          type: "oauth",
          label: "Mirasim (email code)",
          prompts: [
            {
              type: "text",
              key: "email",
              message: "Email address to send the sign-in code to",
              placeholder: "you@example.com",
              validate: (v) => (EMAIL.test(String(v ?? "").trim()) ? null : "that isn't an email address a code can go to"),
            },
          ],
          authorize: emailSignIn,
        },
      ],
      usage,
    },
    async config(config) {
      config.provider ??= {}
      const was = config.provider[ID] ?? {}
      config.provider[ID] = {
        name: "Mirasim",
        npm: ANTHROPIC,
        api: RELAY() + "/v1",
        ...was,
        models: { ...(was.models ?? {}) },
      }
    },
    // the account's own list, as the relay tells it
    provider: {
      id: ID,
      async models(provider, { auth } = {}) {
        if (auth?.type !== "oauth" || !auth.access || !auth.deviceKey) return provider.models
        let cred
        try {
          cred = await fresh(async () => auth)
        } catch (e) {
          // a refused refresh marks the account, as the built-in's did
          if (e?.expired) throw Object.assign(new Error(e.message), { signIn: "expired" })
          return provider.models
        }
        try {
          const { parsed, roster } = await models(cred, true)
          if (!parsed.length) return provider.models
          return Object.fromEntries(parsed.map((m) => [m.id, runtimeModel(m, roster)]))
        } catch {
          return provider.models
        }
      },
    },
  }
}

// runtimeModel is one catalog entry as OpenCode lists it: on Anthropic's
// wire for Claude, DeepSeek, GLM and Kimi, OpenAI Responses for GPT, with
// the reasoning ladder the roster or the family declares.
function runtimeModel(m, roster) {
  const family = familyOf(String(m.id).toLowerCase())
  const spec = roster ? specOf(roster, m.id) : null
  const context = Math.max(Number(m.max_input_tokens ?? 0), Number(spec?.contextWindow ?? 0))
  const efforts = spec?.effort?.length ? spec.effort : familyEfforts(family)
  const npm = family === "codex" ? OPENAI : ANTHROPIC
  return {
    id: m.id,
    providerID: ID,
    name: spec?.label || m.id,
    api: { id: m.id, url: RELAY() + "/v1", npm },
    status: "active",
    headers: {},
    options: {},
    cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
    limit: { context, output: Number(spec?.maxOutput ?? 0) },
    capabilities: {
      temperature: true,
      reasoning: efforts.length > 0,
      attachment: false,
      toolcall: true,
      input: { text: true, image: false, audio: false, video: false, pdf: false },
      output: { text: true, image: false, audio: false, video: false, pdf: false },
      interleaved: false,
    },
    release_date: "",
    variants: Object.fromEntries(efforts.map((e) => [e, { reasoningEffort: e }])),
  }
}

// for tests
export const _internal = {
  loadDeviceKey,
  signatureHeaders,
  sealWith,
  sealPublicKey,
  chacha20,
  chacha20poly1305Seal,
  canonicalMetadata,
  sha256hex,
  parseModels,
  parseRoster,
  specOf,
  thinkingAdaptive,
  parseLimits,
  normalizeBody,
  familyOf,
  agentFor,
  levelBudget,
  budgetLevel,
  roundPercent,
  inferenceHeaders,
  withTokens,
  expiryOf,
  newDeviceKey,
}
