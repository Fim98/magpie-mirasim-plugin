// Cross-checks the plugin's port of the signing envelope against magpie's
// Go implementation: the values internal/mirasim/cross_check_test.go wrote
// to cross-check.json (run `go test ./internal/mirasim -run TestCross`
// first). Run: bun mirasim-plugin/test.mjs
import { createPrivateKey, createPublicKey, diffieHellman, sign as cryptoSign } from "node:crypto"
import { readFileSync } from "node:fs"

const { loadDeviceKey, sealWith, sha256hex } = await import("./index.mjs").then((m) => m._internal)

const cross = JSON.parse(readFileSync(new URL("./cross-check.json", import.meta.url), "utf8"))

const hex = (b) => Buffer.from(b).toString("hex")
const parse = (s) => JSON.parse(s)

let failed = 0
const eq = (name, got, want) => {
  const ok = got === want
  if (!ok) {
    failed++
    console.error(`✗ ${name}\n  got  ${got}\n  want ${want}`)
  } else console.log(`✓ ${name}`)
}

// the fixed device key, as the Go test keeps it
const key = loadDeviceKey(cross.pem)

eq("publicB6", key.publicB6, cross.publicB6)
eq("device id", key.id, cross.deviceId)
eq("sha256hex(cred)", sha256hex("cred"), "55d91a3561684b32df5e58a0d91968b93798af4f924bba383e1c98625ec0c834")
eq("sha256hex(meta)", sha256hex("meta"), "ea3bd73e2b506e00527232b3ed743c066da83a8e3066f62a71e75eb9b4aa1db6")
eq("sha256hex(body)", sha256hex("body"), "230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5")

// the signed payload, as the Go test built it, and the deterministic
// Ed25519 signature over it
const nonce = Buffer.from(Array.from({ length: 12 }, (_, i) => 0xa0 + i))
eq("nonce text", nonce.toString("base64url"), cross.nonceText)
const payload = [
  "mrs-sig-v2",
  "POST",
  "/v1/messages",
  "1730000000000",
  cross.nonceText,
  key.id,
  "0.0.372",
  sha256hex("cred"),
  sha256hex("meta"),
  sha256hex("body"),
].join("\n")
eq("payload", hex(payload), cross.payload)
const sig = cryptoSign(null, Buffer.from(payload), key.private).toString("base64url")
eq("signature", sig, cross.sig)

// the sealed header: the ephemeral secret 0x10..0x2f and its public key, the
// nonce 0x50..0x5b, sealed to the recipient the Go test derived
const X25519_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex")
const ephSecret = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x10 + i))
const ephPriv = createPrivateKey({ key: Buffer.concat([X25519_PKCS8, ephSecret]), format: "der", type: "pkcs8" })
const ephPublicRaw = createPublicKey(ephPriv).export({ type: "spki", format: "der" }).subarray(-32)
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex")
const recipientRaw = Buffer.from(cross.recipient, "base64")
const recipient = createPublicKey({ key: Buffer.concat([X25519_SPKI, recipientRaw]), format: "der", type: "spki" })
const sealNonce = Buffer.from(Array.from({ length: 12 }, (_, i) => 0x50 + i))
const packed = sealWith(
  ephPublicRaw,
  ephPriv,
  recipient,
  { "x-mirasim-session": "s", "x-mirasim-agent": "claude" },
  "POST",
  "/v1/messages",
  sealNonce,
)
eq("sealed header", packed, cross.seal)

// the body normalization, against internal/provider/mirasim_body_test.go
const { normalizeBody, parseRoster, specOf, thinkingAdaptive, familyOf, agentFor } = await import("./index.mjs").then((m) => m._internal)
const json = (o) => JSON.stringify(o)

// a caller asking a token budget of an effort-form model keeps the amount it
// asked for, on the ladder rung the budget maps to
{
  const out = parse(normalizeBody(`{"model":"claude-sonnet-5","max_tokens":64000,"thinking":{"type":"enabled","budget_tokens":20000}}`, null))
  eq("budget→adaptive type", out.thinking.type, "adaptive")
  eq("budget→adaptive effort", out.output_config.effort, "high")
  eq("budget gone", "budget_tokens" in (out.thinking ?? {}), false)
}
// a model the roster says takes a budget keeps the budget form, held inside
// its bounds
{
  const roster = parseRoster(`{"version":"1","agents":{"claude":[{"id":"claude-opus-9","contextWindow":100000,"adaptive":false}]}}`)
  const out = parse(normalizeBody(`{"model":"claude-opus-9","max_tokens":4096,"thinking":{"type":"enabled","budget_tokens":20000}}`, roster))
  eq("budget kept type", out.thinking.type, "enabled")
  eq("budget clamped", String(out.thinking.budget_tokens), "4095")
}
// an effort passes through onto the adaptive form
{
  const out = parse(normalizeBody(`{"model":"claude-sonnet-5","thinking":{"type":"adaptive"},"output_config":{"effort":"xhigh"}}`, null))
  eq("effort passthrough", out.output_config.effort, "xhigh")
}
// DeepSeek's off is a plain effort, its thinking gone
{
  const out = parse(normalizeBody(`{"model":"deepseek-v4","thinking":{"type":"disabled","budget_tokens":1024}}`, null))
  eq("deepseek thinking gone", "thinking" in out, false)
  eq("deepseek off", out.output_config.effort, "off")
}
// a codex body folds an effort the relay doesn't carry; one it does stays
{
  const out = parse(normalizeBody(`{"model":"gpt-6","instructions":"i","input":"x","reasoning":{"effort":"minimal"}}`, null))
  eq("codex minimal→low", out.reasoning.effort, "low")
  const keep = parse(normalizeBody(`{"model":"gpt-6","reasoning":{"effort":"max"}}`, null))
  eq("codex max unmoved", keep.reasoning.effort, "max")
}
// no thinking said, nothing touched — byte for byte
{
  const body = `{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}],"max_tokens":128}`
  eq("no thinking untouched", normalizeBody(body, null), body)
}

// the roster's shapes, as ParseRoster reads them and specOf merges them
const roster = parseRoster({
  version: "1",
  agents: {
    claude: [{ id: "claude-sonnet-4-8", label: "Sonnet", contextWindow: 200000, maxOutput: 64000, effort: ["low", "high"], adaptive: true }],
    dsh: [{ id: "deepseek-v3.2", contextWindow: 128000, adaptive: false }],
  },
  models: { "claude-opus-4-6": { id: "claude-opus-4-6", contextWindow: 320000, effort: ["low", "medium"] } },
})
eq("roster specOf label", specOf(roster, "claude-sonnet-4-8").label, "Sonnet")
eq("roster specOf window", String(specOf(roster, "claude-sonnet-4-8").contextWindow), "200000")
eq("roster specOf effort", JSON.stringify(specOf(roster, "claude-sonnet-4-8").effort), JSON.stringify(["low", "high"]))
eq("roster models entry effort", JSON.stringify(specOf(roster, "claude-opus-4-6").effort), JSON.stringify(["low", "medium"]))
eq("roster dsh adaptive", String(thinkingAdaptive(roster, "deepseek-v3.2").adaptive), "false")
eq("roster unknown", String(thinkingAdaptive(roster, "glm-4.7").known), "false")

// familyOf and agentFor
eq("family deepseek", familyOf("deepseek-v3.2"), "dsh")
eq("family glm", familyOf("glm-4.7"), "zcode")
eq("family kimi", familyOf("kimi-k3"), "kimi")
eq("family gpt", familyOf("gpt-5.4"), "codex")
eq("family claude", familyOf("claude-haiku-4-5"), "claude")
eq("agent messages", agentFor("/v1/messages", json({ model: "glm-4.7" })), "zcode")
eq("agent responses", agentFor("/v1/responses", "{}"), "codex")
eq("agent claude", agentFor("/v1/messages/count_tokens", ""), "claude")

process.exit(failed ? 1 : 0)
