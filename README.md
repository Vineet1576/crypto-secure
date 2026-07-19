# crypto-secure

**Hybrid encryption library (ECDH P-256 + AES-256-GCM) with Express middleware and browser client for automatic end-to-end encrypted communication.** Also supports RSA-2048 OAEP for backward compatibility.

Drop it into your Express backend + React/Vue/any frontend and get **end-to-end encryption with 4 lines of code** — no crypto expertise required.

---

## Why crypto-secure? (The Problem It Solves)

In today's era of mass surveillance, data breaches, and API sniffing, **HTTPS alone is not enough**:

| Threat | HTTPS Protection | crypto-secure Protection |
|---|---|---|
| TLS termination at load balancer | ❌ — plaintext inside your network | ✅ — end-to-end encrypted |
| Cloud provider / hosting access | ❌ — can read your data | ✅ — only your keys can decrypt |
| Man-in-the-middle at proxy layer | ❌ — TLS is terminated | ✅ — ECDH + AES-GCM envelope |
| Database leak (server-side) | ❌ — logged after decryption | ✅ — never stored in plaintext |
| Insider access to server memory | ❌ — plaintext in process | ✅ — encrypted until handled |

**What makes it unique:** Unlike libraries that just provide raw crypto functions, `crypto-secure` gives you **drop-in middleware** that makes every request and response automatically encrypted — your route handlers don't change at all.

---

## Features

- **🔐 Dual protocol** — ECDH P-256 (primary, v2) with per-message ephemeral keys for forward secrecy, plus RSA-2048 OAEP (v1) for backward compatibility. Auto-detected per envelope.
- **✅ Authenticated encryption (AEAD)** — AES-GCM prevents tampering, padding oracle attacks, and chosen-ciphertext attacks (unlike AES-CBC).
- **📦 Payload compression** — Plaintext is gzip-compressed before encryption, reducing wire size by **50–85%** for typical API payloads without any security tradeoff.
- **🔄 Express middleware** — `cs.middleware({ privateKey })` auto-decrypts incoming `req.body` and auto-encrypts outgoing `res.json()`. Zero changes to your route handlers.
- **🌐 Browser client** — Full Web Crypto API implementation. Works with React, Vue, Angular, vanilla JS. No `node-forge` needed on the client.
- **🪝 Axios interceptors** — Built-in request/response interceptors for transparent encryption. Set once, forget about it.
- **🔑 Fresh keys per message** — Every encryption generates a new random AES-256 key (v1) or a new ephemeral ECDH key (v2) and 12-byte IV. Perfect forward secrecy at the message level (v2).
- **📎 AAD (Additional Authenticated Data)** — Bind context metadata (user ID, API version, timestamp) to the ciphertext so it can't be replayed in a different context.
- **💾 Key persistence** — `generateKeyPair("./keys")` writes `.pem` files to disk automatically. `generateECDHKeyPair("./keys")` writes `ecdh-public.pem` and `ecdh-private.pem`.
- **💾 localStorage key caching** — Browser client caches the server's public key in `localStorage` for 24 hours, avoiding re-fetch on page reload (no cookie overhead).
- **🔒 Route-level encryption** — Simple base64 route/value encryption for URL params, tokens, and short strings.
- **📦 Zero extra dependencies in Node** — Only `node-forge` at runtime; compression uses Node's built-in `zlib`. ECDH uses Node.js built-in `crypto` module.
- **🧩 Framework-agnostic frontend** — ES Module export works with any bundler (Vite, Webpack, esbuild, etc.).
- **🛡️ Decompression bomb protection** — `gunzipSync` is limited to 10MB decompressed output, preventing zip-bomb DoS attacks.

---

## Comparison: Traditional vs crypto-secure

| Aspect | Traditional Approach | crypto-secure |
|---|---|---|
| **Setup time** | Days (select algos, implement key exchange, write middleware) | **Minutes** |
| **Lines of code** | 30–100+ per project | **4 lines** (backend) / **6 lines** (frontend) |
| **Encryption type** | Manual per-endpoint | **Automatic** via middleware |
| **Algorithm** | AES-CBC (vulnerable) or raw RSA (slow) | ECDH P-256 + AES-256-GCM |
| **Key exchange** | Hardcoded keys or complex PKI | ECDH P-256 with ephemeral keys |
| **Forward secrecy** | ❌ Rarely implemented | ✅ Per-message (v2 protocol) |
| **Tamper detection** | None (CBC) | Built-in (GCM authentication tag) |
| **Wire size** | Full plaintext + padding | Compressed + encrypted (50–85% smaller, fixed overhead ~214 chars v2) |
| **Frontend support** | Usually none provided | Web Crypto API (React, Vue, etc.) |
| **Key storage** | Manual file management | Auto-save `.pem` or in-memory |

---

## How It Works (Protocol)

### Wire Format (v2 — ECDH, default)

Every encrypted payload on the wire uses this JSON envelope:

```json
{
  "epk": "<base64 ephemeral P-256 public key (124 chars)>",
  "iv":  "<base64 12-byte IV (16 chars)>",
  "t":   "<base64 16-byte GCM authentication tag (24 chars)>",
  "d":   "<base64 AES-GCM ciphertext>",
  "aad": "<base64 additional authenticated data (optional)>"
}
```

**v1 (RSA) envelopes** are also supported for backward compatibility — detected by the presence of `encryptedAESKey` instead of `epk`.

### Encryption Flow (v2)

```
Plaintext (any JSON)
    │
    ▼
JSON.stringify()
    │
    ▼
gzip compress (reduces wire size 50–85%)
    │
    ▼
Generate ephemeral ECDH P-256 keypair
    │
    ├── private key → ECDH(ephemPriv, recipientPub) → shared secret
    │                                                      │
    │                                               SHA-256 + context string
    │                                                      │
    │                                               AES-256 key
    │                                                      │
    └── public key → epk (sent in envelope)                │
                                                           ▼
                                              AES-256-GCM encrypt(compressed)
                                                  │
                                              ├── ciphertext (→ d)
                                              └── auth tag (→ t)
                                                  │
                                                  ▼
                              Base64-encode all binary fields → JSON envelope
```

### Decryption Flow (v2)

```
JSON envelope
    │
    ▼
Base64-decode all fields
    │
    ▼
ECDH(recipientPriv, ephemPub) → same shared secret
    │
    ▼
SHA-256 + context string → same AES-256 key
    │
    ▼
AES-256-GCM decrypt + verify authentication tag
    │
    ▼
gunzip decompress
    │
    ▼
JSON.parse → original payload
```

### Key Exchange Flow

```
Client (Browser)                         Server (Express)
┌─────────────────┐                     ┌──────────────────────────┐
│  generateECDHKey│                     │  generateECDHKeyPair()   │
│  Pair()          │                     │  → server ECDH keys     │
│  → client keys   │                     └───────────┬─────────────┘
└────────┬────────┘                                   │
         │  GET /.well-known/encryption-key           │
         │ ←─────────────────────────────────── ecdhPublicKey
         │                                             │
         │  POST /api/data                             │
         │  Header: x-encryption-key (← client pub)    │
         │  Body: { epk, iv, t, d }                    │
         │ ─────────────────────────────────────────→ │
         │                                             │  ECDH(srvPriv, epk)
         │                                             │  → AES key → decrypt
         │                                             │  → req.body
         │                                             │
         │  Response: { epk, iv, t, d }               │
         │ ←────────────────────────────────────────── │  Generate ephemeral
         │  ECDH(clientPriv, serverEpk)                │  ECDH keypair
         │  → AES key → decrypt                        │  ECDH(srvEphemPriv,
         │  → response.data                            │      clientPub)
         │                                             │  → AES key → encrypt
```

v1 RSA clients follow the same flow but use RSA-2048 OAEP key wrapping instead of ECDH.

---

## Backend Usage (Express)

### Install

```bash
npm install crypto-secure
```

### Minimum Setup — ECDH (recommended, 4 lines)

```js
const cs = require("crypto-secure");
const keypair = cs.generateECDHKeyPair("./keys");
app.use(express.json());
app.use(cs.middleware({ privateKey: keypair.privateKey }));
```

### Minimum Setup — RSA (backward compatible, 4 lines)

```js
const cs = require("crypto-secure");
const keypair = cs.generateKeyPair("./keys");
app.use(express.json());
app.use(cs.middleware({ privateKey: keypair.privateKey }));
```

Your existing routes stay **completely unchanged**:

```js
app.post("/api/data", (req, res) => {
  // req.body is already decrypted automatically
  console.log(req.body);
  res.json({ received: req.body, ok: true });
  // response is auto-encrypted with client's public key
});
```

### Production Setup (key persistence)

```js
const fs = require("fs");
const cs = require("crypto-secure");

const keyFile = "./keys/server-ecdh-key.json";
let keypair;
if (fs.existsSync(keyFile)) {
  keypair = JSON.parse(fs.readFileSync(keyFile, "utf8"));
} else {
  keypair = cs.generateECDHKeyPair("./keys");
  fs.writeFileSync(keyFile, JSON.stringify(keypair));
}

app.use(express.json());
app.use(cs.middleware({ privateKey: keypair.privateKey }));

// Expose your public key for clients
app.get("/.well-known/encryption-key", (req, res) => {
  res.json({ publicKey: keypair.publicKey });
});
```

---

## Frontend Usage (React / Browser)

### Install

```bash
npm install crypto-secure
```

### Setup — ECDH (recommended, 6 lines)

```js
import * as cs from "crypto-secure/client";

const serverKey = await cs.fetchServerPublicKey("/.well-known/encryption-key");
const clientKeys = await cs.generateECDHKeyPair();

axios.defaults.headers.common["x-encryption-key"] =
  cs.getClientHeader(clientKeys.publicKey)["x-encryption-key"];
```

### Encrypt a request

```js
const encrypted = await cs.encrypt(payload, serverKey);
// → { epk, iv, t, d } (v2) or { encryptedAESKey, delta, tag, encryptedData } (v1)
axios.post("/api/data", encrypted);
```

### Decrypt a response

```js
const res = await axios.post("/api/data", payload);
const decrypted = await cs.decrypt(res.data, clientKeys.privateKey);
```

### Automatic encryption via Axios interceptors

```js
axios.interceptors.request.use(cs.createAxiosRequestInterceptor(serverKey));
axios.interceptors.response.use(
  ...cs.createAxiosResponseInterceptor(clientKeys.privateKey)
);
// All requests/responses are now automatically encrypted — zero manual work
```

### Route-level encryption (URL params, tokens, etc.)

```js
const enc = cs.encryptRoute("sensitive-value"); // base64 encoded
const dec = cs.decryptRoute(enc);               // back to original
```

---

## API Reference

### Server-side (`crypto-secure`)

| Function | Description |
|---|---|
| `generateKeyPair(saveTo?)` | Generate RSA-2048 keypair. If `saveTo` is a path, writes `public.pem` and `private.pem` |
| `generateECDHKeyPair(saveTo?)` | Generate ECDH P-256 keypair. If `saveTo` is a path, writes `ecdh-public.pem` and `ecdh-private.pem` |
| `encrypt(payload, publicKey, aad?)` | Hybrid encrypt — auto-detects EC vs RSA key, dispatches to ECDH or RSA path. Payload is gzip-compressed before encryption |
| `decrypt(encryptedPayload, privateKey)` | Hybrid decrypt — auto-detects v2 (ECDH) vs v1 (RSA) envelope format. Ciphertext is gunzip-decompressed after decryption |
| `isEncrypted(obj)` | Check if an object is an encrypted payload (duck-type check on envelope fields for both v1 and v2) |
| `generateAESKey()` | Generate a random 32-byte AES-256 key |
| `generateIV()` | Generate a random 12-byte IV for GCM |
| `middleware(options)` | Express middleware factory. Options: `{ privateKey, publicKeyHeader, decryptBody, encryptResponse, requireClientKey }` |
| `Client` | Node.js client class for programmatic encryption/decryption with key management |

### Browser-side (`crypto-secure/client`)

| Function | Description |
|---|---|
| `generateKeyPair()` | Generate RSA-2048 keypair using Web Crypto API |
| `generateECDHKeyPair()` | Generate ECDH P-256 keypair using Web Crypto API |
| `getClientHeader(publicKeyPem)` | Returns `{ "x-encryption-key": "..." }` header (base64 DER without PEM framing) |
| `fetchServerPublicKey(url)` | Fetch server's public key from endpoint. Cached in memory + localStorage for 24h |
| `clearServerPublicKeyCache()` | Clear in-memory and localStorage cache |
| `encrypt(payload, serverPublicKey)` | Hybrid encrypt for requests — auto-detects EC vs RSA key (with gzip compression) |
| `decrypt(encryptedPayload, clientPrivateKey)` | Hybrid decrypt for responses — auto-detects v2 vs v1 envelope (with gunzip decompression) |
| `encryptRoute(value)` | Base64-encode a route/param value (padding-stripped) |
| `decryptRoute(value)` | Base64-decode a route/param value |
| `createAxiosRequestInterceptor(serverKey, aad?)` | Axios request interceptor — auto-encrypts all outgoing data |
| `createAxiosResponseInterceptor(clientPrivateKey)` | Axios response interceptor — auto-decrypts all incoming responses |

### Middleware Options

| Option | Type | Default | Description |
|---|---|---|---|
| `privateKey` | string (PEM) | **required** | Server's private key (RSA or ECDH) for decrypting request bodies |
| `publicKeyHeader` | string | `"x-encryption-key"` | HTTP header where client sends its public key |
| `decryptBody` | boolean | `true` | Auto-decrypt `req.body` if it's an encrypted envelope |
| `encryptResponse` | boolean | `true` | Auto-encrypt `res.json()` responses with client's public key |
| `requireClientKey` | boolean | `false` | When `true`, rejects requests without the encryption header |

---

## Payload Compression Impact

Since the library gzip-compresses plaintext before encryption, here's the expected reduction in `d` (ciphertext) size:

| JSON Payload Size | Before (base64) | After (compressed + base64) | Reduction |
|---|---|---|---|
| 100 bytes | ~133 chars | ~133 chars | ~0% (gzip overhead) |
| 1 KB | ~1,365 chars | ~410 chars | **~70%** |
| 10 KB | ~13,650 chars | ~2,730 chars | **~80%** |
| 100 KB | ~136,500 chars | ~20,500 chars | **~85%** |
| 1 MB | ~1.37M chars | ~137K chars | **~90%** |

> **Note:** The fixed envelope overhead varies by protocol version — ~214 chars for v2 (ECDH), ~449 chars for v1 (RSA). Compression provides the most benefit for payloads above 500 bytes.

### Wire size comparison by protocol

| Payload | RSA (v1) total | ECDH (v2) total | Savings |
|---|---|---|---|
| 100 bytes | ~582 chars | **~347 chars** | **-40%** |
| 1 KB | ~859 chars | **~624 chars** | **-27%** |
| 10 KB | ~3,179 chars | **~2,944 chars** | **-7%** |

### Real-world performance

The fixed envelope overhead becomes negligible at scale. Gzip compression on repetitive JSON structures is the dominant factor.

| Scenario | Raw JSON | After gzip | v1 (RSA) total | v2 (ECDH) total | v2 overhead vs raw |
|---|---|---|---|---|---|
| **20 form fields** (simple POST) | ~0.4 KB | ~0.16 KB | ~0.61 KB | **~0.43 KB** | **+7%** |
| **50 fields per user × 10 users** (team list) | ~15 KB | ~2.5 KB | ~2.95 KB | **~2.71 KB** | **<1%** |
| **50 fields per user × 100 users** (full directory) | ~150 KB | ~22 KB | ~22.45 KB | **~22.21 KB** | **<0.5%** |
| **Pagination: 50 users per page** (typical API) | ~75 KB | ~11 KB | ~11.45 KB | **~11.21 KB** | **<0.5%** |
| **1 MB file upload** (compressed) | 1 MB | ~0.10 MB | ~0.10 MB | **~0.10 MB** | **<0.1%** |

> **Key takeaway:** For any real-world API payload (>500 bytes), the encryption overhead is **under 1%** of total wire size. The gzip compression typically saves more bytes (50–90%) than encryption adds. This makes `crypto-secure` practical for production APIs serving hundreds of users without meaningful bandwidth impact.

---

## Security Details

### Algorithms

| Component | v2 (ECDH) | v1 (RSA) |
|---|---|---|
| Key agreement | ECDH P-256 with ephemeral keys | RSA-2048 OAEP SHA-256 |
| Key derivation | SHA-256(sharedSecret \|\| context) | Direct decryption |
| Symmetric encryption | AES-256-GCM | AES-256-GCM |
| IV | 12 bytes random | 12 bytes random |
| Authentication tag | 128-bit GCM tag | 128-bit GCM tag |
| Compression | gzip (deflate) before encryption | gzip (deflate) before encryption |

### Security Properties

- **AEAD (Authenticated Encryption with Associated Data)** — GCM provides both confidentiality and integrity. Any tampering with ciphertext is detected on decryption.
- **Per-message forward secrecy (v2)** — Every `encrypt()` generates a fresh ephemeral ECDH keypair. The ephemeral private key is discarded after encryption. Compromising the server's long-term key does not decrypt past messages.
- **Fresh key per message** — Every `encrypt()` call generates a new AES key (v1) or ephemeral ECDH keypair (v2) and IV via cryptographic RNG.
- **Key encapsulation** — The AES key is never transmitted in plaintext. v1 wraps it with RSA-OAEP. v2 derives it via ECDH + SHA-256.
- **Padding oracle immunity** — GCM is not vulnerable to padding oracle attacks (unlike CBC).
- **AAD binding** — Optional additional data is cryptographically bound to the ciphertext. Modifying AAD invalidates the tag.
- **No plaintext in transit** — The only data on the wire is the encrypted envelope.
- **Decompression bomb protection** — Gunzip decompression limited to 10MB max output.

### What crypto-secure does NOT protect against

- **Side-channel attacks** (timing, power analysis, cache) — not designed for HSM-level security
- **Quantum computing** — ECDH P-256 and AES-256 are not quantum-resistant. Post-quantum migration is a future concern
- **Compromised private keys (v1 only)** — v1 RSA mode has no forward secrecy; past traffic can be decrypted if key is stolen
- **Client-side XSS** — an attacker with JS execution can read plaintext after decryption

---

## Architecture

```
                          ┌─────────────────────────────────────────┐
                          │         Shared Protocol v2              │
                          │   ECDH P-256 + SHA-256 KDF             │
                          │   AES-256-GCM (authenticated)          │
                          │   gzip compression before encrypt      │
                          │   Base64 wire encoding                  │
                          │   Backward compatible with v1 (RSA)     │
                          └─────────────────────────────────────────┘
                                     ↕
           ┌──────────────────────────┴──────────────────────────┐
           ▼                                                      ▼
┌─────────────────────────┐                    ┌──────────────────────────┐
│   Node.js (server)      │                    │  Browser (client)        │
│                         │                    │                          │
│  crypto-secure.js       │                    │  client-browser.mjs      │
│  └─ ECDH + RSA crypto   │                    │  └─ Web Crypto API       │
│  └─ node-forge (RSA)    │                    │  └─ CompressionStream    │
│  └─ Node crypto (ECDH)  │                    │  └─ localStorage caching │
│  └─ zlib compression    │                    │  └─ Axios interceptors   │
│                         │                    │                          │
│  middleware.js           │                    │  encryptRoute()          │
│  └─ Express middleware   │                    │  decryptRoute()          │
│  └─ Auto decrypt req     │                    │                          │
│  └─ Auto encrypt res     │                    │                          │
│                         │                    │                          │
│  client.js              │                    │                          │
│  └─ Node.js client class│                    │                          │
└─────────────────────────┘                    └──────────────────────────┘
```

### Protocol Detection

| Envelope has | Protocol | Key exchange |
|---|---|---|
| `epk` field (and `iv`, `t`, `d`) | v2 | ECDH P-256 with ephemeral keys |
| `encryptedAESKey` field (and `delta`, `tag`, `encryptedData`) | v1 | RSA-2048 OAEP |

### Core Files

| File | Purpose |
|---|---|
| `crypto-secure.js` | Core hybrid encryption engine. UMD format — works in Node.js, AMD, and browser globals. Uses `node-forge` for RSA and Node.js `crypto` for ECDH. |
| `middleware.js` | Express middleware factory. Decrypts `req.body`, encrypts `res.json()`, handles PEM key reconstruction from HTTP headers. |
| `client.js` | Node.js client class with key pair management and helper methods for request/response encryption. |
| `client-browser.mjs` | Browser client as an ES Module. Uses Web Crypto API (`crypto.subtle`) and `CompressionStream` for native browser compression. Includes Axios interceptor factories and localStorage-based key caching. |
| `index.js` | Package entry point. Aggregates all modules and attaches `.middleware` and `.Client` to the main export. |

---

## Package Contents

```
crypto-secure/
├── index.js                # Package entry (CommonJS)
├── crypto-secure.js        # Core crypto engine (UMD)
├── middleware.js            # Express middleware (CommonJS)
├── client.js               # Node.js client (CommonJS)
├── client-browser.mjs      # Browser client (ES Module)
├── CONTRIBUTING.md         # Contribution guidelines
├── CODE_OF_CONDUCT.md      # Code of conduct
├── LICENSE                 # MIT license
├── package.json
└── README.md
```

---

## Requirements

- **Node.js** ≥ 14.18.0 (uses `Buffer`, `zlib`, `crypto`, `require`)
- **Express** 4.x or 5.x (peer dependency, only needed for middleware)
- **Browsers**: Chrome 80+, Firefox 110+, Safari 16.4+, Edge 80+ (requires `CompressionStream` and Web Crypto API support)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
