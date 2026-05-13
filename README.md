# crypto-secure

**Hybrid encryption (RSA + AES-GCM) with Express middleware for automatic request/response encryption.**

Drop it into your Express backend + React frontend and get end-to-end encryption with **4 lines of code**.

---

## Features

- **Hybrid encryption** — RSA-2048 wraps AES-256 keys, AES-256-GCM encrypts payloads
- **Authenticated encryption** — AES-GCM prevents tampering (unlike CBC which is vulnerable to padding oracle attacks)
- **Express middleware** — auto-decrypts incoming requests, auto-encrypts outgoing responses
- **React / browser client** — uses Web Crypto API, works with any framework
- **Zero config for routes** — existing endpoints remain unchanged
- **Auto-save keys** — `generateKeyPair("./keys")` writes `.pem` files to disk

---

## Comparison: Traditional vs This Package

| Aspect | Traditional Approach | crypto-secure |
|---|---|---|
| **Encryption type** | Manual per-endpoint | Automatic via middleware |
| **Algorithm** | AES-CBC or custom | AES-256-GCM (authenticated) |
| **Key exchange** | Hardcoded or manual | RSA-2048 OAEP SHA-256 |
| **Tamper protection** | None (CBC) | Built-in (GCM tag) |
| **Lines of code** | 30-100+ per project | **4 lines** (backend) / **6 lines** (frontend) |
| **Request decryption** | Manual | Automatic |
| **Response encryption** | Manual | Automatic |
| **Key storage** | Manual | Auto-save `.pem` files |
| **Frontend support** | Usually none | Web Crypto API (React, Vue, etc.) |
| **Security rating** | ~6/10 (CBC, no auth) | ~9/10 (GCM, OAEP SHA-256, AAD) |

---

## Backend Usage (Express)

### Install

```bash
npm install crypto-secure
```

### Setup (4 lines)

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

### Key persistence (survive restarts)

```js
const fs = require("fs");
const cs = require("crypto-secure");

const keyFile = "./keys/server-key.json";
let keypair;
if (fs.existsSync(keyFile)) {
  keypair = JSON.parse(fs.readFileSync(keyFile, "utf8"));
} else {
  keypair = cs.generateKeyPair("./keys");
  fs.writeFileSync(keyFile, JSON.stringify(keypair));
}

app.use(express.json());
app.use(cs.middleware({ privateKey: keypair.privateKey }));

// Expose your public key for clients
app.get("/.well-known/encryption-key", (req, res) => {
  res.json({ publicKey: keypair.publicKey });
});
```

### How it works

1. **Incoming request** — Client encrypts payload with server's public key → middleware decrypts with server's private key
2. **Outgoing response** — Server encrypts payload with client's public key (from `x-encryption-key` header) → client decrypts with its private key

---

## Frontend Usage (React / Browser)

### Install

```bash
npm install crypto-secure
```

### Setup (6 lines)

```js
import * as cs from "crypto-secure/client";

const serverKey = await cs.fetchServerPublicKey("/user/publicKey");
const clientKeys = await cs.generateKeyPair();

axios.defaults.headers.common["x-encryption-key"] =
  cs.getClientHeader(clientKeys.publicKey)["x-encryption-key"];
```

### Encrypt a request

```js
const encrypted = await cs.encrypt(payload, serverKey);
// → { encryptedAESKey, delta, tag, encryptedData }
axios.post("/api/data", encrypted);
```

### Decrypt a response

```js
const res = await axios.post("/api/data", payload);
const decrypted = await cs.decrypt(res.data, clientKeys.privateKey);
```

### Or use built-in Axios interceptors

```js
axios.interceptors.request.use(cs.createAxiosRequestInterceptor(serverKey));
axios.interceptors.response.use(
  ...cs.createAxiosResponseInterceptor(clientKeys.privateKey)
);
// Now all requests/responses are automatically encrypted
```

### Route-level encryption (for URL params, tokens, etc.)

```js
// Encrypt
const enc = cs.encryptRoute("sensitive-value");
// Decrypt
const dec = cs.decryptRoute(enc);
```

---

## API Reference

### Server-side (`crypto-secure`)

| Function | Description |
|---|---|
| `generateKeyPair(saveTo?)` | Generate RSA-2048 keypair. If `saveTo` is a path, saves `public.pem` and `private.pem` |
| `encrypt(payload, publicKey, aad?)` | Hybrid encrypt with RSA + AES-GCM |
| `decrypt(encryptedPayload, privateKey)` | Hybrid decrypt |
| `isEncrypted(obj)` | Check if an object is an encrypted payload |
| `middleware(options)` | Express middleware factory. Options: `{ privateKey, publicKeyHeader, decryptBody, encryptResponse }` |
| `Client` | Node.js client class for programmatic use |

### Browser-side (`crypto-secure/client`)

| Function | Description |
|---|---|
| `generateKeyPair()` | Generate RSA-2048 keypair using Web Crypto API |
| `getClientHeader(publicKeyPem)` | Returns `{ "x-encryption-key": "..." }` header |
| `fetchServerPublicKey(url)` | Fetch server's public key from endpoint (cached in cookie) |
| `encrypt(payload, serverPublicKey)` | Hybrid encrypt for requests |
| `decrypt(encryptedPayload, clientPrivateKey)` | Hybrid decrypt for responses |
| `encryptRoute(value)` | Simple base64 route-level encryption |
| `decryptRoute(value)` | Simple base64 route-level decryption |
| `createAxiosRequestInterceptor(serverKey)` | Axios request interceptor factory |
| `createAxiosResponseInterceptor(clientPrivateKey)` | Axios response interceptor factory |

---

## Architecture

```
Client (Browser)                          Server (Express)
┌─────────────────┐                      ┌──────────────────────┐
│  generateKeyPair │                      │  generateKeyPair       │
│  → client keys   │                      │  → server keys         │
└────────┬────────┘                      └───────────┬──────────┘
         │                                            │
         │  fetchServerPublicKey()                    │
         │ ←────────────────────────────────── publicKey
         │                                            │
         │  POST /api/data                           │
         │  Header: x-encryption-key                  │
         │  Body: { encryptedAESKey,                  │
         │           delta, tag, encryptedData }      │
         │ ──────────────────────────────────────────→ │
         │                                            │  decrypt with
         │                                            │  server privateKey
         │                                            │  → req.body
         │                                            │
         │  Response: { encryptedAESKey,               │
         │              delta, tag, encryptedData }    │
         │ ←────────────────────────────────────────── │  encrypt with
         │                                            │  client publicKey
         │  decrypt with                              │
         │  client privateKey                         │
         │  → response.data                           │
```

---

## Security

- **AES-256-GCM** — authenticated encryption, prevents padding oracle and tampering attacks
- **RSA-2048 OAEP** with SHA-256 — secure key wrapping
- **MGF1** uses SHA-256 (not SHA-1)
- **AAD support** — bind context data (sender ID, version, etc.) to ciphertext
- **Fresh random key + IV** per encryption
- **No plaintext keys in transit** — only RSA-wrapped AES keys

---

## License

© Vineet Rana — All rights reserved.
