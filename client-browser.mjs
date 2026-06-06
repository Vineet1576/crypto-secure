// Browser client for CryptoSecure — uses Web Crypto API, compatible with
// the server middleware (AES-256-GCM + RSA-OAEP SHA-256).
//
// Usage:
//   import * as cs from "crypto-secure/client";
//   const serverKey = await cs.fetchServerPublicKey("/user/publicKey");
//   const clientKeys = await cs.generateKeyPair();
//   const encrypted = await cs.encrypt({ msg: "hello" }, serverKey);
//   const decrypted = await cs.decrypt(encrypted, clientKeys.privateKey);

var textEncoder = new TextEncoder();
var textDecoder = new TextDecoder();

async function gzipCompress(data) {
  var compressed = await new Response(
    new Blob([data]).stream().pipeThrough(new CompressionStream("gzip")),
  ).arrayBuffer();
  return new Uint8Array(compressed);
}

async function gzipDecompress(data) {
  var decompressed = await new Response(
    new Blob([data]).stream().pipeThrough(new DecompressionStream("gzip")),
  ).arrayBuffer();
  return new Uint8Array(decompressed);
}

function bytesToBase64(bytes) {
  var binary = "";
  for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(b64) {
  var binary = atob(b64);
  var bytes = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function pemToBinary(pem) {
  var b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(b64).buffer;
}

function binaryToPem(derBytes, label) {
  var b64 = bytesToBase64(new Uint8Array(derBytes));
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) {
    lines.push(b64.substring(i, i + 64));
  }
  return (
    "-----BEGIN " + label + "-----\r\n" +
    lines.join("\r\n") +
    "\r\n-----END " + label + "-----"
  );
}

// ─── Key Management ───────────────────────────────────────────

export async function generateKeyPair() {
  var rsaKeyPair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );

  var spkiDer = await crypto.subtle.exportKey("spki", rsaKeyPair.publicKey);
  var pkcs8Der = await crypto.subtle.exportKey("pkcs8", rsaKeyPair.privateKey);

  return {
    publicKey: binaryToPem(spkiDer, "PUBLIC KEY"),
    privateKey: binaryToPem(pkcs8Der, "PRIVATE KEY"),
    _publicKeyObj: rsaKeyPair.publicKey,
    _privateKeyObj: rsaKeyPair.privateKey,
  };
}

export function getClientHeader(clientPublicKeyPem) {
  var b64 = clientPublicKeyPem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  return { "x-encryption-key": b64 };
}

// ─── Server Public Key ────────────────────────────────────────

var _serverPublicKeyPem = "";

export async function fetchServerPublicKey(url) {
  if (_serverPublicKeyPem) return _serverPublicKeyPem;
  var cookieKey = readCookie("crypto_public_key");
  if (cookieKey) { _serverPublicKeyPem = cookieKey; return cookieKey; }

  var res = await fetch(url);
  if (!res.ok) throw new Error("Failed to fetch server public key: " + res.status);
  var json = await res.json();
  var key = json.publicKey || json;
  if (!key) throw new Error("No publicKey in server response");

  _serverPublicKeyPem = key;
  writeCookie("crypto_public_key", key, 86400);
  return key;
}

export function clearServerPublicKeyCache() {
  _serverPublicKeyPem = "";
  document.cookie = "crypto_public_key=; path=/; max-age=0";
}

function readCookie(name) {
  var m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : "";
}

function writeCookie(name, value, maxAge) {
  document.cookie = name + "=" + encodeURIComponent(value) + "; path=/; max-age=" + maxAge + "; SameSite=Lax";
}

// ─── Hybrid Encrypt / Decrypt ─────────────────────────────────

export async function encrypt(payload, serverPublicKeyPem) {
  if (!serverPublicKeyPem) throw new Error("Server public key required");

  var aesKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  var iv = crypto.getRandomValues(new Uint8Array(12)); // 12 bytes for GCM

  var aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: "AES-GCM" }, false, ["encrypt"]);

  var plaintext = textEncoder.encode(JSON.stringify(payload));
  var compressed = await gzipCompress(plaintext);
  var encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv, tagLength: 128 },
    aesKey,
    compressed,
  );

  // GCM appends the tag to the ciphertext — split them
  var tag = new Uint8Array(encryptedData.slice(-16));
  var ciphertext = new Uint8Array(encryptedData.slice(0, -16));

  var rsaKey = await crypto.subtle.importKey(
    "spki",
    pemToBinary(serverPublicKeyPem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );

  var encryptedAESKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    rsaKey,
    aesKeyRaw,
  );

  return {
    encryptedAESKey: bytesToBase64(new Uint8Array(encryptedAESKey)),
    delta: bytesToBase64(iv),
    tag: bytesToBase64(tag),
    encryptedData: bytesToBase64(ciphertext),
  };
}

export async function decrypt(encryptedPayload, clientPrivateKeyPem) {
  if (!encryptedPayload || !encryptedPayload.encryptedAESKey) {
    throw new Error("Invalid encrypted payload");
  }

  var rsaKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToBinary(clientPrivateKeyPem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );

  var aesKeyRaw = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    rsaKey,
    base64ToBytes(encryptedPayload.encryptedAESKey),
  );

  var aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]);

  // Recombine ciphertext + tag for Web Crypto API
  var ciphertext = base64ToBytes(encryptedPayload.encryptedData);
  var tag = base64ToBytes(encryptedPayload.tag);
  var combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  var decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(encryptedPayload.delta), tagLength: 128 },
    aesKey,
    combined,
  );

  var decompressed = await gzipDecompress(new Uint8Array(decrypted));
  var text = textDecoder.decode(decompressed);
  try { return JSON.parse(text); } catch { return text; }
}

// ─── Route-level base64 encrypt/decrypt (for URL params etc.) ─

export function encryptRoute(value) {
  try {
    return btoa(encodeURIComponent(String(value))).replace(/=/g, "");
  } catch { return ""; }
}

export function decryptRoute(value) {
  if (!value) return "";
  try {
    var pad = (4 - (value.length % 4)) % 4;
    return decodeURIComponent(atob(value + "=".repeat(pad)));
  } catch { return ""; }
}

// ─── Axios Interceptors (optional) ────────────────────────────

export function createAxiosRequestInterceptor(serverPublicKeyPem) {
  return async function requestInterceptor(config) {
    if (!config.headers) config.headers = {};

    var isFormData = typeof FormData !== "undefined" && config.data instanceof FormData;
    var isBinary = config.data instanceof Blob || config.data instanceof ArrayBuffer;
    var hasBody = config.data !== undefined && config.data !== null && !isFormData && !isBinary;

    var hasParamObj = config.params && typeof config.params === "object" && !Array.isArray(config.params);

    if (hasParamObj && !hasBody) {
      var encrypted = await encrypt(config.params, serverPublicKeyPem);
      config.params = { data: JSON.stringify(encrypted) };
    }

    if (hasBody) {
      var encrypted = await encrypt(config.data, serverPublicKeyPem);
      config.data = { data: encrypted };
    }

    return config;
  };
}

export function createAxiosResponseInterceptor(clientPrivateKeyPem) {
  var isEncrypted = function (obj) {
    return obj && typeof obj === "object" && typeof obj.encryptedAESKey === "string" && typeof obj.tag === "string";
  };

  return [
    async function (response) {
      var payload = response.data;
      if (payload && isEncrypted(payload)) {
        response.data = await decrypt(payload, clientPrivateKeyPem);
      }
      return response;
    },
    async function (error) {
      var payload = error.response && error.response.data;
      if (payload && isEncrypted(payload)) {
        try {
          error.response.data = await decrypt(payload, clientPrivateKeyPem);
        } catch {}
      }
      return Promise.reject(error);
    },
  ];
}
