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

export async function generateECDHKeyPair() {
  var ecKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );

  var spkiDer = await crypto.subtle.exportKey("spki", ecKeyPair.publicKey);
  var pkcs8Der = await crypto.subtle.exportKey("pkcs8", ecKeyPair.privateKey);

  return {
    publicKey: binaryToPem(spkiDer, "PUBLIC KEY"),
    privateKey: binaryToPem(pkcs8Der, "PRIVATE KEY"),
    _publicKeyObj: ecKeyPair.publicKey,
    _privateKeyObj: ecKeyPair.privateKey,
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
  var storedKey = readStorage("crypto_public_key");
  if (storedKey) { _serverPublicKeyPem = storedKey; return storedKey; }

  var res = await fetch(url);
  if (!res.ok) throw new Error("Failed to fetch server public key: " + res.status);
  var json = await res.json();
  var key = json.publicKey || json;
  if (!key) throw new Error("No publicKey in server response");

  _serverPublicKeyPem = key;
  writeStorage("crypto_public_key", key, 86400);
  return key;
}

export function clearServerPublicKeyCache() {
  _serverPublicKeyPem = "";
  try { localStorage.removeItem("crypto_public_key"); } catch (e) {}
}

function readStorage(name) {
  try {
    var value = localStorage.getItem(name);
    if (value) {
      var record = JSON.parse(value);
      if (record.t && Date.now() < record.t) return record.v;
      localStorage.removeItem(name);
    }
  } catch (e) {}
  return "";
}

function writeStorage(name, value, maxAge) {
  try {
    localStorage.setItem(name, JSON.stringify({
      v: value,
      t: Date.now() + maxAge * 1000,
    }));
  } catch (e) {}
}

// ─── Hybrid Encrypt / Decrypt ─────────────────────────────────

async function ecdhDeriveAESKey(ecdhPrivateKey, peerPublicKeySpkiDer) {
  var peerKey = await crypto.subtle.importKey(
    "spki", peerPublicKeySpkiDer,
    { name: "ECDH", namedCurve: "P-256" },
    false, [],
  );

  var sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerKey },
    ecdhPrivateKey,
    256,
  );

  var ctx = textEncoder.encode("crypto-secure-ecdh-v2");
  var combined = new Uint8Array(32 + ctx.length);
  combined.set(new Uint8Array(sharedBits), 0);
  combined.set(ctx, 32);

  return await crypto.subtle.digest("SHA-256", combined);
}

async function ecdhEncryptBrowser(payload, serverPublicKeyPem, aad) {
  var ephemKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );

  var aesKeyRaw = await ecdhDeriveAESKey(
    ephemKeyPair.privateKey,
    pemToBinary(serverPublicKeyPem),
  );

  var aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: "AES-GCM" }, false, ["encrypt"]);

  var iv = crypto.getRandomValues(new Uint8Array(12));
  var plaintext = textEncoder.encode(JSON.stringify(payload));
  var compressed = await gzipCompress(plaintext);

  var gcmOpts = { name: "AES-GCM", iv: iv, tagLength: 128 };
  if (aad) {
    gcmOpts.additionalData = typeof aad === "string"
      ? textEncoder.encode(aad)
      : new Uint8Array(aad);
  }
  var encryptedData = await crypto.subtle.encrypt(gcmOpts, aesKey, compressed);

  var tag = new Uint8Array(encryptedData.slice(-16));
  var ciphertext = new Uint8Array(encryptedData.slice(0, -16));

  var ephemPubDer = await crypto.subtle.exportKey("spki", ephemKeyPair.publicKey);

  var output = {
    epk: bytesToBase64(new Uint8Array(ephemPubDer)),
    iv: bytesToBase64(iv),
    t: bytesToBase64(tag),
    d: bytesToBase64(ciphertext),
  };

  if (aad) {
    output.aad = bytesToBase64(
      typeof aad === "string" ? textEncoder.encode(aad) : new Uint8Array(aad),
    );
  }

  return output;
}

async function rsaEncryptBrowser(payload, serverPublicKeyPem, aad) {
  var aesKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  var iv = crypto.getRandomValues(new Uint8Array(12));

  var aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: "AES-GCM" }, false, ["encrypt"]);

  var plaintext = textEncoder.encode(JSON.stringify(payload));
  var compressed = await gzipCompress(plaintext);

  var gcmOpts = { name: "AES-GCM", iv: iv, tagLength: 128 };
  if (aad) {
    gcmOpts.additionalData = typeof aad === "string"
      ? textEncoder.encode(aad)
      : new Uint8Array(aad);
  }
  var encryptedData = await crypto.subtle.encrypt(gcmOpts, aesKey, compressed);

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

  var output = {
    encryptedAESKey: bytesToBase64(new Uint8Array(encryptedAESKey)),
    delta: bytesToBase64(iv),
    tag: bytesToBase64(tag),
    encryptedData: bytesToBase64(ciphertext),
  };

  if (aad) {
    output.aad = bytesToBase64(
      typeof aad === "string" ? textEncoder.encode(aad) : new Uint8Array(aad),
    );
  }

  return output;
}

function isECPublicKey(publicKeyPem) {
  try {
    var der = pemToBinary(publicKeyPem);
    // SPKI format: first byte 0x30 (SEQUENCE), algorithm identifier follows
    // EC keys have OID 1.2.840.10045.2.1 (06 07 2A 86 48 CE 3D 02 01)
    var view = new Uint8Array(der);
    for (var i = 0; i < view.length - 9; i++) {
      if (view[i] === 0x06 && view[i + 1] === 0x07 &&
          view[i + 2] === 0x2A && view[i + 3] === 0x86 &&
          view[i + 4] === 0x48 && view[i + 5] === 0xCE &&
          view[i + 6] === 0x3D && view[i + 7] === 0x02 &&
          view[i + 8] === 0x01) {
        return true;
      }
    }
  } catch (e) {}
  return false;
}

export async function encrypt(payload, serverPublicKeyPem, aad) {
  if (isECPublicKey(serverPublicKeyPem)) {
    return await ecdhEncryptBrowser(payload, serverPublicKeyPem, aad);
  }
  return await rsaEncryptBrowser(payload, serverPublicKeyPem, aad);
}

async function ecdhDecryptBrowser(encryptedPayload, clientPrivateKeyPem) {
  var privKeyDer = pemToBinary(clientPrivateKeyPem);
  var privKey = await crypto.subtle.importKey(
    "pkcs8", privKeyDer,
    { name: "ECDH", namedCurve: "P-256" },
    false, ["deriveBits"],
  );

  var ephemPubDer = base64ToBytes(encryptedPayload.epk).buffer;
  var ephemPubKey = await crypto.subtle.importKey(
    "spki", ephemPubDer,
    { name: "ECDH", namedCurve: "P-256" },
    false, [],
  );

  var aesKeyRaw = await ecdhDeriveAESKey(privKey, ephemPubDer);
  var aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]);

  var iv = base64ToBytes(encryptedPayload.iv);
  var tag = base64ToBytes(encryptedPayload.t);
  var ciphertext = base64ToBytes(encryptedPayload.d);

  var combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  var gcmOpts = { name: "AES-GCM", iv: iv, tagLength: 128 };
  if (encryptedPayload.aad) {
    gcmOpts.additionalData = base64ToBytes(encryptedPayload.aad);
  }

  var decrypted = await crypto.subtle.decrypt(gcmOpts, aesKey, combined);

  var decompressed = await gzipDecompress(new Uint8Array(decrypted));
  var text = textDecoder.decode(decompressed);
  try { return JSON.parse(text); } catch { return text; }
}

export async function decrypt(encryptedPayload, clientPrivateKeyPem) {
  if (encryptedPayload && encryptedPayload.epk) {
    return await ecdhDecryptBrowser(encryptedPayload, clientPrivateKeyPem);
  }

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

  var ciphertext = base64ToBytes(encryptedPayload.encryptedData);
  var tag = base64ToBytes(encryptedPayload.tag);
  var combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  var gcmOpts = { name: "AES-GCM", iv: base64ToBytes(encryptedPayload.delta), tagLength: 128 };
  if (encryptedPayload.aad) {
    gcmOpts.additionalData = base64ToBytes(encryptedPayload.aad);
  }

  var decrypted = await crypto.subtle.decrypt(gcmOpts, aesKey, combined);

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

export function createAxiosRequestInterceptor(serverPublicKeyPem, aad) {
  return async function requestInterceptor(config) {
    if (!config.headers) config.headers = {};

    var isFormData = typeof FormData !== "undefined" && config.data instanceof FormData;
    var isBinary = config.data instanceof Blob || config.data instanceof ArrayBuffer;
    var hasBody = config.data !== undefined && config.data !== null && !isFormData && !isBinary;

    var hasParamObj = config.params && typeof config.params === "object" && !Array.isArray(config.params);

    if (hasParamObj && !hasBody) {
      var encrypted = await encrypt(config.params, serverPublicKeyPem, aad);
      config.params = { data: JSON.stringify(encrypted) };
    }

    if (hasBody) {
      var encrypted = await encrypt(config.data, serverPublicKeyPem, aad);
      config.data = { data: encrypted };
    }

    return config;
  };
}

export function createAxiosResponseInterceptor(clientPrivateKeyPem) {
  var isEncrypted = function (obj) {
    return obj && typeof obj === "object" && (
      (typeof obj.encryptedAESKey === "string" && typeof obj.tag === "string") ||
      (typeof obj.epk === "string" && typeof obj.t === "string")
    );
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
