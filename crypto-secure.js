(function (global, factory) {
  typeof exports === "object" && typeof module !== "undefined"
    ? (module.exports = factory())
    : typeof define === "function" && define.amd
      ? define(factory)
      : (global.CryptoSecure = factory());
})(this, function () {
  "use strict";

  var forge, zlib, crypto;
  if (typeof window !== "undefined" && window.forge) {
    forge = window.forge;
  } else {
    forge = require("node-forge");
    zlib = require("zlib");
    crypto = require("crypto");
  }

  var ALGORITHM = "AES-GCM";
  var KEY_SIZE = 32;
  var IV_SIZE = 12;
  var MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024;

  function generateKeyPair(saveTo) {
    var keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    var result = {
      publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
      privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
    };

    if (saveTo) {
      if (saveTo.indexOf("..") !== -1) {
        throw new Error(
          "Path traversal detected: key save path must not contain '..'",
        );
      }
      try {
        var fs = require("fs");
        var path = require("path");
        if (!fs.existsSync(saveTo)) fs.mkdirSync(saveTo, { recursive: true });
        fs.writeFileSync(path.join(saveTo, "public.pem"), result.publicKey);
        fs.writeFileSync(path.join(saveTo, "private.pem"), result.privateKey);
      } catch (e) {
        throw new Error("Failed to save keys to disk: " + e.message);
      }
    }

    return result;
  }

  function generateAESKey() {
    return forge.random.getBytesSync(KEY_SIZE);
  }

  function generateIV() {
    return forge.random.getBytesSync(IV_SIZE);
  }

  function encryptAES(data, key, iv, aad) {
    var cipher = forge.cipher.createCipher(ALGORITHM, key);
    var opts = { iv: iv, tagLength: 128 };
    if (aad) {
      opts.additionalData = forge.util.createBuffer(
        typeof aad === "string" ? aad : aad.getBytes(),
      );
    }
    cipher.start(opts);
    var jsonStr = JSON.stringify(data);
    var compressed = zlib.gzipSync(Buffer.from(jsonStr, "utf8"));
    cipher.update(
      forge.util.createBuffer(compressed.toString("latin1"), "binary"),
    );
    if (!cipher.finish()) {
      throw new Error("AES-GCM encryption failed");
    }
    var tag = cipher.mode.tag;
    var tagBytes = tag.bytes ? tag.bytes() : tag;
    if (!tagBytes || tagBytes.length !== 16) {
      throw new Error(
        "AES-GCM encryption failed to produce a valid authentication tag",
      );
    }
    return {
      data: cipher.output.getBytes(),
      tag: tagBytes,
    };
  }

  function decryptAES(encryptedData, key, iv, tag, aad) {
    if (!tag || tag.length !== 16) {
      throw new Error(
        "Decryption failed: invalid authentication tag length",
      );
    }
    var decipher = forge.cipher.createDecipher(ALGORITHM, key);
    var opts = { iv: iv, tag: tag };
    if (aad) {
      opts.additionalData = forge.util.createBuffer(
        typeof aad === "string" ? aad : aad.getBytes(),
      );
    }
    decipher.start(opts);
    decipher.update(forge.util.createBuffer(encryptedData));
    if (!decipher.finish()) {
      throw new Error(
        "Decryption failed: authentication tag mismatch (data may be tampered)",
      );
    }
    var decrypted = decipher.output.getBytes();
    var decompressed = zlib.gunzipSync(Buffer.from(decrypted, "latin1"), {
      maxOutputLength: MAX_DECOMPRESSED_SIZE,
    });
    return JSON.parse(decompressed.toString("utf8"));
  }

  function encryptRSA(data, publicKey) {
    var pubKey = forge.pki.publicKeyFromPem(publicKey);
    return pubKey.encrypt(data, "RSA-OAEP", {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() },
    });
  }

  function decryptRSA(encryptedData, privateKey) {
    var privKey = forge.pki.privateKeyFromPem(privateKey);
    return privKey.decrypt(encryptedData, "RSA-OAEP", {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() },
    });
  }

  // ─── ECDH Key Agreement (v2 protocol) ────────────────────────

  function deriveAESKey(sharedSecret) {
    return crypto
      .createHash("sha256")
      .update(Buffer.from(sharedSecret))
      .update(Buffer.from("crypto-secure-ecdh-v2", "utf8"))
      .digest();
  }

  function generateECDHKeyPair(saveTo) {
    var keypair = crypto.generateKeyPairSync("ec", {
      namedCurve: "P-256",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    var result = {
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey,
    };

    if (saveTo) {
      if (saveTo.indexOf("..") !== -1) {
        throw new Error(
          "Path traversal detected: key save path must not contain '..'",
        );
      }
      try {
        var fs = require("fs");
        var path = require("path");
        if (!fs.existsSync(saveTo)) fs.mkdirSync(saveTo, { recursive: true });
        fs.writeFileSync(
          path.join(saveTo, "ecdh-public.pem"),
          result.publicKey,
        );
        fs.writeFileSync(
          path.join(saveTo, "ecdh-private.pem"),
          result.privateKey,
        );
      } catch (e) {
        throw new Error("Failed to save keys to disk: " + e.message);
      }
    }

    return result;
  }

  function ecdhEncrypt(payload, publicKey, aad) {
    var ephemKeyPair = crypto.generateKeyPairSync("ec", {
      namedCurve: "P-256",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    var recipientKey = crypto.createPublicKey(publicKey);

    var sharedSecret = crypto.diffieHellman({
      privateKey: crypto.createPrivateKey(ephemKeyPair.privateKey),
      publicKey: recipientKey,
    });

    var aesKey = deriveAESKey(sharedSecret);

    var iv = crypto.randomBytes(12);
    var jsonStr = JSON.stringify(payload);
    var compressed = zlib.gzipSync(Buffer.from(jsonStr, "utf8"));

    var cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv, {
      authTagLength: 16,
    });
    if (aad) {
      cipher.setAAD(
        Buffer.from(typeof aad === "string" ? aad : aad, "utf8"),
      );
    }
    var encrypted = Buffer.concat([cipher.update(compressed), cipher.final()]);
    var tag = cipher.getAuthTag();

    var ephemPubDer = crypto
      .createPublicKey(ephemKeyPair.publicKey)
      .export({ type: "spki", format: "der" });

    var output = {
      epk: ephemPubDer.toString("base64"),
      iv: iv.toString("base64"),
      t: tag.toString("base64"),
      d: encrypted.toString("base64"),
    };

    if (aad) {
      output.aad = Buffer.from(
        typeof aad === "string" ? aad : aad,
        "utf8",
      ).toString("base64");
    }

    return output;
  }

  function ecdhDecrypt(encryptedPayload, privateKey) {
    var ephemPubKey = crypto.createPublicKey({
      key: Buffer.from(encryptedPayload.epk, "base64"),
      type: "spki",
      format: "der",
    });

    var privKey = crypto.createPrivateKey(privateKey);

    var sharedSecret = crypto.diffieHellman({
      privateKey: privKey,
      publicKey: ephemPubKey,
    });

    var aesKey = deriveAESKey(sharedSecret);

    var iv = Buffer.from(encryptedPayload.iv, "base64");
    var tag = Buffer.from(encryptedPayload.t, "base64");
    var encrypted = Buffer.from(encryptedPayload.d, "base64");

    var decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv, {
      authTagLength: 16,
    });
    decipher.setAuthTag(tag);
    if (encryptedPayload.aad) {
      decipher.setAAD(Buffer.from(encryptedPayload.aad, "base64"));
    }

    var decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);
    var decompressed = zlib.gunzipSync(decrypted, {
      maxOutputLength: MAX_DECOMPRESSED_SIZE,
    });
    return JSON.parse(decompressed.toString("utf8"));
  }

  function encrypt(payload, publicKey, aad) {
    if (crypto) {
      try {
        var keyObj = crypto.createPublicKey(publicKey);
        if (keyObj.asymmetricKeyType === "ec") {
          return ecdhEncrypt(payload, publicKey, aad);
        }
      } catch (e) {}
    }

    var aesKey = generateAESKey();
    var iv = generateIV();

    var result = encryptAES(payload, aesKey, iv, aad);
    var encryptedKey = encryptRSA(aesKey, publicKey);

    var output = {
      encryptedAESKey: forge.util.encode64(encryptedKey),
      delta: forge.util.encode64(iv),
      tag: forge.util.encode64(result.tag),
      encryptedData: forge.util.encode64(result.data),
    };

    if (aad) {
      output.aad = forge.util.encode64(
        typeof aad === "string" ? aad : aad.getBytes(),
      );
    }

    return output;
  }

  function decrypt(encryptedPayload, privateKey) {
    if (encryptedPayload && encryptedPayload.epk) {
      return ecdhDecrypt(encryptedPayload, privateKey);
    }

    var encryptedAESKey = encryptedPayload.encryptedAESKey;
    var delta = encryptedPayload.delta;
    var tag = encryptedPayload.tag;
    var encryptedData = encryptedPayload.encryptedData;

    if (typeof tag !== "string" || tag.length === 0) {
      throw new Error("Invalid payload: missing authentication tag ('tag')");
    }

    var aesKey = decryptRSA(forge.util.decode64(encryptedAESKey), privateKey);
    var iv = forge.util.decode64(delta);
    var tagBytes = forge.util.decode64(tag);
    var aad = encryptedPayload.aad
      ? forge.util.decode64(encryptedPayload.aad)
      : null;
    var data = decryptAES(
      forge.util.decode64(encryptedData),
      aesKey,
      iv,
      tagBytes,
      aad,
    );

    return data;
  }

  function isEncrypted(obj) {
    return (
      obj &&
      typeof obj === "object" &&
      ((typeof obj.encryptedAESKey === "string" &&
        typeof obj.delta === "string" &&
        typeof obj.tag === "string" &&
        typeof obj.encryptedData === "string") ||
        (typeof obj.epk === "string" &&
          typeof obj.iv === "string" &&
          typeof obj.t === "string" &&
          typeof obj.d === "string"))
    );
  }

  return {
    encrypt: encrypt,
    decrypt: decrypt,
    generateKeyPair: generateKeyPair,
    generateECDHKeyPair: generateECDHKeyPair,
    generateAESKey: generateAESKey,
    generateIV: generateIV,
    isEncrypted: isEncrypted,
    ALGORITHM: ALGORITHM,
    KEY_SIZE: KEY_SIZE,
    IV_SIZE: IV_SIZE,
  };
});
