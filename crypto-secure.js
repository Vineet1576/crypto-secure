(function (global, factory) {
  typeof exports === "object" && typeof module !== "undefined"
    ? (module.exports = factory())
    : typeof define === "function" && define.amd
      ? define(factory)
      : (global.CryptoSecure = factory());
})(this, function () {
  "use strict";

  var forge;
  if (typeof window !== "undefined" && window.forge) {
    forge = window.forge;
  } else {
    forge = require("node-forge");
  }

  var ALGORITHM = "AES-GCM";
  var KEY_SIZE = 32;
  var IV_SIZE = 12;

  function generateKeyPair(saveTo) {
    var keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    var result = {
      publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
      privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
    };

    if (saveTo) {
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
        typeof aad === "string" ? aad : aad.getBytes()
      );
    }
    cipher.start(opts);
    cipher.update(forge.util.createBuffer(JSON.stringify(data)));
    if (!cipher.finish()) {
      throw new Error("AES-GCM encryption failed");
    }
    var tag = cipher.mode.tag;
    var tagBytes = tag.bytes ? tag.bytes() : tag;
    if (!tagBytes || tagBytes.length !== 16) {
      throw new Error(
        "AES-GCM encryption failed to produce a valid authentication tag"
      );
    }
    return {
      data: cipher.output.getBytes(),
      tag: tagBytes,
    };
  }

  function decryptAES(encryptedData, key, iv, tag, aad) {
    var decipher = forge.cipher.createDecipher(ALGORITHM, key);
    var opts = { iv: iv, tag: tag };
    if (aad) {
      opts.additionalData = forge.util.createBuffer(
        typeof aad === "string" ? aad : aad.getBytes()
      );
    }
    decipher.start(opts);
    decipher.update(forge.util.createBuffer(encryptedData));
    if (!decipher.finish()) {
      throw new Error(
        "Decryption failed: authentication tag mismatch (data may be tampered)"
      );
    }
    return JSON.parse(decipher.output.toString("utf8"));
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

  function encrypt(payload, publicKey, aad) {
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
        typeof aad === "string" ? aad : aad.getBytes()
      );
    }

    return output;
  }

  function decrypt(encryptedPayload, privateKey) {
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
      aad
    );

    return data;
  }

  function isEncrypted(obj) {
    return (
      obj &&
      typeof obj === "object" &&
      typeof obj.encryptedAESKey === "string" &&
      typeof obj.delta === "string" &&
      typeof obj.tag === "string" &&
      typeof obj.encryptedData === "string"
    );
  }

  return {
    encrypt: encrypt,
    decrypt: decrypt,
    generateKeyPair: generateKeyPair,
    generateAESKey: generateAESKey,
    generateIV: generateIV,
    isEncrypted: isEncrypted,
    ALGORITHM: ALGORITHM,
    KEY_SIZE: KEY_SIZE,
    IV_SIZE: IV_SIZE,
  };
});
