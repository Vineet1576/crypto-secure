var CryptoSecure = require("./crypto-secure");

function createMiddleware(options) {
  if (!options) options = {};

  var privateKey = options.privateKey;
  var publicKeyHeader = options.publicKeyHeader || "x-encryption-key";
  var decryptBody = options.decryptBody !== false;
  var encryptResponse = options.encryptResponse !== false;

  if (!privateKey) {
    throw new Error(
      "CryptoSecure middleware requires a privateKey option. " +
        "Use CryptoSecure.generateKeyPair() to create one."
    );
  }

  return function cryptoSecureMiddleware(req, res, next) {
    if (decryptBody && req.body && CryptoSecure.isEncrypted(req.body)) {
      try {
        req.body = CryptoSecure.decrypt(req.body, privateKey);
      } catch (err) {
        return res.status(400).json({
          error: "Request decryption failed: " + err.message,
        });
      }
    }

    if (encryptResponse) {
      var clientPublicKey = req.headers[publicKeyHeader.toLowerCase()];
      if (clientPublicKey) {
        var lines = [];
        for (var i = 0; i < clientPublicKey.length; i += 64) {
          lines.push(clientPublicKey.substring(i, i + 64));
        }
        clientPublicKey =
          "-----BEGIN PUBLIC KEY-----\r\n" +
          lines.join("\r\n") +
          "\r\n-----END PUBLIC KEY-----";
      }
      var originalJson = res.json.bind(res);

      res.json = function (data) {
        if (clientPublicKey && data !== undefined && data !== null) {
          try {
            var encrypted = CryptoSecure.encrypt(data, clientPublicKey);
            res.set("x-encrypted", "true");
            return originalJson(encrypted);
          } catch (err) {
            console.error(
              "[CryptoSecure] Response encryption failed:",
              err.message
            );
            return res
              .status(500)
              .json({ error: "Response encryption failed" });
          }
        }
        return originalJson(data);
      };
    }

    next();
  };
}

module.exports = createMiddleware;
