var CryptoSecure = require("./crypto-secure");

function CryptoSecureClient(options) {
  if (!options) options = {};
  this.clientKeyPair = options.keyPair || CryptoSecure.generateKeyPair();
  this.serverPublicKey = options.serverPublicKey || null;
}

CryptoSecureClient.prototype.getPublicKey = function () {
  return this.clientKeyPair.publicKey;
};

CryptoSecureClient.prototype.setServerPublicKey = function (key) {
  this.serverPublicKey = key;
};

CryptoSecureClient.prototype.encryptRequest = function (data, aad) {
  if (!this.serverPublicKey) {
    throw new Error(
      "Server public key not set. Call setServerPublicKey() first."
    );
  }
  return CryptoSecure.encrypt(data, this.serverPublicKey, aad);
};

CryptoSecureClient.prototype.decryptResponse = function (encryptedPayload) {
  return CryptoSecure.decrypt(encryptedPayload, this.clientKeyPair.privateKey);
};

CryptoSecureClient.prototype.getHeaders = function () {
  var forge = require("node-forge");
  var pemObj = forge.pem.decode(this.clientKeyPair.publicKey);
  var body = Array.isArray(pemObj) ? pemObj[0].body : pemObj.body;
  var headers = {};
  headers["x-encryption-key"] = forge.util.encode64(body);
  return headers;
};

module.exports = CryptoSecureClient;
