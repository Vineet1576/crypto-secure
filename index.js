var CryptoSecure = require("./crypto-secure");
var cryptoSecureMiddleware = require("./middleware");
var CryptoSecureClient = require("./client");

CryptoSecure.middleware = cryptoSecureMiddleware;
CryptoSecure.Client = CryptoSecureClient;

module.exports = CryptoSecure;
