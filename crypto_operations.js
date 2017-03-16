var primitives = require('./crypto_primitives')

// Takes message and key as byte arrays and outputs an object containing hex strings
module.exports.encryptMessage = function(message, key) {

  // generate random nonce for message
  var nonce = primitives.genNonce(24)
  var encMessage = primitives.encrypt(message, nonce, key)

  // convert nonce and ciphertext to hex
  var nonceHex = primitives.byteArrayToHex(nonce)
  var encMessageHex = primitives.byteArrayToHex(encMessage)

  // return object containing nonce and encrypted message as hex strings
  var encPayload = {
    nonce: nonceHex,
    encMessage: encMessageHex
  }

  return encPayload
}

// Expects encPayload to be an object containing hex strings, key to be a byte array and outputs message as a byte array
module.exports.decryptMessage = function(encPayload, key) {
  var nonceHex = encPayload.nonce
  var encMessageHex = encPayload.encMessage

  var nonce = primitives.hexToByteArray(nonceHex)
  var encMessage = primitives.hexToByteArray(encMessageHex)

  var message = primitives.decrypt(encMessage, nonce, key)

  return message
}

// Takes pubKey and key as byte arrays, outputs object containing hex strings
module.exports.signPubKey = function(pubKey, key) {
  var signature = primitives.sign(pubKey, key)

  var signatureHex = primitives.byteArrayToHex(signature)
  var pubKeyHex = primitives.byteArrayToHex(pubKey)

  // signed objects are bundled as message-signature pairs
  return {
      signature: signatureHex,
      pubKey: pubKeyHex
  }
}

module.exports.verifyPubKey = function(signedPubKey, key) {
  var signatureHex = signedPubKey.signature
  var pubKeyHex = signedPubKey.pubKey

  var signature = primitives.hexToByteArray(signatureHex)
  var pubKey = primitives.hexToByteArray(pubKeyHex)

  return primitives.verifySignature(pubKey, signature, key)
}

module.exports.hashNonce = function(nonce) {
  return primitives.byteArrayToHex(primitives.hash(primitives.hexToByteArray(nonce)))
}
