var primitives = require('./crypto_primitives')
var operations = require('./crypto_operations')

function ProtocolClient(idKeys, cache, store) {
  this._idKeys = idKeys
  this._encKeys
  this._signedEncPubKey
  this._secretKey
  this._number
}

ProtocolClient.prototype.initiate = function(number) {
  var self = this

  self._number = primitives.strToHex(number)

  var message = {
    signPubKey: primitives.byteArrayToHex(self._idKeys.publicKey),
    number: primitives.strToHex(number)
  }

  return message
}

ProtocolClient.prototype.respond = function(challengeObject, response) {
  var self = this

  var signPubKey = challengeObject.signPubKey
  var signedEncPubKey = challengeObject.signedEncPubKey

  var isVerifiedEncPubKey = operations.verifyPubKey(signedEncPubKey, primitives.hexToByteArray(signPubKey))
  if(!isVerifiedEncPubKey) {
    return {
      error: 'Signature verification failure'
    }
  }

  // recreate the nonceNumberPair from nonce received via sms and client phone number
  var nonce = primitives.hexToByteArray(response)
  var nonceNumberPair = primitives.concatArray(nonce, primitives.hexToByteArray(self._number))

  // generate client ephemeral key pair
  self._encKeys = primitives.genEncryptionKeys()
  self._signedEncPubKey = operations.signPubKey(self._encKeys.publicKey, self._idKeys.secretKey)

  // calculate secret shared key
  self._secretKey = primitives.calcEncryptionSecret(primitives.hexToByteArray(signedEncPubKey.pubKey), self._encKeys.secretKey)

  // encrypt response with new secret key
  var encResponse = operations.encryptMessage(nonceNumberPair, self._secretKey)

  // return response object
  var message = {
    signPubKey: primitives.byteArrayToHex(self._idKeys.publicKey),
    signedEncPubKey: self._signedEncPubKey,
    response: encResponse
  }

  return message
}

module.exports = ProtocolClient
