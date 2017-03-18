var primitives = require('./crypto_primitives')
var operations = require('./crypto_operations')

function ProtocolClient(idKeys, cache, store) {
  this._idKeys = idKeys
  this._encKeys = primitives.genEncryptionKeys()
}

ProtocolClient.prototype.initiate = function(number) {
  var self = this

  // sign the encryption public key
  var signedEncPubKey = operations.signPubKey(self._encKeys.publicKey, self._idKeys.secretKey)

  var message = {
    signPubKey: primitives.byteArrayToHex(self._idKeys.publicKey),
    signedEncPubKey: signedEncPubKey,
    number: number
  }

  return message
}

ProtocolClient.prototype.respond = function(challengeObject, response) {
  var self = this

  var signPubKey = challengeObject.signPubKey
  var signedEncPubKey = challengeObject.signedEncPubKey
  var challenge = challengeObject.challenge

  var isVerifiedEncPubKey = operations.verifyPubKey(signedEncPubKey, primitives.hexToByteArray(signPubKey))
  if(!isVerifiedEncPubKey) {
    return {
      error: 'Signature verification failure'
    }
  }

  // calculate secret shared key
  var secretKey = primitives.calcEncryptionSecret(primitives.hexToByteArray(signedEncPubKey.pubKey), self._encKeys.secretKey)

  // generate response hash
  var responseHash = primitives.hash(primitives.hexToByteArray(response))
  var challengeHash = operations.decryptMessage(challenge, secretKey)

  // compare responseHash and challengeHash. If not equal, abort
  var isVerifiedChallenge = primitives.verify(challengeHash, responseHash)
  if(!isVerifiedChallenge) {
    return {
      error: 'Challenge response failure'
    }
  }

  // update ephemeral encryption key pair
  self._encKeys = primitives.genEncryptionKeys()

  // sign ephemeral encryption public key
  var localSignedEncPubKey = operations.signPubKey(self._encKeys.publicKey, self._idKeys.secretKey)

  // calculate secret between new ephemeral encryption private key and other party's ephemeral encryption public key
  var ratchetedSecretKey = primitives.calcEncryptionSecret(primitives.hexToByteArray(signedEncPubKey.pubKey), self._encKeys.secretKey)

  // encrypt response with new secret key
  var encResponse = operations.encryptMessage(primitives.hexToByteArray(response), ratchetedSecretKey)

  // return response object
  var message = {
    signPubKey: primitives.byteArrayToHex(self._idKeys.publicKey),
    signedEncPubKey: localSignedEncPubKey,
    response: encResponse
  }

  return message
}

module.exports = ProtocolClient
