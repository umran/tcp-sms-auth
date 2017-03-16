var primitives = require('./crypto_primitives')
var operations = require('./crypto_operations')

function ProtocolServer(idKeys, cache, store) {
  this._idKeys = idKeys
  this._encKeys = primitives.genEncryptionKeys()
  this._cache = cache
  this._store = store
}

// server method
ProtocolServer.prototype.challenge = function(initiateObject) {
  var self = this

  var signPubKey = initiateObject.signPubKey
  var signedEncPubKey = initiateObject.signedEncPubKey
  var number = initiateObject.number

  var isVerifiedEncPubKey = operations.verifyPubKey(signedEncPubKey, primitives.hexToByteArray(signPubKey))
  if(!isVerifiedEncPubKey) {
    return {
      error: 'Signature verification failure'
    }
  }

  // calculate secret shared key
  var secretKey = primitives.calcEncryptionSecret(primitives.hexToByteArray(signedEncPubKey.pubKey), self._encKeys.secretKey)

  // generate challenge
  var nonce = primitives.genNonce(16)
  var nonceHash = primitives.hash(nonce)

  // encrypt challenge
  var encNonceHash = operations.encryptMessage(nonceHash, secretKey)

  // sign responder's encryption public key
  var localSignedEncPubKey = operations.signPubKey(self._encKeys.publicKey, self._idKeys.secretKey)

  var message = {
    sms: {
      number: number,
      challenge: primitives.byteArrayToHex(nonce)
    },
    http: {
      signPubKey: primitives.byteArrayToHex(self._idKeys.publicKey),
      signedEncPubKey: localSignedEncPubKey,
      challenge: encNonceHash,

      // warning! the actual nonce MUST NOT be included during production.
      nonce: primitives.byteArrayToHex(nonce)
    }
  }

  var cache = {
    registrationId: primitives.byteArrayToHex(nonceHash),
    signPubKey: signPubKey,
    number: number
  }

  self._cache.set(cache)

  return message
}

// server method
ProtocolServer.prototype.terminate = function(responseObject) {
  var self = this

  var signPubKey = responseObject.signPubKey
  var signedEncPubKey = responseObject.signedEncPubKey
  var encResponse = responseObject.response

  // lookup signPublicKey from storage
  var clientRecord = self._cache.lookup(signPubKey)

  if(!clientRecord) {
    return {
      error: 'Identity key lookup failure'
    }
  }

  var isVerifiedEncPubKey = operations.verifyPubKey(signedEncPubKey, primitives.hexToByteArray(signPubKey))
  if(!isVerifiedEncPubKey) {
    return {
      error: 'Signature verification failure'
    }
  }

  // calculate secret shared key
  var secretKey = primitives.calcEncryptionSecret(primitives.hexToByteArray(signedEncPubKey.pubKey), self._encKeys.secretKey)
  var response = operations.decryptMessage(encResponse, secretKey)

  var responseHash = primitives.hash(response)
  var challengeHash = primitives.hexToByteArray(clientRecord.registrationId)

  var isVerifiedChallenge = primitives.verify(challengeHash, responseHash)

  if(!isVerifiedChallenge) {
    return {
      error: 'Authentication failure'
    }
  }

  self._store.persist(clientRecord)

  return {
    success: "client was registered successfully"
  }
}

module.exports = ProtocolServer
