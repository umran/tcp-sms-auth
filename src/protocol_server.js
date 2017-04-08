var primitives = require('./crypto_primitives')
var operations = require('./crypto_operations')

function ProtocolServer(idKeys, cache, store) {
  this._idKeys = idKeys
  this._cache = cache
  this._store = store
  this._encKeys
  this._signedEncPubKey
  this._secretKey
}

ProtocolServer.prototype.challenge = function(initiateObject) {
  var self = this

  var signPubKey = initiateObject.signPubKey
  var number = initiateObject.number

  // generate nonce
  var nonce = primitives.genNonce(16)
  var nonceNumberPair = primitives.concatArray(nonce, primitives.hexToByteArray(number))

  // calculate hash of the nonceNumberPair
  var nonceNumberPairDigest = primitives.hash(nonceNumberPair)

  // generate server's ephemeral keys
  self._encKeys = primitives.genEncryptionKeys()
  self._signedEncPubKey = operations.signPubKey(self._encKeys.publicKey, self._idKeys.secretKey)

  var message = {
    sms: {
      number: number,
      challenge: primitives.byteArrayToHex(nonce)
    },
    tcp: {
      signPubKey: primitives.byteArrayToHex(self._idKeys.publicKey),
      signedEncPubKey: self._signedEncPubKey
    }
  }

  var cache = {
    signPubKey: signPubKey,
    number: number,
    nonceNumberPairDigest: primitives.byteArrayToHex(nonceNumberPairDigest)
  }

  self._cache.set(cache)

  return message
}

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
  self._secretKey = primitives.calcEncryptionSecret(primitives.hexToByteArray(signedEncPubKey.pubKey), self._encKeys.secretKey)

  // decrypt client response
  var response = operations.decryptMessage(encResponse, self._secretKey)

  // calculate response hash
  var responseDigest = primitives.hash(response)

  var isVerifiedChallenge = primitives.verify(responseDigest, primitives.hexToByteArray(clientRecord.nonceNumberPairDigest))

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
