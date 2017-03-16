var primitives = require('./crypto_primitives')
var operations = require('./crypto_operations')

function Registration(idKeys, cache, store) {
  this._idKeys = {
    signPubKey: idKeys.publicKey,
    signPrivKey: idKeys.secretKey
  }
  this._encKeys = primitives.genEncryptionKeys()

  if(cache && store) {
    this._cache = cache
    this._store = store
  }
}

// client method
Registration.prototype.initiate = function(number) {
  var self = this

  // sign the encryption public key
  var signedEncPubKey = operations.signPubKey(self._encKeys.publicKey, self._idKeys.signPrivKey)

  var message = {
    signPubKey: primitives.byteArrayToHex(self._idKeys.signPubKey),
    signedEncPubKey: signedEncPubKey,
    number: number
  }

  return message
}

// server method
Registration.prototype.challenge = function(initiateObject) {
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
  var localSignedEncPubKey = operations.signPubKey(self._encKeys.publicKey, self._idKeys.signPrivKey)

  var message = {
    sms: {
      number: number,
      challenge: primitives.byteArrayToHex(nonce)
    },
    http: {
      signPubKey: primitives.byteArrayToHex(self._idKeys.signPubKey),
      signedEncPubKey: localSignedEncPubKey,
      challenge: encNonceHash
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

// client method
Registration.prototype.respond = function(challengeObject, response) {
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
  var localSignedEncPubKey = operations.signPubKey(self._encKeys.publicKey, self._idKeys.signPrivKey)

  // calculate secret between new ephemeral encryption private key and other party's ephemeral encryption public key
  var ratchetedSecretKey = primitives.calcEncryptionSecret(primitives.hexToByteArray(signedEncPubKey.pubKey), self._encKeys.secretKey)

  // encrypt response with new secret key
  var encResponse = operations.encryptMessage(primitives.hexToByteArray(response), ratchetedSecretKey)

  // return response object
  var message = {
    signPubKey: primitives.byteArrayToHex(self._idKeys.signPubKey),
    signedEncPubKey: localSignedEncPubKey,
    response: encResponse
  }

  return message
}

// server method
Registration.prototype.terminate = function(responseObject) {
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

module.exports = Registration
