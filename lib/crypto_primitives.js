var nacl = require('tweetnacl')

module.exports.genSigningKeys = function() {
  return nacl.sign.keyPair()
}

module.exports.sign = function(message, privateKey ) {
  return nacl.sign.detached(message, privateKey)
}

module.exports.verifySignature = function(message, signature, publicKey) {
  return nacl.sign.detached.verify(message, signature, publicKey)
}

module.exports.genEncryptionKeys = function() {
  return nacl.box.keyPair()
}

module.exports.calcEncryptionSecret = function(theirPublicKey, ourPrivateKey) {
  return nacl.box.before(theirPublicKey, ourPrivateKey)
}

module.exports.encrypt = function(message, nonce, key) {
  return nacl.secretbox(message, nonce, key)
}

module.exports.decrypt = function(ciphertext, nonce, key) {
  return nacl.secretbox.open(ciphertext, nonce, key)
}

module.exports.hash = function(data) {
  return nacl.hash(data)
}

module.exports.verify = function(x, y) {
  return nacl.verify(x, y)
}

module.exports.genNonce = function(length) {
  return nacl.randomBytes(length)
}

module.exports.strToHex = function(string) {
    var hex, i

    var result = ""
    for (i=0; i<string.length; i++) {
        hex = string.charCodeAt(i).toString(16)
        result += ("000"+hex).slice(-4)
    }

    return result
}

module.exports.hexToStr = function(hex) {
    var j
    var hexes = hex.match(/.{1,4}/g) || []
    var back = ""
    for(j = 0; j<hexes.length; j++) {
        back += String.fromCharCode(parseInt(hexes[j], 16))
    }

    return back
}

module.exports.byteArrayToHex = function(uint8arr) {
  if (!uint8arr) {
    return ''
  }

  var hexStr = ''
  for (var i = 0; i < uint8arr.length; i++) {
    var hex = (uint8arr[i] & 0xff).toString(16)
    hex = (hex.length === 1) ? '0' + hex : hex
    hexStr += hex
  }

  return hexStr.toUpperCase()
}

module.exports.hexToByteArray = function(str) {
  if (!str) {
    return new Uint8Array()
  }

  var a = []
  for (var i = 0, len = str.length; i < len; i+=2) {
    a.push(parseInt(str.substr(i,2),16))
  }

  return new Uint8Array(a)
}
