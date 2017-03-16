function Cache() {
  this._cache = new Array()
}

Cache.prototype.lookup = function(key) {
  var result = this._cache[key]
  return result
}

Cache.prototype.set = function(value) {
  var key = value.signPubKey
  this._cache[key] = value
}

module.exports = Cache
