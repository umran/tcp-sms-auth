function Store() {
  this._store = new Array()
}

Store.prototype.persist = function(value) {
  var key = value.signPubKey
  this._store[key] = value
}

module.exports = Store
