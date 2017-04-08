module.exports.initiate = function(initiateObject) {
  // check for existence of required parameters
  if (typeof initiateObject.signPubKey === "undefined" || typeof initiateObject.number === "undefined") {
    return false
  }

  // check for proper encoding and length of parameters
  
}
