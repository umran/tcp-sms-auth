var primitives = require('../crypto_primitives')
var Cache = require('../cache')
var Store = require('../store')
var Protocol = require('../protocol')

var clientIdKeys = primitives.genSigningKeys()
var serverIdKeys = primitives.genSigningKeys()

var serverCache = new Cache()
var serverStore = new Store()

var client = new Protocol(clientIdKeys)
var server = new Protocol(serverIdKeys, serverCache, serverStore)

// client initiates the protocol
var initiateObject = client.initiate('7774272')

// server responds with a challenge
var challengeObject = server.challenge(initiateObject)

// client calls back with a response
var responseObject = client.respond(challengeObject.http, challengeObject.http.nonce)

// server terminates the protocol upon response
var terminationObject = server.terminate(responseObject)

// log all messages
console.log(initiateObject)
console.log(challengeObject)
console.log(responseObject)
console.log(terminationObject)
