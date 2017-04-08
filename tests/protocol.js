var primitives = require('../src/crypto_primitives')
var Cache = require('../src/cache')
var Store = require('../src/store')
var ProtocolClient = require('../src/protocol_client')
var ProtocolServer = require('../src/protocol_server')

var clientIdKeys = primitives.genSigningKeys()
var serverIdKeys = primitives.genSigningKeys()

var serverCache = new Cache()
var serverStore = new Store()

var client = new ProtocolClient(clientIdKeys)
var server = new ProtocolServer(serverIdKeys, serverCache, serverStore)

// client initiates the protocol
var initiateObject = client.initiate('7012345')

// server responds with a challenge
var challengeObject = server.challenge(initiateObject)

// client calls back with a response
var responseObject = client.respond(challengeObject.tcp, challengeObject.sms.challenge)

// server terminates the protocol upon response
var terminationObject = server.terminate(responseObject)

// log all messages
console.log(initiateObject)
console.log(challengeObject)
console.log(responseObject)
console.log(terminationObject)
