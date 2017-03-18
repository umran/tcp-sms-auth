# tcp-sms-auth
A simple mobile device authentication scheme over ip and sms

### Usage and  code example

The following example is a test script ('tests/protocol.js') and demonstrates the steps involved in the authentication process. Although the client and server identity keys in this example are created on the fly, in an actual implementation these are supposed to be long-lived, that is to say that they must be preserved for as long as the server and client are to remain authenticated. Furthermore, the cache and storage classes included in this example are mere placeholders. In a potential implementation please make sure the storage and cache classes have the methods defined in this example.

```js

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
var responseObject = client.respond(challengeObject.http, challengeObject.sms.challenge)

// server terminates the protocol upon response
var terminationObject = server.terminate(responseObject)

// log all messages
console.log(initiateObject)
console.log(challengeObject)
console.log(responseObject)
console.log(terminationObject)

```
