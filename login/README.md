## Bearer Authentication with Coz

In addition to being Coz is well-suited for building stateless, cryptographically verifiable bearer
authentication systems.

A typical bearer login flow looks like this:

0. (Optional) Server includes a signed challenge in the initial in response to client.
1. Client creates and signs a Coz login request.
2. Server verifies the signature. On success, server signs a bearer token, and
   presents it to the client.  The bearer token is another Coz signed by the
   server, containing the authenticated identity, session claims, and any other
   relevant client data
3. Client presents this bearer Coz on subsequent requests (via secure cookies or
   other HTTP headers).
4. To sign out, the client deletes the bearer token.

`typ`s that we recommend:

`cyphr.me/user/login/challenge/create` // (Optional) server challenge.
`cyphr.me/user/login/request/create`   // User login request.
`cyphr.me/user/login/bearer/create`    // Server response.  This is the bearer token.
`cyphr.me/user/login/bearer/delete`    // User deletes the bearer token.

Typically with CRUD.  Both the server and the user must have permissions to
delete the bearer.  To sign all users out, the server rotates valid keys. 

We recommend enforcing replay protection using a narrow window of acceptance for
`now`, meaning that a challenge system is typically overkill for simple
authentication.  What is gained by a challenge?  It ensures that the client is
currently in possession of the key and that a transaction wasn't signed in the
past that's being replayed now.  As long as a new challenge is presented on
request, the server can be confident that for the current session the client has
access to the private key.  A server already expects a client to manage their
own key security, making the complexity of a challenge largely unnecessary. TLS
plus tight timestamp checks suffice for almost all use cases, but an example is
included here for completeness.  Coz also recommends that services have at
minimum and interface for revoked keys.  If a user key is compromised, but a
revoke was issues to the server, future login requests must be invalid for new
requests, limiting the impact of replay attacks.


Example 1: user login request.  In this example there's no challenge :
```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/user/login/request"
  },
  "sig": "..." //TODO valid sig
}
```


Example 2: first time login with embedded key and server challenge.  To
ensure that the server sill has the original challenge, the challenge that the
server signed is replayed with the client's request.

```json5
{
  "pay":{
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/user/login/request",
    "challenge":"0KE9JjOz7YdkPTavixp5mGFubCYCLJEYRCOQrtzhmiw"
  },
	"sig": "...", //TODO valid sig
  "key":{
    "alg":"ES256",
    "now":1623132000,
    "pub":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
    "tag":"Zami's Majuscule Key.",
    "tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
  },
  "challenge":{
    "pay":{
      "alg": "ES256",
      "now": 1623132000,
      "tmb": "<server-key-tmb>",
      "typ": "cyphr.me/user/login/challenge/create",
      "nonce":"7TpCh6fd1WkuWJpbhckGMcVRi9naAnoXh78KvTUoeMU"
    },
    "sig":"" // TODO valid sig
  }
}
```

In both cases, the server issues a signed bearer token to the client, which is
transferred back to the server on every request. 


```json5
{
  "pay":{
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "T0jUB_Bk4pzgvnNWMGfmV0pK4Gu63g_M08pu8HIUGkA", // The server's key
    "typ": "cyphr.me/user/login/bearer/create",
		// Example other fields like user permissions, account information, etc.
		"user_name":"User0",
		"user_role":"admin",
		"user_id":"1234567890"
  },
	"sig": "...", //TODO valid sig
}
```


#### Advantages of Signed Bearer Tokens over Traditional Session Authentication with Coz
Signed bearer tokens issued by the server offer major benefits over traditional
session authentication, which uses an entropic token given to the client and
stored in a database. On each client request the server must query the database
to verify the token along with other information like user permissions.

In contrast, by using Coz, the server verifies each request by checking the
cryptographic signature against its own trusted key, with no need to query a
database, cache, or centralized session store. All identity, permissions, or
other claims exist directly in the signed payload. This stateless design
delivers fast authorization, easy horizontal scaling, and eliminates bottlenecks
from per-request lookups. It also shrinks the attack surface by removing session
stores that could be targeted, while revocation remains clean through key
rotation or explicit key-revocation lists when required. Coz signed bearer
tokens provide the speed and simplicity of stateless bearer authentication.




# Test Keys
// User Key 0:
```json5
{
	"tag": "User Key 0",
  "alg":"ES256",
  "now":1623132000,
  "tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
  "pub":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  "prv":"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA"
}
```

// User Key 1:
```json5
{
  "alg": "ES256",
  "now":1623132000,
  "tag": "User Key 1",
  "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
  "prv": "dRlV0LjnJOVfK_hNl_6rjVKutZWTHNL-Vs4_dVZ0bls",
  "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M"
}
```

// Server Key:
```json5
{
	"tag": "Cyphrpass Server Key A",
  "alg":"ES256",
  "now":1623132000,
  "tmb":"T0jUB_Bk4pzgvnNWMGfmV0pK4Gu63g_M08pu8HIUGkA",
  "pub":"yfZ-PY4QdhWKJ0o41yc8-X9qnahpfKoTN6sr0zd68lMFNbAzOwj9LSVdRngno4Bs_CNyDJCQJ6uqq9Q65cjn-A",
  "prv":"WG-hEn8De4fJJ3FxWAsOAADDp89XigiRajUCI9MFWSo"
}
```

