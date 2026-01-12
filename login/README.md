

// Server Key:

```json5
{
  "alg":"ES256",
  "now":1768092490,
  "tmb":"T0jUB_Bk4pzgvnNWMGfmV0pK4Gu63g_M08pu8HIUGkA",
  "pub":"yfZ-PY4QdhWKJ0o41yc8-X9qnahpfKoTN6sr0zd68lMFNbAzOwj9LSVdRngno4Bs_CNyDJCQJ6uqq9Q65cjn-A",
  "prv":"WG-hEn8De4fJJ3FxWAsOAADDp89XigiRajUCI9MFWSo"
}
```









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


Example user login request.  In this example there's no challenge :
```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/user/login/request"
  },
  "sig": "..."
}
```


**Example 2** first time login with embedded key and server challenge.  To
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
    "sig":"" // TODO
  }
}
}
```


// TODO not a valid key.
```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1736434800,
    "tmb": "L0SS81e5QKSUSu-17LTQsvwKpUhBxe6ZZIEnSRV73o8",
    "typ": "cyphr.me/login/challenge/create",
    "nonce": "random-secure-nonce-from-server-b64"
  },
  "sig": "..."
}
```
