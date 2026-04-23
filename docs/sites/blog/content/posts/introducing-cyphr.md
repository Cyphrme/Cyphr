+++
title       = "Introducing Cyphr"
description = "Authentication for the Internet"
date        = 2026-04-25
authors     = ["Cyphr Contributors"]
tags        = ["protocol", "identity", "release"]
+++

In 1961, MIT built the first computer password. By 1979, its designers had
published a paper documenting why passwords were structurally
broken.[^morris-thompson] We've spent the decades since building
mitigations: salted hashes, Kerberos, SSL certificates, OAuth,
WebAuthn. Every generation shifts _who_ you trust without eliminating
the _need_ to trust. The server. The provider. The certificate authority.
The authenticator vendor.

The pattern is remarkably consistent. Kerberos moved trust from the local
machine to a central Key Distribution Center; compromise the KDC, and every
identity in the realm falls.[^kerberos] The certificate authority system
moved trust to institutions that vouch for websites; in 2011, a single
breached CA issued 531 rogue certificates and enabled the surveillance of
300,000 Iranian Gmail users.[^diginotar] OAuth moved trust to identity
providers; when Google suspended Andrew Spinks' account without explanation
in 2021, he lost fifteen years of email, his YouTube channel, and thousands
of dollars in purchases, with no human to appeal to.[^spinks] WebAuthn
moved trust to hardware vendors and their attestation chains. Passkeys
moved it to cloud sync infrastructure. Each generation solved the previous
generation's failure mode. None eliminated the structural dependency.

Ken Thompson saw the deeper pattern forty years ago. His 1984 Turing
Award lecture proved that a compiler backdoor could be absent from source
code yet present in the binary: you cannot trust software authored by
someone you cannot verify.[^thompson] Thompson's proof was about
compilers, but the corollary extends to any system that depends on
unverifiable authorship. In 2024, a pseudonymous contributor
demonstrated this corollary in the identity domain, spending two years
earning trust in xz-utils to backdoor SSH authentication across every
major Linux distribution.[^xz-utils] The malicious releases were
cryptographically signed. The signatures were technically valid. They
proved only that the person who inserted the backdoor was the same person
who signed the release.[^xz-identity] The identity tools we had caught
nothing.

Every identity system on the internet asks you to delegate the one thing
that shouldn't be delegable: _who you are_. We built Cyphr because your
identity is yours. Not your provider's, not your platform's, not your
government's. Yours.

## What's Been Tried

We aren't the first to see this problem. The history of decentralized
identity is a thirty-year search for the right architecture, and every
attempt has illuminated a constraint that the next attempt inherits.

**PGP and the Web of Trust** got the premise right: identity should be
verified through cryptographic proof, not institutional decree. But PGP
demanded that users understand the difference between public and private
keys, attend key-signing parties, and manage revocation manually. When
Whitten and Tygar tested PGP 5.0 in 1999, the majority of participants
couldn't sign and encrypt a message in ninety minutes.[^johnny] Some
attempted to send their private keys to correspondents, demonstrating
that the mental model was fundamentally misaligned with user
expectations.[^johnny] The Web of Trust decayed under its own social
overhead, its key servers polluted with millions of expired and
compromised keys.[^pgp-dead]

**Blockchain-based identity** (Namecoin, uPort, Microsoft ION) offered a
global source of truth, but it coupled a per-user concern to
global consensus. Updating a key required paying fluctuating network
fees. Block confirmation times made real-time authentication
impractical. A 2015 analysis of Namecoin found 28 actively used domains
out of 120,000 registrations.[^namecoin] uPort deprecated its libraries
in 2021 after years of struggling with Ethereum gas
costs.[^uport] The core insight: identity doesn't require a global
ledger.

**W3C Decentralized Identifiers (DIDs)** standardized the syntax
but not the substance. Within a year, over 100 DID methods were
registered, most non-interoperable.[^did-methods] Google,
Apple, and Mozilla filed formal objections, arguing that standardizing
the format of identifiers without standardizing the protocols to resolve
them was a specification without a product.[^did-objections]

The gap isn't a missing feature. It's a missing _combination_:
hierarchical state, algorithm agnosticism, standard JSON encoding,
level-graduated complexity, and no blockchain dependency. Together, in
one protocol.

## Introducing the Cyphr Protocol

Cyphr is a self-sovereign identity protocol built on cryptographic state
trees. A Cyphr identity, called a **principal**, is not an account on a
server. It is a Merkle tree of cryptographic state whose root hash _is_
the identity. That hash, the **Principal Root** (PR), is the only
identifier you need. It is self-certifying: anyone who has the state tree
can recompute the root and verify that the principal is authentic, with
no server, no provider, no certificate authority in the loop.

If you've built an application on OAuth, you know what this eliminates.
Your authentication stack doesn't depend on Google's uptime. Your users
don't lose access because a provider suspended their account. You don't
rewrite your auth integration because a vendor changed their API terms.
The principal is a mathematical object controlled by its holder. It
doesn't phone home.

The protocol is organized into six **levels** of increasing complexity,
each building on the previous:

| Level | Name               | What It Adds                                                                                                     |
| :---- | :----------------- | :--------------------------------------------------------------------------------------------------------------- |
| **1** | Static Key         | A single key. The key's thumbprint (`tmb`) _is_ the identity, via implicit promotion to PR.[^implicit-promotion] |
| **2** | Key Replacement    | Swap your key without losing your identity.                                                                      |
| **3** | Multi-Key + Commit | Multiple concurrent keys with equal authority. The commit chain begins.                                          |
| **4** | Arbitrary Data     | Introduces the Data Tree. Enables Authenticated Atomic Actions (AAA).                                            |
| **5** | Rules              | Weighted permissions, timelocks, M-of-N signing.                                                                 |
| **6** | Programmable       | VM execution for complex conditional policies.                                                                   |

This graduation is deliberate. A Level 1 principal is a single key pair:
no commits, no tree structure, no overhead. If all you need is a
throwaway identity for a one-time interaction, Level 1 costs you nothing
beyond generating a key. When your requirements grow, the protocol grows
with you. Add a second device at Level 3. Record signed actions at Level 4. Impose organizational signing policies at Level 5. The complexity you
pay for is the complexity you use.

The mental model is familiar to anyone who has used git. A principal's
commit chain is to identity what git's commit history is to code:
append-only, cryptographically chained, independently verifiable. Each
commit bundles one or more signed transactions (key creation, key
revocation, data operations) into an atomic unit with a finality marker.
The commit history _is_ the principal's identity evolution, and like a git
log, it can be audited by anyone who has a copy.

At Level 4 and above, Cyphr enables **Authenticated Atomic Actions**
(AAA). In a traditional system, authentication produces a session, and
the session authorizes subsequent actions on your behalf. A bearer token
acts like a house key: whoever holds it can open the door.[^bearer]

AAA replaces this model entirely. Every discrete action is individually
signed by a specific key, independently verifiable by anyone, and
cryptographically bound to the principal's state tree. No session. No
intermediary. No delegation.

Consider what this means in practice. In a bearer-token system, if your
session token is stolen at 2pm, every action from 2pm to revocation is
indistinguishable from your own. The attacker's actions and yours share
the same credential. With AAA, each action carries its own signature. A
forensic audit can distinguish exactly which actions were authorized by
which key. The stolen credential can't retroactively attribute
authorship, because there is no credential to steal; there are only
individually signed statements.[^aaa-model]

The forensic advantage is real, but it understates what data actions open
up. When every action is signed by a self-sovereign key and bound to a
portable state tree, the data itself becomes independently distributable
and independently verifiable. It isn't trapped in a platform's database.
It isn't contingent on a service's continued existence or goodwill. The
signature travels with the data, and anyone who has the principal's
public state can verify authorship without contacting the original
service, or any service at all.

Consider social media. Today, your posts exist at the pleasure of the
platform that hosts them. The platform can delete your content, suspend
your account, or disappear entirely, and your published record vanishes
with it. A court order, a terms-of-service change, or an acquisition can
erase years of public discourse overnight. With data actions, every post
is a signed statement bound to your principal. The signature provides
non-repudiation: neither you nor anyone else can plausibly deny that the
statement was made. And because the signed action is a self-contained
cryptographic object, it can be mirrored, archived, and verified by
anyone. No single authority can scrub the record, because the record
doesn't live in one place.[^data-actions]

This isn't limited to social media. Medical records signed by the
patient and provider. Legal filings with cryptographic authorship proof.
Scientific data with an auditable chain of custody from instrument to
publication. Anywhere that "who said this, and can you prove it?" matters,
data actions provide an answer that doesn't depend on trusting a
custodian. The common thread is structural: binding data to a
self-sovereign cryptographic identity makes the provenance portable,
verifiable, and resistant to institutional capture.

A genesis message, the first Coz that creates a principal, looks like this:

```json
{
  "pay": {
    "alg": "ES256",
    "tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL5hTN0OU1ygWJdBJak",
    "typ": "cyphr/key/create",
    "now": 1745523600
  },
  "sig": "..."
}
```

At genesis, the thumbprint of the signing key (`tmb`) _is_ the Key Root
(KR), _is_ the Auth Root (AR), _is_ the Principal Root (PR), _is_ the
Principal Genesis (PG). One value. One identity. No ceremony.[^implicit-promotion]

## The Design Decisions: Why Coz, Why MALT

Two dependencies define Cyphr's architectural character. Neither is
incidental.

### Coz: Bit-Perfect JSON Signing

Coz is a cryptographic JSON messaging specification that
provides bit-perfect payload preservation.[^coz] The problem it solves is
subtle but load-bearing: if the bytes of a JSON payload change during
serialization (field reordering, whitespace normalization, Unicode
re-encoding), the signature breaks. Every JSON-based signing system must
solve this, and most solve it by escaping from JSON entirely.

JWS base64url-encodes the raw payload bytes, which preserves them but
forces every consumer to decode before reading the content; the
"human-readable" format is only human-readable after a transformation
step.[^jws] CBOR offers deterministic encoding but introduces a binary
format that no web developer can read in a terminal.[^cbor]

Coz solves the problem differently: it preserves the exact bytes of `pay`
through signing and verification. The JSON stays human-readable. The
signature stays valid. You can `cat` a Coz message, read the payload,
and pipe it to a verifier without a decoding step. Both properties hold
simultaneously, and neither requires leaving JSON.

### MALT: The Commit Tree

MALT (Merkle Append-only Log Tree) is our implementation of the
append-only Merkle tree structure described in RFC 9162
(Certificate Transparency v2.0, §2.1).[^rfc9162] Each commit produces a Transaction Root (TR),
and those roots are appended to a dense, left-filled Merkle tree. Why a
tree instead of a flat log? A flat sequential log
requires $O(n)$ verification: to validate the current state, you
replay every event from genesis. MALT provides $O(\log n)$ inclusion
proofs: you can verify that a specific commit exists in the history
without downloading or replaying the entire chain. For a principal with
thousands of commits, this is the difference between seconds and
milliseconds.

### Algorithm Agnosticism

Every digest in Cyphr is a MultihashDigest: a self-describing,
algorithm-tagged value. The protocol doesn't marry you to Ed25519 or
P-256. This isn't a theoretical hedge. NIST finalized the first
post-quantum signature standard (ML-DSA) in August 2024.[^nist-pq]
Protocols that hardcode a single algorithm today face a rip-and-replace
migration in three to five years. MultihashDigest sidesteps this: when
post-quantum algorithms mature, principals can rotate to new algorithms
without losing their identity or their history. The migration is a
transaction, not a fork.

### No Blockchain

The commit chain is per-principal, not global. There
is no mining, no gas, no consensus overhead for identity operations.
Cyphr uses a witness model for duplicity detection: a principal
designates a set of witnesses who verify that the controller isn't
publishing conflicting state. Witnesses don't need to trust
each other; they independently verify non-duplicity, and any single
honest witness is sufficient to detect equivocation. This scales linearly
with the number of witnesses, not with the total population of the
network.

### Mutual State Synchronization

Traditional authentication is asymmetric in a way that has nothing to do
with cryptography. The service tracks your state: your password hash,
your session, your last login. You track nothing about the service. If
the service's view of your account diverges from reality (a stale
session, a revoked key it hasn't learned about), you have no mechanism to
detect or correct the discrepancy. Recovery is manual, per-service, and
mediated by email: the de facto root of trust for the entire consumer
internet.

Cyphr inverts this through **Mutual State Synchronization** (MSS). In
Cyphr, both parties are principals. A user tracks the service's state;
the service tracks the user's state. Each maintains an independent,
cryptographically verifiable view of the other.[^mss] When a client
mutates its own state (rotating a key, revoking a device), it pushes the
mutation to all registered services. During authentication, the service
verifies the push against the principal's commit chain. If the states
diverge, either party can detect the discrepancy and initiate
reconciliation from a shared trust anchor.

The analogy is double-entry bookkeeping. Instead of a single ledger entry
that one party controls, two entries are cross-checked. The result:
low-latency authentication (pre-synced state eliminates round-trips),
independence from email and certificate authority choke points, and
programmatic recovery without per-service manual intervention. When you
rotate your key, every service you've registered with learns about it.
You don't reset passwords one by one.

MSS also governs how witnesses operate. A witness keeps a copy of an
external principal's state and verifies consistency. An oracle is a
witness with delegated trust: third parties can query an oracle to
resolve a principal's current state without contacting the principal
directly. This enables offline-capable authentication flows where a
service verifies a principal's state against a locally cached trust
anchor, updating asynchronously as new commits arrive.

## Why Now

Three converging pressures make this the right moment for a structural
alternative.

### Supply Chain Identity

The xz-utils backdoor was
not a packaging failure. It was an identity failure: a pseudonymous actor
earned commit access through social engineering, and no existing
tooling could distinguish a legitimate maintainer from an adversary with
a long commit history.[^xz-utils] SolarWinds was signed with the
corporate key. The build system was authentic. The individual developer
was not.[^solarwinds] Codecov exploited CI pipeline trust to exfiltrate
credentials from thousands of repositories.[^codecov] Every layer of
supply chain security (hashes, signatures, authorization) bottoms
out at identity.

Sigstore, the current standard for open-source signing, delegates that
identity to OIDC providers. If Google revokes a developer's account,
their ability to sign software disappears. An attacker who compromises an
OIDC account can immediately leverage Sigstore to sign malicious code
with a "trusted" identity.[^sigstore-critique] The root of trust for the
global software supply chain is, today, the account security model of
three corporations. Identity should be self-certifying, not
federated.

The sibling project [Atom](https://nrd.sh/blog/atom-reforged.html) (under
separate development by one of Cyphr's authors) addresses the
complementary problem of cryptographic source provenance.
Cyphr provides the identity layer that supply chain provenance requires.

### AI and Authorship

When anyone can generate
anything, "who said this?" becomes the critical question. The C2PA
standard certifies the _tool_ (Adobe Photoshop, a Leica camera), not the
_person_.[^c2pa-tool] A valid C2PA manifest proves that an image was
produced by compliant software. It does not prove that a specific human
directed its creation. AAA certifies the person: because each action's
signature binds it to a specific key in a principal's state tree, the
provenance is traceable not to a tool or platform but to a verifiable
identity. In a world of synthetic media, the distinction between
"this tool produced this artifact" and "this person authorized this
action" is the difference between provenance and accountability.

### Centralized Digital Identity

India's Aadhaar
enrolled 1.4 billion people and promptly demonstrated that a centralized
biometric database is a single point of failure for an entire nation's
identity. In 2018, full database access was available for
$8.[^aadhaar] Biometric authentication failures denied vulnerable
populations access to food rations.[^dreze-khera] The EU's eIDAS 2.0
regulation mandates that browsers trust government-issued certificates,
prompting an open letter from over 500 security researchers warning
that Article 45 creates a mechanism for state-conducted
man-in-the-middle attacks.[^eidas] Even Estonia, the most benign example
of government digital identity, had 760,000 national ID cards
compromised by the ROCA vulnerability: a flaw in a single
manufacturer's TPM chip that allowed private key reconstruction from
the public key.[^roca] Self-sovereignty isn't an ideological preference.
It is a structural defense against documented failure modes.

## The Stakes

We are not building Cyphr because decentralized identity is an
interesting research problem. We are building it because the
alternative, the world we are actively constructing, converges on
authoritarianism with mathematical predictability.

Every identity system that depends on a central authority gives that
authority a kill switch. Google can suspend your account and erase
fifteen years of your digital life with no human review. India can enroll
1.4 billion people in a biometric database and sell access for eight
dollars. The EU can mandate that browsers trust government certificates,
and 500 security researchers can sign a letter warning that this enables
state-conducted surveillance, and the regulation passes anyway. These are
not hypotheticals. They happened. They are happening.

The convergence is structural, not conspiratorial. Centralized identity
systems produce centralized power because identity is the root of
authorization. Control identity and you control access: to financial
systems, to communication platforms, to food rations, to the ability to
publish software. The history of the 21st century is a history of
institutions discovering, one by one, that the identity infrastructure
they inherited gives them capabilities they never asked for and cannot
resist using. The capability creates its own demand.

AI accelerates this. Generative systems have decoupled content from
authorship at industrial scale, making "who said this?" the foundational
question of information integrity. The institutions racing to answer that
question are the same ones whose identity infrastructure we just
diagnosed as structurally broken. C2PA certifies the tool, not the
person. Platform verification certifies the account, not the human. Each
proposed solution reinforces the dependency: _trust us to tell you who
is real_. The structural result is a world where the right to be
believed, to have your words attributable to you, verifiably, without
intermediation, is granted by platforms rather than derived from
cryptographic proof.

Self-sovereign identity is not a feature. It is a structural
precondition for any society that intends to remain
free.[^sovereign-source] The tools we have today — passwords, OAuth,
passkeys, platform accounts — are adequate for commerce. They are
catastrophically inadequate for liberty. Cyphr exists because the
difference matters.

## What's Next

This is v0.1.0. The honest accounting: the first twelve sections of the
specification are solid. Levels 1 through 4 are implemented in both Rust
and Go, with shared cross-language test vectors ensuring implementation
parity. The dual-implementation strategy is deliberate: if two
independent codebases, written in different languages by different
authors, produce identical outputs for identical inputs, the protocol is
the specification, not the implementation.

What we've released:

- The [protocol specification](https://docs.cyphr.me) at `docs.cyphr.me`
- The Rust crate: [`cyphr`](https://crates.io/crates/cyphr) on crates.io
- The Go module: [`github.com/Cyphrme/Cyphr`](https://github.com/Cyphrme/Cyphr)
- The source repository: [github.com/Cyphrme/Cyphr](https://github.com/Cyphrme/Cyphr)

What remains is substantial, and we are not going to pretend otherwise.
MSS is specified but not implemented. The witness and oracle models are
designed but untested at scale. Levels 5 and 6 (weighted permissions,
timelocks, programmable policy) are specified in the SPEC but exist only
on paper.

The first concrete integration target is [cyphr.me](https://cyphr.me)
itself. The existing site runs on an ad hoc authentication backend that
predates the protocol; migrating it to use Cyphr directly will be the
first real-world validation of the full authentication flow, from
principal creation through key rotation to authenticated actions against
a live service. That migration is underway.

Beyond that: a CLI tutorial for developer workflows, git commit signing
integration, and the sustained engineering of proving that a
self-sovereign identity protocol can operate at the scale the internet
demands.

We are looking for developers, cryptographers, protocol thinkers, and
integrators who see the same gap we do. Read the spec. Run the tests.
Build something on it. Tell us where the protocol breaks, where the
abstractions leak, where the documentation lies. This is not a finished
product announced from a stage. It is a working system released into the
open because the problem it addresses does not wait for perfection.

We built Cyphr because sixty years of evidence demonstrates that
delegated identity fails — structurally, repeatedly, at every scale from
a single user locked out of Gmail to 1.4 billion citizens enrolled in a
compromised biometric database. The alternative is not theoretical. It is
running, tested, and specified. The question is whether enough people
agree that identity should belong to the person it describes.

Your identity is yours.

## _Footnotes_

[^morris-thompson]: Morris and Thompson, "Password Security: A Case History" (1979). [PDF](https://rist.tech.cornell.edu/6431papers/MorrisThompson1979.pdf). The paper documented that 71% of passwords were six characters or fewer, and 15% were common dictionary words. The structural diagnosis was clear even then: shared secrets are fundamentally broken.

[^thompson]: Ken Thompson, "Reflections on Trusting Trust," Turing Award Lecture (1984). [PDF](https://www.cs.cmu.edu/~rdriley/487/papers/Thompson_1984_ReflectionsonTrustingTrust.pdf). Thompson proved that a backdoor could be absent from source code yet present in the binary, identifying the existential limit of source-code verification.

[^xz-utils]: The xz-utils backdoor (CVE-2024-3094) was discovered by Andres Freund on March 29, 2024, after he noticed a performance regression during timing measurements. The "Jia Tan" persona had been contributing since 2022, using sock-puppet accounts to pressure the original maintainer into sharing commit access. [Wikipedia](https://en.wikipedia.org/wiki/XZ_Utils_backdoor); [Tukaani Project advisory](https://tukaani.org/xz-backdoor/).

[^xz-identity]: The malicious xz-utils releases were signed with GPG keys belonging to Jia Tan. The signatures were cryptographically valid but provided no security value, as the identity was a fabrication with no real-world verification. [InfoQ analysis](https://www.infoq.com/news/2024/04/xz-backdoor/).

[^kerberos]: The Kerberos KDC stores the master keys for every user and service in the realm. Its compromise enables "Golden Ticket" attacks: forged TGTs granting unrestricted impersonation of any identity, indefinitely. [MIT Project Athena](https://web.mit.edu/saltzer/www/publications/athenaplan/e.2.1.pdf); [SailPoint overview](https://www.sailpoint.com/identity-library/kerberos-authentication-protocol).

[^diginotar]: In 2011, the Dutch CA DigiNotar was breached through a publicly-facing web server running outdated software. The attacker issued at least 531 rogue certificates for domains including google.com, yahoo.com, and torproject.org, enabling mass surveillance of Iranian citizens. DigiNotar detected the intrusion on July 19 but failed to revoke certificates or notify browser vendors for weeks. The breach was publicly exposed when an Iranian user posted the fraudulent certificate on Pastebin on August 28. [ENISA report](https://www.enisa.europa.eu/sites/default/files/all_files/Operation_Black_Tulip_v2.pdf); [Fox-IT investigation](https://roselabs.nl/files/audit_reports/Fox-IT_-_DigiNotar.pdf); [Wikipedia](https://en.wikipedia.org/wiki/DigiNotar).

[^spinks]: Andrew Spinks, president of Re-Logic, had his Google account suspended without explanation in January 2021. For three weeks he could not access Gmail (used for 15 years), Google Drive, YouTube, or Google Play purchases. The impact was severe enough that Spinks canceled the planned port of Terraria for Google Stadia, stating "doing business with Google is a liability." [The Register](https://www.theregister.com/2021/02/08/terraria_developer_cancels_stadia_port/); [PCMag](https://www.pcmag.com/news/terraria-for-google-stadia-canceled-and-its-googles-fault).

[^johnny]: Whitten and Tygar, "Why Johnny Can't Encrypt: A Usability Evaluation of PGP 5.0" (1999). [PDF](https://people.eecs.berkeley.edu/~tygar/papers/Why_Johnny_Cant_Encrypt/USENIX.pdf). Participants attempted to send their private keys to correspondents, demonstrating that the PGP mental model was fundamentally misaligned with user expectations.

[^pgp-dead]: Peter Gutmann's analysis documented the structural decay of the Web of Trust: key servers polluted with expired keys, no effective revocation mechanism, and $O(N^2)$ social overhead for mesh construction. See also [Why Johnny Still, Still Can't Encrypt](https://ar5iv.labs.arxiv.org/html/1510.08555).

[^namecoin]: Kalodner et al., "An Empirical Study of Namecoin and Lessons for Decentralized Namespace Design," WEIS 2015. [PDF](https://econinfosec.org/archive/weis2015/papers/WEIS_2015_kalodner.pdf).

[^uport]: uPort's pivot to Serto in 2021 marked the effective deprecation of the original Ethereum-based identity libraries. [Medium announcement](https://serto.medium.com/uport-is-now-serto-df9c73d545e6).

[^did-methods]: The W3C DID Method Registry lists registered methods. The proliferation of incompatible methods was a central concern in the formal objections. [DID Spec Registries](https://www.w3.org/TR/did-spec-registries/).

[^did-objections]: The W3C DID Formal Objections Report (2022) documents objections from Google, Apple, and Mozilla. Mozilla argued that the spec "delegates the actual work to a registry of methods that have no interoperable implementations." [W3C Report](https://www.w3.org/2022/03/did-fo-report.html).

[^implicit-promotion]: Implicit promotion: when a tree component has only one child, its value promotes to the parent without additional hashing. A single `tmb` promotes through KR → AR → PR, so at Level 1, the key thumbprint _is_ the identity. See [SPEC §2.2.7](https://docs.cyphr.me).

[^bearer]: Bearer tokens (JWTs, OAuth access tokens) function as possession credentials: whoever holds the token is authorized. Stolen tokens enable unconstrained impersonation until expiry or revocation. [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750).

[^aaa-model]: In AAA, there is no long-lived session credential. Each action is an independently signed Coz message bound to the principal's state tree. An attacker who intercepts one signed action gains no ability to produce new ones without the private key. This is structurally equivalent to the difference between stealing a signed check (bearer) and forging a signature (asymmetric).

[^data-actions]: Data actions in Cyphr are structurally distinct from authentication transactions. They are stateless signed messages that do not mutate the Auth Tree and are not chained via `pre`. This makes them lightweight for high-volume use cases while preserving full cryptographic authorship proof. The Data Tree's semantics are deliberately application-defined, allowing different deployments to impose their own structure. See [SPEC §4.7](https://docs.cyphr.me).

[^coz]: The Coz specification (v1.0) provides bit-perfect JSON payload preservation for cryptographic signing. [GitHub](https://github.com/Cyphrme/Coz).

[^jws]: JWS (JSON Web Signature, RFC 7515) base64url-encodes the payload to preserve byte fidelity. The signed content is not directly readable without decoding. [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515).

[^cbor]: CBOR (Concise Binary Object Representation, RFC 8949) provides deterministic serialization but produces binary output not human-readable without tooling. [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949).

[^malt]: MALT (Merkle Append-only Log Tree) provides $O(\log n)$ inclusion proofs and deterministic state derivation. [GitHub](https://github.com/Cyphrme/malt).

[^rfc9162]: B. Laurie, E. Messeri, R. Stradling, "Certificate Transparency Version 2.0," RFC 9162 (2021). MALT implements the append-only Merkle tree structure defined in §2.1 with Cyphr-specific extensions for identity state management. [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162).

[^nist-pq]: NIST announced the finalization of ML-DSA (FIPS 204), ML-KEM (FIPS 203), and SLH-DSA (FIPS 205) on August 13, 2024. These are the first standardized post-quantum cryptographic algorithms. [NIST announcement](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards).

[^solarwinds]: The SolarWinds Orion compromise (2020) injected the SUNBURST backdoor during the build process. The resulting artifact was signed with SolarWinds' corporate certificate, making it appear legitimate. The signed artifact was authentic to the build system but not to any individual developer. [MITRE ATT&CK C0024](https://attack.mitre.org/campaigns/C0024/).

[^codecov]: In January 2021, attackers modified Codecov's Bash Uploader script, exfiltrating CI environment variables from thousands of repositories for two months before detection. [Codecov advisory](https://about.codecov.io/security-update/).

[^sigstore-critique]: Sigstore delegates the root of trust to OIDC providers. An attacker who compromises an OIDC account can immediately sign malicious code with a "trusted" identity. The security of the global software supply chain becomes inextricable from the account security models of Google, Microsoft, and GitHub. [Sigstore Security Model](https://docs.sigstore.dev/about/security/).

[^c2pa-tool]: The C2PA specification primarily certifies the claim generator (the software tool), not the human operator. A manifest stating "this was produced by Adobe Photoshop" provides no information about the operator's identity or intent. [C2PA Explainer](https://spec.c2pa.org/specifications/specifications/2.4/explainer/Explainer.html).

[^aadhaar]: Rachna Khaira, The Tribune (January 2018). Anonymous sellers on WhatsApp provided access to the entire Aadhaar database for Rs 500 (~$8), including name, address, photo, and phone number for any Aadhaar number. The UIDAI responded by filing a police report against the journalist. [EFF analysis](https://www.eff.org/deeplinks/2018/02/can-indias-aadhaar-biometric-identity-program-be-fixed).

[^dreze-khera]: Jean Drèze and Reetika Khera documented that Aadhaar-based biometric authentication at ration shops excluded 1.5 to 2 million individuals from food benefits in Jharkhand alone. Manual laborers with worn fingerprints and elderly residents with degraded irises failed authentication routinely. [Ideas for India](https://www.ideasforindia.in/topics/poverty-inequality/balancing-corruption-and-exclusion-a-rejoinder); [OpenEdition Journals](https://journals.openedition.org/samaj/6459).

[^eidas]: In November 2023, over 500 security researchers signed an open letter warning that eIDAS 2.0 Article 45 (forcing browsers to trust government-issued QWACs) creates a mechanism for state-conducted MITM attacks and metadata surveillance. [ORBilu paper](https://orbilu.uni.lu/bitstream/10993/66334/1/Dikshit%20et%20al.%20-%202025%20-%20EU%20Policies%20Meet%20Global%20Practices%20The%20Discourse%20on%20Qualified%20Website%20Authentication%20Certificates%20-%20revision.pdf).

[^roca]: Nemec et al., "The Return of Coppersmith's Attack: Practical Factorization of Widely Used RSA Moduli," ACM CCS 2017. The ROCA vulnerability (CVE-2017-15361) affected 760,000 Estonian national ID cards by enabling private key reconstruction from the public key due to a flawed prime generation method in Infineon TPM chips. [Preprint](https://crocs.fi.muni.cz/_media/public/papers/nemec_roca_ccs17_preprint.pdf); [Wikipedia](https://en.wikipedia.org/wiki/ROCA_vulnerability).

[^mss]: Mutual State Synchronization is specified in [SPEC §13](https://docs.cyphr.me). MSS draws from the same architectural insight as double-entry bookkeeping: independent verification of shared state eliminates single points of failure in state tracking. Both user and service maintain cryptographically verifiable views of each other's principal state.

[^sovereign-source]: The broader structural analysis of why centralized systems converge on authoritarian outcomes, and why self-sovereignty is a precondition rather than a preference, is developed in [Sovereign Source](https://nrd.sh/blog/sovereign-source.html).
