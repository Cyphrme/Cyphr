

# Enforce immutable principal data structures at the protocol level
Brainstorming:

1. Principal flag at genesis: "flags": {"st": "MALT"}
2. Rule:
```
{
  "resource": "ST",
  "mode": "MALT",
  "enforced": true,
  "violation_action": "reject"
}
```
3. Label the hashing alg as immutable.  Kinda weird.
`SHA-256-MALT`

Also consider protocol enforcement of level 1 and 2
