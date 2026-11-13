# Key storage

Where the `cyphr` CLI keeps your private keys, and what protects them today.

## Keys are unencrypted at rest

The CLI stores private keys as plain bytes in a JSON file (`--keystore`,
default `./cyphr-keys.json`). **Nothing encrypts that file.** Anyone who can
read it can sign as you. Encryption at rest is waiting on Coz encryption,
which will be built on the Coz#41 draft; until it lands, the file's
permissions are the only protection.

Custody cannot be recorded either: nothing in a key's entry says how it is
held, and nothing can attest it. `cyphr key list` therefore labels every key
`software-held, unencrypted`, in table and JSON output (`custody` field).

## What the CLI does to protect the file

- The key file is created with mode `0600`. A missing directory is created
  with mode `0700`, on the first write; reading never creates anything.
- Writes are atomic: the new contents go to a temp file in the same
  directory, are flushed to disk, renamed over the key file, and the
  directory is flushed. A crash leaves the old file or the new one, never a
  torn one.
- An existing key file with looser permissions is tightened on use (group
  and other bits removed), and the CLI says so on stderr:
  `tightened permissions on <path>: 0644 -> 0600`. A stricter mode such as
  `0400` is kept, including across writes.
- An existing directory is never changed, because it may be your working
  directory (the default key file is `./cyphr-keys.json`) or a shared one
  such as `/tmp`. If group or others can reach it, the CLI warns on stderr
  with its path. Put the key file in a directory of its own.

These steps apply on Unix only; other platforms have no permission
handling at all. They do not defend against root, a backup that
copies the file, or malware running as you.
