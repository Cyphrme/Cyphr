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

- The key file is created with mode `0600`, inside a directory with mode
  `0700`. A missing directory is created that way.
- Writes are atomic: the new contents go to a temp file in the same
  directory, are flushed to disk, renamed over the key file, and the
  directory is flushed. A crash leaves the old file or the new one, never a
  torn one.
- An existing key file or directory with looser permissions is tightened on
  use (group and other bits removed), and the CLI says so on stderr:
  `tightened permissions on <path>: 0644 -> 0600`. A stricter mode such as
  `0400` is left as it is.
- When `--keystore` is a bare file name, its directory is your working
  directory and is left alone; only the file is tightened. Put the key file
  in a directory of its own.

These steps apply on Unix. They do not defend against root, a backup that
copies the file, or malware running as you.
