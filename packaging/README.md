# Packaging

Everything an operator needs to build, check and verify `cyphr-server`.

| File                        | Purpose                                                          |
| :-------------------------- | :--------------------------------------------------------------- |
| `default.nix`               | `nix-build packaging/` builds the server from this repository.   |
| `Cargo.lock`                | Dependency pin for the nix build (`rs/Cargo.lock` is ignored).   |
| `cyphr-server.example.toml` | Example config; only options the binary accepts today.           |
| `smoke.sh`                  | Starts a server on an empty data dir, expects a 404 from `/tip`. |

Check a build: `packaging/smoke.sh result/bin/cyphr-server`.

## Verifying a release

Each `rs/v*` release attaches `cyphr-server-<arch>-<os>` archives next to the
CLI archives, a `SHA256SUMS` file covering every archive, and SLSA v1 build
provenance recorded as GitHub artifact attestations (Sigstore keyless).

```sh
gh attestation verify cyphr-server-x86_64-linux.tar.gz --repo Cyphrme/Cyphr
sha256sum --check --ignore-missing SHA256SUMS
```
