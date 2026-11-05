# Builds cyphr-server from this repository: `nix-build packaging/`.
#
# The nixpkgs pin matches shell.nix so the package and the dev shell share one
# toolchain universe. rustc comes from that nixpkgs (not the nightly in
# rs/rust-toolchain.toml): the server compiles on stable, and release.yml
# builds it on stable too.
#
# Cargo.lock is vendored beside this file because rs/Cargo.lock is
# git-ignored, and buildRustPackage needs a lockfile to fetch a fixed
# dependency set. Refresh it from rs/Cargo.lock when dependencies change.
let
  pkgs = import (builtins.fetchTarball {
    url = "https://github.com/nixos/nixpkgs/archive/fb7944c166a3b630f177938e478f0378e64ce108.tar.gz";
    sha256 = "sha256:1k5rlkipyc4n7jk8nfmzm1rg3i94zmr90k41yplxhnrb3fkk808j";
  }) { };

  # Only the Rust workspace and the license file it references
  # (license-file = "../LICENSE") enter the build, so edits to docs or the
  # corpus do not invalidate the derivation.
  src = pkgs.lib.fileset.toSource {
    root = ../.;
    fileset = pkgs.lib.fileset.unions [
      ../rs
      ../LICENSE
      ./Cargo.lock
    ];
  };
in
pkgs.rustPlatform.buildRustPackage {
  pname = "cyphr-server";
  version = "0.1.0";
  inherit src;

  sourceRoot = "source/rs";
  cargoLock.lockFile = ./Cargo.lock;
  postPatch = "cp ${./Cargo.lock} Cargo.lock";

  cargoBuildFlags = [
    "-p"
    "cyphr-server"
  ];
  # The workspace suite takes minutes and is CI's job; the packaging smoke
  # test (packaging/smoke.sh) is the check that matters for this artifact.
  doCheck = false;

  meta = {
    description = "Cyphr Protocol authority server";
    homepage = "https://cyphr.me";
    mainProgram = "cyphr-server";
  };
}
