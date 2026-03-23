{ lib, fetchFromGitHub, rustPlatform, iproute2, nftables, ... }:

rustPlatform.buildRustPackage {
  pname = "harbor";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner  = "Masrkai";
    repo   = "Harbor";
    rev    = "98248001faca40975f7819b1b308848b15072bba";          # or a specific commit hash / tag e.g. "v0.1.0"
    hash   = "sha256-r9SRB6wYmlQ+7DpeQKKZuKhoKZ4evNU34PwhGv1ChBw=";
    # hash   = lib.fakeHash;    # replace after first failed build
  };

  cargoLock = {
    lockFile = ./Cargo.lock;  # copy your Cargo.lock next to this file
  };

  nativeBuildInputs = [ iproute2 nftables ];


  # Harbor needs raw socket access — these let it find system tools at runtime
  # but the build itself doesn't need them
  meta = with lib; {
    description = "Per-device bandwidth shaping and network traffic management";
    license     = licenses.mit;
    maintainers = [ "Masrkai" ];
    platforms   = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "Harbor";
  };
}
