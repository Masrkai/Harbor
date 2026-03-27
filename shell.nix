# shell.nix
{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    llvmPackages_21.llvm   # match the version rustc uses

    cargo
    cargo-watch
    cargo-nextest
    cargo-llvm-cov
  ];

  LLVM_COV      = "${pkgs.llvmPackages_21.llvm}/bin/llvm-cov";
  LLVM_PROFDATA = "${pkgs.llvmPackages_21.llvm}/bin/llvm-profdata";

  shellHook = ''
    alias build='cargo build --release'
    alias test='cargo llvm-cov nextest --ignore-filename-regex="rustc-" --html'
    alias review='[ -f target/llvm-cov/html/index.html ] && xdg-open target/llvm-cov/html/index.html || { echo "No report found, run test first"; }'

    alias package-test-remote='nix-build -E "with import <nixpkgs> {}; callPackage ./default.nix {}"'
    alias package-test-local='nix-build -E "with import <nixpkgs> {}; callPackage ./default-local.nix {}"'
  '';
}
