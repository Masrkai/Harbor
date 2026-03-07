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
}
