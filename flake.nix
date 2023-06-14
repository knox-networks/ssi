# === Common commands ===
# $ nix build '.#common'
# $ nix run '.#cli'
# $ nix flake check
{
  description = "SSI flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane = { url = "github:ipetkov/crane"; inputs.nixpkgs.follows = "nixpkgs"; };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # libs
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs) lib;
        craneLib = crane.lib.${system};

        # darwin/macOS conditionals
        macBuildInputs = lib.optionals pkgs.stdenv.isDarwin [
          pkgs.libiconv
          pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
        ];

        src = lib.cleanSourceWith {
          src = ./.; # The original, unfiltered source
          filter = path: type:
            (lib.hasSuffix "\.proto" path) ||
            (lib.hasSuffix "buf\.gen\.yaml" path) ||
            (craneLib.filterCargoSources path type)
          ;
        };

        # dependency caching
        cargoArtifacts = craneLib.buildDepsOnly {
          inherit src;
          pname = "ssi";

          buildInputs = [
            pkgs.protobuf
          ] ++ macBuildInputs;
          doCheck = false;
        };

        # buildLocalPackage allows reuse of inputs and package name
        ssi = craneLib.buildPackage {
          inherit src cargoArtifacts;
          pname = "ssi";

          preBuild = ''
            export HOME=$(mktemp -d)
          '';

          buildInputs = [
            pkgs.protobuf
            pkgs.buf
          ] ++ macBuildInputs;
          doCheck = false;
        };

      in
      {
        # $ nix flake check
        checks = {
          inherit ssi;
        };

        # $ nix build
        # $ nix build '.#ssi'
        packages = {
          default = ssi;
          ssi = ssi;
        };
      });
}


