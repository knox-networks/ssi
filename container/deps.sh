#!/usr/bin/env bash

set -o pipefail

# This script is meant to be used
# when running a container image to fetch dependencies
# such as CI or in a Dockerfile,
# THUS an x86_64 linux platrom is assumed
USAGE='
USAGE:
  '$0' <DEPS>... [--force] [--no-symlink]

DEPS:
  cachepot
  cargo-make
  cargo-nextest
  cross
  flatc
  grpc_health_probe
  protoc
  sccache

FLAGS:
  --force    skip checking for dependency
'

case "$1" in
--help | -h)
  echo "$USAGE"
  exit 0
  ;;
esac

# Check if a `cli-command` exists within `$PATH`
# emit exit code
exists() {
  local command="$1"
  local which_err_code=0

  # if we pass in --no-symlink
  # check for the explicit filepath
  # rather than what is found in $PATH
  if [[ "$NO_SYMLINK" == "true" ]]; then
    case "$command" in
    # anything starting with cargo- is a cargo subcommand
    # thus has to lie in ~/.cargo/bin
    # TODO for these commands
    # symlink from ~/.local/bin/$command -> ~/.cargo/bin/$command
    # to reduce these checks
    cargo-*) command="$HOME/.cargo/bin/$command" ;;
    *) command="$HOME/.local/bin/$command" ;;
    esac
  fi

  command -v "$command" 1> /dev/null || which_err_code=$?

  if [[ "$which_err_code" == 0 ]]; then
    # call the error function
    echo "$command found in \$PATH"
  fi

  return $which_err_code
}

# prepend with underscore to avoid accidentally triggering a function
# the snippet below would attempt to trigger a function named flatc:
# $(exists flatc)
install() {
  echo "installing $1..."
  "_$1"
}

# try_ln is mainly used for github actions where
# a partially restored cache may require sudo permissions
# to symlink into /usr/local/bin
try_ln() {
  if [[ "$NO_SYMLINK" == "true" ]]; then
    return 0
  fi

  ln -s "$1" "$2" || {
    echo "trying: sudo ln -sf $1 $2"
    sudo ln -sf "$1" "$2"
  }
}

_cachepot() {
  local version=${CACHEPOT_VERSION:-a702d14aa}
  local version_name="cachepot-x86_64-unknown-linux-musl"
  wget -qO- \
    "https://github.com/mkatychev/cachepot/releases/download/${version}/${version_name}.tar.gz" |
    tar xz -C "$HOME/.local/bin"
  chmod +x "$HOME/.local/bin/cachepot" &&
    try_ln "$HOME/.local/bin/cachepot" /usr/local/bin/cachepot
}

_cross() {
  local version=${CROSS_VERSION:-0.2.4}
  wget -qO- \
    "https://github.com/cross-rs/cross/releases/download/v${version}/cross-x86_64-unknown-linux-musl.tar.gz" |
    tar xz -C "$HOME/.local/bin/" &&
    chmod +x "$HOME/.local/bin/cross" &&
    try_ln "$HOME/.local/bin/cross" /usr/local/bin/cross
}

_flatc() {
  local version=${FLATC_VERSION:-23.1.21}
  local zip_file="Linux.flatc.binary.clang++-12.zip"
  wget -q "https://github.com/google/flatbuffers/releases/download/v${version}/$zip_file" &&
    unzip -o "$zip_file" -d "$HOME/.local/bin" &&
    chmod +x "$HOME/.local/bin/flatc" &&
    try_ln "$HOME/.local/bin/flatc" /usr/local/bin/flatc
  rm "$zip_file"
}

_protoc() {
  local version=${PROTOC_VERSION:-21.12}
  local zip_file="protoc-${version}-linux-x86_64.zip"
  wget -q "https://github.com/protocolbuffers/protobuf/releases/download/v${version}/protoc-${version}-linux-x86_64.zip" &&
    unzip -o "$zip_file" -d "$HOME/.local" &&
    chmod +x "$HOME/.local/bin/protoc" &&
    try_ln "$HOME/.local/bin/protoc" /usr/local/bin/protoc
  rm "$zip_file"
}

_cargo-make() {
  local version=${CARGO_MAKE_VERSION:-0.35.12}
  local version_name="cargo-make-v${version}-x86_64-unknown-linux-musl"
  local zip_file="$version_name.zip"
  wget -q "https://github.com/sagiegurari/cargo-make/releases/download/${version}/$zip_file" &&
    unzip -po "$zip_file" "$version_name/cargo-make" > "$HOME/.cargo/bin/cargo-make"
  chmod +x "$HOME/.cargo/bin/cargo-make"
  rm "$zip_file"
}

_grpc_health_probe() {
  local version=${GRPC_HEALTH_PROBE_VERSION:-0.4.11}
  wget -qO "$HOME/.local/bin/grpc_health_probe" \
    "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v${version}/grpc_health_probe-linux-amd64" &&
    chmod +x "$HOME/.local/bin/grpc_health_probe" &&
    try_ln "$HOME/.local/bin/grpc_health_probe" /usr/local/bin/grpc_health_probe

}

_cargo-nextest() {
  local version=${NEXTEST_VERSION:-latest}
  wget -qO- https://get.nexte.st/latest/linux |
    tar xz -C "$HOME/.cargo/bin/" &&
    chmod +x "$HOME/.cargo/bin/cargo-nextest"

}

_sccache() {
  local version=${SCCACHE_VERSION:-0.4.0-pre.6}
  local arch="x86_64"
  local version_name="sccache-v${version}-${arch}-unknown-linux-musl"
  wget -qO- \
    "https://github.com/mozilla/sccache/releases/download/v${version}/${version_name}.tar.gz" |
    tar -zxvf - --strip-components 1 -C "$HOME/.local/bin" "$version_name/sccache"
  chmod +x "$HOME/.local/bin/sccache" &&
    try_ln "$HOME/.local/bin/sccache" /usr/local/bin/sccache
}

_bootstrap.sh() {
  wget_script bootstrap.sh
}

_max-pods-calculator.sh() {
  wget_script max-pods-calculator.sh
}

wget_script() {
  local name="$1"
  local url="${DEPS_URL[$name]}"
  # TODO impl **/bin alternative
  # when downloading files meant for an interpreter
  wget -qO "$HOME/.local/bin/$name" "$url" &&
    chmod +x "$HOME/.local/bin/$name"
  # handle symlink?
  # try_ln "$HOME/.local/bin/$name" /usr/local/bin/bootstrap
}

# TODO test ${vesrion} interaction when mutating DEPS_URL map
declare -lA DEPS_URL
DEPS_URL["bootstrap.sh"]="https://raw.githubusercontent.com/awslabs/amazon-eks-ami/master/files/bootstrap.sh"
DEPS_URL["max-pods-calculator.sh"]="https://raw.githubusercontent.com/awslabs/amazon-eks-ami/master/files/max-pods-calculator.sh"

DEPS=()
# Replace as many `pattern` matches as possible with `replacement`:
# ${var//pattern/replacement}
# ----------------------------
# This strips commas from args:
# string "cross, cargo-make, flatc" -> array (cross cargo-make flatc)
for arg in "${@//,/}"; do
  # handle --flags here
  if [[ $arg == [-]* ]]; then
    case "$arg" in
    --force) FORCE="true" ;;
    --no-symlink) NO_SYMLINK="true" ;;
    *) {
      echo "$arg is an invalid flag"
      exit 1
    } ;;
    esac
  else
    # generate an array of dependencies
    DEPS+=("$arg")
  fi
done

# handle a default argument to be passed in GH actions >:(
# https://github.com/actions/runner/issues/924#issuecomment-810666502
[[ "$1" == "" ]] && exit 0
mkdir -p "$HOME/.local/bin"
mkdir -p "$HOME/.cargo/bin"
for dep in "${DEPS[@]}"; do
  if [[ "$FORCE" == "true" ]]; then
    install "$dep"
  else
    exists "$dep" || install "$dep"
  fi

done
