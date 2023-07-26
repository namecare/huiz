#!/bin/bash

# Check if an argument is provided, otherwise set the default build type to "release"
if [ -z "$1" ]; then
  build_type="release"
  cargo_build_type="--release"
else
  # Convert the argument to lowercase to make it case-insensitive
  build_type=$(echo "$1" | tr '[:upper:]' '[:lower:]')

  # Check if the provided argument is either "release" or "debug"
  if [ "$build_type" != "release" ] && [ "$build_type" != "debug" ]; then
    echo "Invalid build type! Please provide 'release' or 'debug' as the argument."
    exit 1
  fi

  if [ "$build_type" == "release" ]; then
    cargo_build_type="--release"
  else
    cargo_build_type=""
  fi
fi

echo "Building xcframework for Namecare SDK"
pwd

compare_version() {
    if [[ $1 == $2 ]]; then
        return 1
    fi
    local IFS=.
    local i a=(${1%%[^0-9.]*}) b=(${2%%[^0-9.]*})
    local arem=${1#${1%%[^0-9.]*}} brem=${2#${2%%[^0-9.]*}}
    for ((i=0; i<${#a[@]} || i<${#b[@]}; i++)); do
        if ((10#${a[i]:-0} < 10#${b[i]:-0})); then
            return 1
        elif ((10#${a[i]:-0} > 10#${b[i]:-0})); then
            return 0
        fi
    done
    if [ "$arem" '<' "$brem" ]; then
        return 1
    elif [ "$arem" '>' "$brem" ]; then
        return 0
    fi
    return 1
}

NAME="huiz"
PROJECT_NAME="${NAME}_ffi"
FFI_DIR=.
FFI_CONFIG="${FFI_DIR}/uniffi.toml"
LIB_NAME="lib${PROJECT_NAME}"
SWIFT_MODULE_NAME="Huiz"
TARGET_OUT="../target"
REQUIRED_VERSION=1.70.0
CURRENT_VERSION=$(rustc -V | awk '{sub(/-.*/,"");print $2}')

echo "Set up stack"

echo "rustc -V: current ${CURRENT_VERSION} vs. required ${REQUIRED_VERSION}"
if compare_version "${REQUIRED_VERSION}" "${CURRENT_VERSION}"; then
  echo "ERROR: rustc version ${CURRENT_VERSION} not supported, please upgrade to at least ${REQUIRED_VERSION}"
  exit 1
fi

echo "Cleaning up..."
rm -rf out

rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-ios
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim

echo "Building huiz"

pushd ${FFI_DIR} || exit 1

#cargo build --target=x86_64-apple-darwin $build_type
cargo build --target=aarch64-apple-darwin $cargo_build_type
cargo build --target=x86_64-apple-ios $cargo_build_type
cargo build --target=aarch64-apple-ios $cargo_build_type
cargo build --target=aarch64-apple-ios-sim $cargo_build_type

popd

echo "Lipo..."
mkdir -p out/framework
mkdir -p out/include
mkdir -p out/lib/ios
mkdir -p out/lib/ios-simulator
mkdir -p out/lib/macos

#lipo -create "../../target/x86_64-apple-darwin/$build_type/${LIB_NAME}.dylib" \
#  "../../target/aarch64-apple-darwin/$build_type/${LIB_NAME}.dylib" \
#  -output out/lib/macos/${LIB_NAME}.dylib

lipo -create "${TARGET_OUT}/x86_64-apple-ios/$build_type/${LIB_NAME}.a" \
    "${TARGET_OUT}/aarch64-apple-ios-sim/$build_type/${LIB_NAME}.a" \
    -output out/lib/ios-simulator/${LIB_NAME}.a

cp -r -p "${TARGET_OUT}/aarch64-apple-ios/$build_type/${LIB_NAME}.a" out/lib/ios/${LIB_NAME}.a

echo "Uniffi-bindgen"

cargo run --bin uniffi-bindgen generate --library "${TARGET_OUT}/aarch64-apple-ios/$build_type/${LIB_NAME}.a" --language swift --out-dir out

mv out/${SWIFT_MODULE_NAME}FFI.h out/include/${SWIFT_MODULE_NAME}FFI.h
#mv out/${SWIFT_MODULE_NAME}FFI.modulemap out/include/module.modulemap

echo "Creating xcframework"

xcodebuild -create-xcframework \
	-library out/lib/ios/${LIB_NAME}.a -headers out/include \
	-library out/lib/ios-simulator/${LIB_NAME}.a -headers out/include \
	-output out/framework/${SWIFT_MODULE_NAME}.xcframework

echo "Done with ffi"