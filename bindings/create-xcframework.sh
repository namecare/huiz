#!/bin/bash

echo "Building xcframework for huiz lib"
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

PROJECT_NAME="Huiz"
FFI_DIR="ffi"
UDL_PATH=${FFI_DIR}/src/huiz.udl
UNIFFI_CONFIG_PATH=${FFI_DIR}/uniffi.toml

LIB_NAME="libhuiz_ffi"

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

cargo build --target=x86_64-apple-darwin --release
cargo build --target=aarch64-apple-darwin --release
cargo build --target=x86_64-apple-ios --release
cargo build --target=aarch64-apple-ios --release
cargo build --target=aarch64-apple-ios-sim --release

popd

echo "Lipo..."
mkdir -p out/framework
mkdir -p out/include
mkdir -p out/lib/ios
mkdir -p out/lib/ios-simulator
mkdir -p out/lib/macos

lipo -create "../target/x86_64-apple-darwin/release/${LIB_NAME}.a" \
  "../target/aarch64-apple-darwin/release/${LIB_NAME}.a" \
  -output out/lib/macos/${LIB_NAME}.a

lipo -create "../target/x86_64-apple-ios/release/${LIB_NAME}.a" \
    "../target/aarch64-apple-ios-sim/release/${LIB_NAME}.a" \
    -output out/lib/ios-simulator/${LIB_NAME}.a

cp -r -p "../target/aarch64-apple-ios/release/${LIB_NAME}.a" out/lib/ios/${LIB_NAME}.a

echo "Uniffi-bindgen"

cargo run --bin uniffi-bindgen generate ${UDL_PATH} --language swift --config ${UNIFFI_CONFIG_PATH} --out-dir out

mv out/${PROJECT_NAME}FFI.h out/include/${PROJECT_NAME}FFI.h
mv out/${PROJECT_NAME}FFI.modulemap out/include/module.modulemap

echo "Creating xcframework"

xcodebuild -create-xcframework \
	-library out/lib/ios/${LIB_NAME}.a -headers out/include \
	-library out/lib/ios-simulator/${LIB_NAME}.a -headers out/include \
	-output out/framework/${PROJECT_NAME}.xcframework
#
echo "Done with ffi"