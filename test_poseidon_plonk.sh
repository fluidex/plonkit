#!/bin/bash
set -exu

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TOOL_DIR=$DIR"/contrib"
CIRCUIT_DIR=$DIR"/testdata/poseidon"
SETUP_DIR=$DIR"/keys/setup"
PLONKIT_BIN=$DIR"/target/release/plonkit"
#PLONKIT_BIN="plonkit"
DUMP_LAGRANGE_KEY=false
REQUIRED_PKG1="axel"
REQUIRED_PKG2="npm"


echo "Step0: check for necessary dependencies"
PKG_OK=""
PKG_OK=$(command -v $REQUIRED_PKG1)
echo Checking for $REQUIRED_PKG1
if [ -z "$PKG_OK" ]; then
  echo "$REQUIRED_PKG1 not found. Installing $REQUIRED_PKG1."
  sudo apt-get --yes install $REQUIRED_PKG1
else
  echo $REQUIRED_PKG1 exists at $PKG_OK
fi

PKG_OK=""
PKG_OK=$(command -v $REQUIRED_PKG2)
echo Checking for $REQUIRED_PKG2
if [ -z "$PKG_OK" ]; then
  echo "$REQUIRED_PKG2 not found. Installing $REQUIRED_PKG2."
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.37.2/install.sh | bash
fi

echo "Step1: build plonkit binary"
cargo build --release
#cargo install --git https://github.com/Fluidex/plonkit
#$PLONKIT_BIN --help

echo "Step2: download universal setup file"
# It is the aztec ignition trusted setup key file. Thanks to matter-labs/zksync/infrastructure/zk/src/run/run.ts
pushd keys/setup
axel -ac https://universal-setup.ams3.digitaloceanspaces.com/setup_2^20.key || true
popd

echo "Step3: compile circuit and calculate witness using snarkjs"
. $TOOL_DIR/process_circom_circuit.sh

echo "Step4: export verification key"
$PLONKIT_BIN export-verification-key -m $SETUP_DIR/setup_2^20.key -c $CIRCUIT_DIR/circuit.r1cs -v $CIRCUIT_DIR/vk.bin

echo "Step5: generate verifier smart contract"
$PLONKIT_BIN generate-verifier -v $CIRCUIT_DIR/vk.bin -s $CIRCUIT_DIR/verifier.sol

if [ "$DUMP_LAGRANGE_KEY" = false ]; then
  echo "Step6: prove with key_monomial_form"
  $PLONKIT_BIN prove -m $SETUP_DIR/setup_2^20.key -c $CIRCUIT_DIR/circuit.r1cs -w $CIRCUIT_DIR/witness.wtns -p $CIRCUIT_DIR/proof.bin -j $CIRCUIT_DIR/proof.json -i $CIRCUIT_DIR/public.json
else
  echo "Step6.1: dump key_lagrange_form from key_monomial_form"
  $PLONKIT_BIN dump-lagrange -m $SETUP_DIR/setup_2^20.key -l $SETUP_DIR/setup_2^20_lagrange.key -c $CIRCUIT_DIR/circuit.r1cs
  echo "Step6.2: prove with key_monomial_form & key_lagrange_form"
  $PLONKIT_BIN prove -m $SETUP_DIR/setup_2^20.key -l $SETUP_DIR/setup_2^20_lagrange.key -c $CIRCUIT_DIR/circuit.r1cs -w $CIRCUIT_DIR/witness.wtns -p $CIRCUIT_DIR/proof.bin -j $CIRCUIT_DIR/proof.json -i $CIRCUIT_DIR/public.json
fi

echo "Step7: verify"
$PLONKIT_BIN verify -p $CIRCUIT_DIR/proof.bin -v $CIRCUIT_DIR/vk.bin