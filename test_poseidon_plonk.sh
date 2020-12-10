#!/bin/bash
set -exu

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TOOL_DIR=$DIR"/contrib"
CIRCUIT_DIR=$DIR"/testdata/poseidon"
SETUP_DIR=$DIR"/keys/setup"
PLONKIT_BIN=$DIR"/target/release/plonkit"
DUMP_LAGRANGE_KEY=false

echo "Step0: build plonkit binary"
cargo build --release

echo "Step1: download universal setup file"
# It is the aztec ignition trusted setup key file. Thanks to matter-labs/zksync/infrastructure/zk/src/run/run.ts
pushd keys/setup
axel -ac https://universal-setup.ams3.digitaloceanspaces.com/setup_2^20.key || true
popd

echo "Step2: compile circuit and calculate witness using snarkjs"
. $TOOL_DIR/process_circom_circuit.sh

echo "Step3: export verification key"
$PLONKIT_BIN export-verification-key -m $SETUP_DIR/setup_2^20.key -c $CIRCUIT_DIR/circuit.r1cs.json -v $CIRCUIT_DIR/vk.bin

echo "Step4: generate verifier smart contract"
$PLONKIT_BIN generate-verifier -v $CIRCUIT_DIR/vk.bin -s $CIRCUIT_DIR/verifier.sol

if [ "$DUMP_LAGRANGE_KEY" = false ]; then
  echo "Step5: prove with key_monomial_form"
  $PLONKIT_BIN prove -m $SETUP_DIR/setup_2^20.key -c $CIRCUIT_DIR/circuit.r1cs.json -w $CIRCUIT_DIR/witness.json -p $CIRCUIT_DIR/proof.bin -j $CIRCUIT_DIR/proof.json -i $CIRCUIT_DIR/public.json
else
  echo "Step5.1: dump key_lagrange_form from key_monomial_form"
  $PLONKIT_BIN dump-lagrange -m $SETUP_DIR/setup_2^20.key -l $SETUP_DIR/setup_2^20_lagrange.key -c $CIRCUIT_DIR/circuit.r1cs.json
  echo "Step5.2: prove with key_monomial_form & key_lagrange_form"
  $PLONKIT_BIN prove -m $SETUP_DIR/setup_2^20.key -l $SETUP_DIR/setup_2^20_lagrange.key -c $CIRCUIT_DIR/circuit.r1cs.json -w $CIRCUIT_DIR/witness.json -p $CIRCUIT_DIR/proof.bin -j $CIRCUIT_DIR/proof.json -i $CIRCUIT_DIR/public.json
fi

echo "Step6: verify"
$PLONKIT_BIN verify -p $CIRCUIT_DIR/proof.bin -v $CIRCUIT_DIR/vk.bin
