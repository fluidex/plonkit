#!/bin/bash
set -ex
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TOOL_DIR=$DIR"/contrib"
CIRCUIT_DIR=$DIR"/testdata/poseidon"
SETUP_DIR=$DIR"/keys/setup"

# from zksync/infrastructure/zk/src/run/run.ts
echo "Step1: download universal setup file"
pushd keys/setup
axel -ac https://universal-setup.ams3.digitaloceanspaces.com/setup_2^20.key || true
popd

echo "Step2: compile circuit and calculate witness using snarkjs"
. $TOOL_DIR/process_circom_circuit.sh

echo "Step3: export verification key"
cargo run --release export-verification-key -m $SETUP_DIR/setup_2^20.key -s plonk -c $CIRCUIT_DIR/circuit.r1cs.json -v $CIRCUIT_DIR/vk.bin

echo "Step4: prove with key_monomial_form"
cargo run --release prove -m $SETUP_DIR/setup_2^20.key -s plonk -c $CIRCUIT_DIR/circuit.r1cs.json -w $CIRCUIT_DIR/witness.json -p $CIRCUIT_DIR/proof.bin

echo "Step5: dump key_lagrange_form from key_monomial_form"
cargo run --release dump-lagrange -m $SETUP_DIR/setup_2^20.key -l $SETUP_DIR/setup_2^20_lagrange.key -s plonk -c $CIRCUIT_DIR/circuit.r1cs.json -w $CIRCUIT_DIR/witness.json

echo "Step6: prove with key_monomial_form & key_lagrange_form"
cargo run --release prove -m $SETUP_DIR/setup_2^20.key -l $SETUP_DIR/setup_2^20_lagrange.key -s plonk -c $CIRCUIT_DIR/circuit.r1cs.json -w $CIRCUIT_DIR/witness.json -p $CIRCUIT_DIR/proof.bin

echo "Step7: verify"
cargo run --release verify -s plonk -p $CIRCUIT_DIR/proof.bin -v $CIRCUIT_DIR/vk.bin
