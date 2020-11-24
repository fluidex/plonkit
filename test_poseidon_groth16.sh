#!/bin/bash
set -ex
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TOOL_DIR=$DIR"/contrib"
CIRCUIT_DIR=$DIR"/testdata/poseidon"

. $TOOL_DIR/process_circom_circuit.sh

# Do a local trusted setup, generate params.bin
cargo run --release setup -c $CIRCUIT_DIR/circuit.r1cs.json

# Export proving and verifying keys compatible with snarkjs and websnark
cargo run --release export-keys -c $CIRCUIT_DIR/circuit.r1cs.json

# generate solidity verifier
cargo run --release generate-verifier

cargo run --release prove -c $CIRCUIT_DIR/circuit.r1cs.json -w $CIRCUIT_DIR/witness.json
cargo run --release verify

# Double check by verifying the same proof with snarkjs
# npx snarkjs verify
