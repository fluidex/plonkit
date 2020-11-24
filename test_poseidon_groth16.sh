#!/bin/sh
set -ex

. ./process_circom_circuit.sh
CIRCUIT_DIR="testdata/poseidon"

# Do a local trusted setup, generate params.bin
cargo run --release setup -c $CIRCUIT_DIR/circuit.r1cs.json

# Export proving and verifying keys compatible with snarkjs and websnark
cargo run --release export-keys

# generate solidity verifier
cargo run --release generate-verifier

cargo run --release prove -c $CIRCUIT_DIR/circuit.r1cs.json
cargo run --release verify

# Double check by verifying the same proof with snarkjs
# npx snarkjs verify
