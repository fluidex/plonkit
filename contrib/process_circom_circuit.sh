#!/bin/bash
set -ex

pushd $CIRCUIT_DIR
npx circom circuit.circom --r1cs --wasm --sym -v
npx snarkjs r1cs export json circuit.r1cs circuit.r1cs.json

# generate the witness using snarkjs
npx snarkjs wc circuit.wasm input.json witness.wtns
# convert the witness to json
npx snarkjs wej witness.wtns witness.json

popd
