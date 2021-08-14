#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPO_DIR=$DIR/".."
CIRCUIT_DIR=$DIR"/circuits/poseidon_recursive"
SETUP_DIR=$REPO_DIR"/keys/setup"
SETUP_POWER=24
SETUP_MK=$SETUP_DIR"/setup_2^${SETUP_POWER}.key"
#SETUP_LK=$SETUP_DIR"/setup_2^${SETUP_POWER}_lagrange.key"
DOWNLOAD_SETUP_FROM_REMOTE=false
PLONKIT_BIN=$REPO_DIR"/target/release/plonkit"
#PLONKIT_BIN="plonkit"
DUMP_LAGRANGE_KEY=false
CONTRACT_TEST_DIR=$DIR"/contract"

cargo build --release

echo "Step: collect old_proofs"
OLD_PROOFS_DIR=$CIRCUIT_DIR/proofs
mkdir -p $OLD_PROOFS_DIR
i=0
for witness_dir in `ls $CIRCUIT_DIR/data`
do
  WITNESS_DIR=$CIRCUIT_DIR/data/$witness_dir
  cp $WITNESS_DIR/proof.bin $OLD_PROOFS_DIR/$i.proof
  let "i++"
done

echo "Step: export recursive vk"
time ($PLONKIT_BIN export-recursive-verification-key -c $i -i 3 -m $SETUP_MK -v $CIRCUIT_DIR/recursive_vk.bin)

echo "Step: generate recursive proof"
time ($PLONKIT_BIN recursive-prove -m $SETUP_MK -o $OLD_PROOFS_DIR -v $CIRCUIT_DIR/vk.bin -n $CIRCUIT_DIR/recursive_proof.bin)

echo "Step: verify recursive proof"
time ($PLONKIT_BIN recursive-verify -p $CIRCUIT_DIR/recursive_proof.bin -v $CIRCUIT_DIR/recursive_vk.bin)

exit

# TODO: finish smart contract verify for recursive
echo "Step8: verify via smart contract"
pushd $CONTRACT_TEST_DIR
yarn install
mkdir -p contracts
cp $CIRCUIT_DIR/public.json $CONTRACT_TEST_DIR/test/data/public.json
cp $CIRCUIT_DIR/proof.json $CONTRACT_TEST_DIR/test/data/proof.json
cp $CIRCUIT_DIR/verifier.sol $CONTRACT_TEST_DIR/contracts/verifier.sol
npx hardhat test
popd
