#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPO_DIR=$DIR/".."
CIRCUIT_DIR=$DIR"/circuits/poseidon_recursive"
SETUP_DIR=$REPO_DIR"/keys/setup"
SETUP_MK=$SETUP_DIR"/setup_2^20.key"
BIG_SETUP_MK=$SETUP_DIR"/setup_2^24.key"
DOWNLOAD_SETUP_FROM_REMOTE=false
PLONKIT_BIN=$REPO_DIR"/target/release/plonkit"
CONTRACT_TEST_DIR=$DIR"/contract"

echo "Step: build plonkit"
cargo build --release

echo "Step: universal setup"
pushd $SETUP_DIR
if ([ ! -f $SETUP_MK ] & $DOWNLOAD_SETUP_FROM_REMOTE); then
  # It is the aztec ignition trusted setup key file. Thanks to matter-labs/zksync/infrastructure/zk/src/run/run.ts
  axel -ac https://universal-setup.ams3.digitaloceanspaces.com/setup_2^${SETUP_POWER}.key -o $SETUP_MK || true
elif [ ! -f $SETUP_MK ] ; then
    $PLONKIT_BIN setup --power 20 --srs_monomial_form $SETUP_MK
fi
if ([ ! -f $BIG_SETUP_MK ] & $DOWNLOAD_SETUP_FROM_REMOTE); then
  # It is the aztec ignition trusted setup key file. Thanks to matter-labs/zksync/infrastructure/zk/src/run/run.ts
  axel -ac https://universal-setup.ams3.digitaloceanspaces.com/setup_2^${SETUP_POWER}.key -o $BIG_SETUP_MK || true
elif [ ! -f $BIG_SETUP_MK ] ; then
    $PLONKIT_BIN setup --power 24 --srs_monomial_form $BIG_SETUP_MK
fi
popd

echo "Step: compile circuit and calculate witness"
npx snarkit check $CIRCUIT_DIR --witness_type bin

echo "Step: export verification key"
$PLONKIT_BIN export-verification-key -m $SETUP_MK -c $CIRCUIT_DIR/circuit.r1cs -v $CIRCUIT_DIR/vk.bin

echo "Step: generate each proof"
for witness_dir in `ls $CIRCUIT_DIR/data`
do
  WITNESS_DIR=$CIRCUIT_DIR/data/$witness_dir
  $PLONKIT_BIN prove -m $SETUP_MK -c $CIRCUIT_DIR/circuit.r1cs -w $WITNESS_DIR/witness.wtns -p $WITNESS_DIR/proof.bin -j $WITNESS_DIR/proof.json -i $WITNESS_DIR/public.json -t rescue
done

echo "Step: collect old_proofs list"
OLD_PROOF_LIST=$CIRCUIT_DIR/old_proof_list.txt
rm $OLD_PROOF_LIST -rf
touch $OLD_PROOF_LIST
i=0
for witness_dir in `ls $CIRCUIT_DIR/data`
do
  WITNESS_DIR=$CIRCUIT_DIR/data/$witness_dir
  echo $WITNESS_DIR/proof.bin >> $OLD_PROOF_LIST
  let "i++"
done
cat $OLD_PROOF_LIST

echo "Step: export recursive vk"
time ($PLONKIT_BIN export-recursive-verification-key -c $i -i 3 -m $BIG_SETUP_MK -v $CIRCUIT_DIR/recursive_vk.bin)

echo "Step: generate recursive proof"
time ($PLONKIT_BIN recursive-prove -m $BIG_SETUP_MK -f $OLD_PROOF_LIST -v $CIRCUIT_DIR/vk.bin -n $CIRCUIT_DIR/recursive_proof.bin)

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
