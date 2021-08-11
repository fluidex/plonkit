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

echo "Step0: check for necessary dependencies: node,npm,axel"
PKG_PATH=""
PKG_PATH=$(command -v npm)
echo Checking for npm
if [ -z "$PKG_PATH" ]; then
  echo "npm not found. Installing nvm & npm & node."
  source <(curl -s https://raw.githubusercontent.com/nvm-sh/nvm/v0.37.2/install.sh)
else
  echo npm exists at $PKG_PATH
fi
PKG_PATH=""
PKG_PATH=$(command -v axel)
if ($DOWNLOAD_SETUP_FROM_REMOTE & [ -z "$PKG_PATH" ]) ; then
  echo Checking for axel
  echo "axel not found. Installing axel."
  sudo apt-get --yes install axel
elif [ ! -z "$PKG_PATH" ] ; then
  echo axel exists at $PKG_PATH
fi
yarn install

echo "Step1: build plonkit binary"
cargo build --release
#cargo install --git https://github.com/Fluidex/plonkit
#$PLONKIT_BIN --help

echo "Step2: universal setup"
pushd $SETUP_DIR
if ([ ! -f $SETUP_MK ] & $DOWNLOAD_SETUP_FROM_REMOTE); then
  # It is the aztec ignition trusted setup key file. Thanks to matter-labs/zksync/infrastructure/zk/src/run/run.ts
  axel -ac https://universal-setup.ams3.digitaloceanspaces.com/setup_2^${SETUP_POWER}.key -o $SETUP_MK || true
elif [ ! -f $SETUP_MK ] ; then
    $PLONKIT_BIN setup --power ${SETUP_POWER} --srs_monomial_form $SETUP_MK
fi
popd

echo "Step3: compile circuit and calculate witness"
npx snarkit check $CIRCUIT_DIR --witness_type bin

echo "Step4: export verification key"
$PLONKIT_BIN export-verification-key -m $SETUP_MK -c $CIRCUIT_DIR/circuit.r1cs -v $CIRCUIT_DIR/vk.bin

#echo "Step5: generate verifier smart contract"
#$PLONKIT_BIN generate-verifier -v $CIRCUIT_DIR/vk.bin -s $CIRCUIT_DIR/verifier.sol #-t contrib/template.sol

if [ "$DUMP_LAGRANGE_KEY" = false ]; then
  echo "Step6: prove with key_monomial_form"
  for witness_dir in `ls $CIRCUIT_DIR/data`
  do
    WITNESS_DIR=$CIRCUIT_DIR/data/$witness_dir
    $PLONKIT_BIN prove -m $SETUP_MK -c $CIRCUIT_DIR/circuit.r1cs -w $WITNESS_DIR/witness.wtns -p $WITNESS_DIR/proof.bin -j $WITNESS_DIR/proof.json -i $WITNESS_DIR/public.json -t rescue
  done
else
  echo "Step6.1: dump key_lagrange_form from key_monomial_form"
  $PLONKIT_BIN dump-lagrange -m $SETUP_MK -l $SETUP_LK -c $CIRCUIT_DIR/circuit.r1cs
  echo "Step6.2: prove with key_monomial_form & key_lagrange_form"
  for witness_dir in `ls $CIRCUIT_DIR/data`
  do
    WITNESS_DIR=$CIRCUIT_DIR/data/$witness_dir
    $PLONKIT_BIN prove -m $SETUP_MK -l $SETUP_LK -c $CIRCUIT_DIR/circuit.r1cs -w $WITNESS_DIR/witness.wtns -p $WITNESS_DIR/proof.bin -j $WITNESS_DIR/proof.json -i $WITNESS_DIR/public.json
  done
fi

echo "Step7: verify"
for witness_dir in `ls $CIRCUIT_DIR/data`
do
  WITNESS_DIR=$CIRCUIT_DIR/data/$witness_dir
  $PLONKIT_BIN verify -p $WITNESS_DIR/proof.bin -v $CIRCUIT_DIR/vk.bin -t rescue
done

echo "Step8: test recursive proof"
./target/release/plonkit_recursive_test

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
