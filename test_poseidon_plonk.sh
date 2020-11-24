set -ex
# from zksync/infrastructure/zk/src/run/run.ts

echo "Step1: download universal setup file"

pushd keys/setup
axel -c https://universal-setup.ams3.digitaloceanspaces.com/setup_2^20.key || true
popd

echo "Step2: compile circuit and calculate witness using snarkjs"
. ./process_circom_circuit.sh

echo "Step3: prove and verify" 
RUST_LOG=info cargo test --release simple_plonk_test
