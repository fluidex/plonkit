#!/bin/sh
set -e

# Test on latest circom
#rm -rf node_modules package.json package-lock.json proving_key.json verification_key.json params.bin proof.json public.json
#npm init -y
#npm install circom snarkjs
#./test.sh

# Test on json-based circom version
rm -rf node_modules package.json package-lock.json proving_key.json verification_key.json params.bin proof.json public.json
npm init -y
npm install circom@0.0.35 snarkjs@0.1.20
./test.sh