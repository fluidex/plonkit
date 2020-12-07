# plonkit!

A zkSNARK toolkit to work with [circom](https://github.com/iden3/circom) zkSNARKs DSL in [plonk](https://eprint.iacr.org/2019/953) proof system. Based on [zkutil](https://github.com/poma/zkutil) and [bellman_ce](https://github.com/matter-labs/bellman).

## Prerequisites
+ `npm i`
+ axel

## Features & Todos

 + [x] Proof Generation
 + [x] Verification key generation
 + [x] Proof verification
 + [ ] Solidity verifier generation
 + [ ] Witness calculation without circom
 + [ ] Local key setup for developement

## Usage examples:

```shell script
# Getting help
> plonkit --help
plonkit 
A zkSNARK toolkit to work with circom zkSNARKs DSL in plonk proof system

USAGE:
    plonkit <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    dump-lagrange              Dump "SRS in lagrange form" from a "SRS in monomial form"
    export-verification-key    Export verifying key
    generate-verifier          Generate verifier smart contract
    help                       Prints this message or the help of the given subcommand(s)
    prove                      Generate a SNARK proof
    verify                     Verify a SNARK proof

# Getting help for a subcommand
> plonkit prove --help
plonkit-prove 
Generate a SNARK proof

USAGE:
    plonkit prove [OPTIONS] --srs_monomial_form <srs-monomial-form>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --circuit <circuit>                        Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    -p, --proof <proof>                            Output file for proof BIN [default: proof.bin]
    -l, --srs_lagrange_form <srs-lagrange-form>    Source file for Plonk universal setup srs in lagrange form
    -m, --srs_monomial_form <srs-monomial-form>    Source file for Plonk universal setup srs in monomial form
    -w, --witness <witness>                        Witness JSON file [default: witness.json]

# Suppose we have circuit file and a sample inputs, plus a plonk universal setup SRS
> ls
circuit.circom  input.json  setup_2^20.key

# Compile the circuit
> circom circuit.circom --r1cs --wasm --sym -v
# Convert the R1CS to json
> snarkjs r1cs export json circuit.r1cs circuit.r1cs.json

# Generate the witness using snarkjs
# At the moment we still need to calculate witness using snarkjs
> snarkjs wc circuit.wasm input.json witness.wtns
# Convert the witness to json
> snarkjs wej witness.wtns witness.json

# Generate a snark proof using the universal setup monomial-form SRS
> plonkit prove --srs_monomial_form setup_2^20.key --circuit circuit.r1cs.json --witness witness.json --proof proof.bin
Loading circuit...
Proving...
Proof saved to proof.bin

# Export verification key
> plonkit export-verification-key --srs_monomial_form setup_2^20.key --circuit circuit.r1cs.json --vk vk.bin
Verification key saved to vk.bin
# Verify the proof
> plonkit verify --proof proof.bin --verification_key vk.bin
Proof is correct

# Here's a list of files that we have after this
> ls
circuit.circom  circuit.r1cs  circuit.r1cs.json  circuit.sym  circuit.wasm  input.json  proof.json  setup_2^20.key  vk.bin  witness.json  witness.wtns
```

Also see `test_poseidon_plonk.sh` for example.

## Installation

Install Rust

```shell script
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install plonkit globally

```shell script
cargo install --git https://github.com/Fluidex/plonkit
# Make sure `~/.cargo/bin` is in $PATH (should be added automatically during Rust installation)
```

Or alternatively you can compile and run it instead:

```shell script
git clone https://github.com/Fluidex/plonkit
cd plonkit
cargo run --release -- prove --help
```
