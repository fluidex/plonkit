extern crate bellman_ce;
extern crate bellman_vk_codegen;
extern crate clap;
extern crate plonkit;

use clap::Clap;
use std::fs::File;
use std::path::Path;
use std::str;

use bellman_ce::pairing::bn256::Bn256;

use plonkit::circom_circuit::CircomCircuit;
use plonkit::plonk;
use plonkit::reader;

static TEMPLATE_PATH: &str = "./contrib/template.sol";

/// A zkSNARK toolkit to work with circom zkSNARKs DSL in plonk proof system
#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Trusted locally set up Plonk universal srs in monomial form
    Setup(SetupOpts),
    /// Dump "SRS in lagrange form" from a "SRS in monomial form"
    DumpLagrange(DumpLagrangeOpts),
    /// Generate a SNARK proof
    Prove(ProveOpts),
    /// Verify a SNARK proof
    Verify(VerifyOpts),
    /// Generate verifier smart contract
    GenerateVerifier(GenerateVerifierOpts),
    /// Export verifying key
    ExportVerificationKey(ExportVerificationKeyOpts),
}

/// A subcommand for locally trusted setting up Plonk universal srs in monomial form
#[derive(Clap)]
struct SetupOpts {
    /// Power_of_two exponent
    #[clap(short = "p", long = "power")]
    power: u32,
    /// Output file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form")]
    srs_monomial_form: String,
}

/// A subcommand for dumping SRS in lagrange form
#[derive(Clap)]
struct DumpLagrangeOpts {
    /// Source file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form")]
    srs_monomial_form: String,
    /// Output file for Plonk universal setup srs in lagrange form
    #[clap(short = "l", long = "srs_lagrange_form")]
    srs_lagrange_form: String,
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    #[clap(short = "c", long = "circuit")]
    circuit: Option<String>,
}

/// A subcommand for generating a SNARK proof
#[derive(Clap)]
struct ProveOpts {
    /// Source file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form")]
    srs_monomial_form: String,
    /// Source file for Plonk universal setup srs in lagrange form
    #[clap(short = "l", long = "srs_lagrange_form")]
    srs_lagrange_form: Option<String>,
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    #[clap(short = "c", long = "circuit")]
    circuit: Option<String>,
    /// Witness JSON file
    #[clap(short = "w", long = "witness", default_value = "witness.json")]
    witness: String,
    /// Output file for proof BIN
    #[clap(short = "p", long = "proof", default_value = "proof.bin")]
    proof: String,
}

/// A subcommand for verifying a SNARK proof
#[derive(Clap)]
struct VerifyOpts {
    /// Proof BIN file
    #[clap(short = "p", long = "proof", default_value = "proof.bin")]
    proof: String,
    /// Verification key file
    #[clap(short = "v", long = "verification_key", default_value = "vk.bin")]
    vk: String,
}

/// A subcommand for generating a Solidity verifier smart contract
#[derive(Clap)]
struct GenerateVerifierOpts {
    /// Verification key file
    #[clap(short = "v", long = "verification_key", default_value = "vk.bin")]
    vk: String,
    /// Output solidity file
    #[clap(short = "s", long = "sol", default_value = "verifier.sol")]
    sol: String,
}

/// A subcommand for exporting verifying keys
#[derive(Clap)]
struct ExportVerificationKeyOpts {
    /// Source file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form")]
    srs_monomial_form: String,
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    #[clap(short = "c", long = "circuit")]
    circuit: Option<String>,
    /// Output verifying key file
    #[clap(short = "v", long = "vk", default_value = "vk.bin")]
    vk: String,
}

fn main() {
    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Setup(o) => {
            setup(o);
        }
        SubCommand::DumpLagrange(o) => {
            dump_lagrange(o);
        }
        SubCommand::Prove(o) => {
            prove(o);
        }
        SubCommand::Verify(o) => {
            verify(o);
        }
        SubCommand::GenerateVerifier(o) => {
            generate_verifier(o);
        }
        SubCommand::ExportVerificationKey(o) => {
            export_vk(o);
        }
    }
}

fn setup(opts: SetupOpts) {
    let srs = plonk::gen_key_monomial_form::<Bn256>(opts.power).unwrap();
    let writer = File::create(&opts.srs_monomial_form).unwrap();
    srs.write(writer).unwrap();
    println!("srs_monomial_form saved to {}", opts.srs_monomial_form);
}

fn resolve_circuit_file(filename: Option<String>) -> String {
    match filename {
        Some(s) => s,
        None => {
            if Path::new("circuit.r1cs").exists() || !Path::new("circuit.json").exists() {
                "circuit.r1cs".to_string()
            } else {
                "circuit.json".to_string()
            }
        }
    }
}

fn dump_lagrange(opts: DumpLagrangeOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    println!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(&circuit_file),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup =
        plonk::SetupForProver::prepare_setup_for_prover(circuit.clone(), reader::load_key_monomial_form(&opts.srs_monomial_form), None)
            .expect("prepare err");

    let key_lagrange_form = setup.get_srs_lagrange_form_from_monomial_form();
    let writer = File::create(&opts.srs_lagrange_form).unwrap();
    key_lagrange_form.write(writer).unwrap();
    println!("srs_lagrange_form saved to {}", opts.srs_lagrange_form);
}

fn prove(opts: ProveOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    println!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(&circuit_file),
        witness: Some(reader::load_witness_from_json_file::<Bn256>(&opts.witness)),
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup = plonk::SetupForProver::prepare_setup_for_prover(
        circuit.clone(),
        reader::load_key_monomial_form(&opts.srs_monomial_form),
        reader::maybe_load_key_lagrange_form(opts.srs_lagrange_form),
    )
    .expect("prepare err");

    println!("Proving...");
    let proof = setup.prove(circuit).unwrap();
    let writer = File::create(&opts.proof).unwrap();
    proof.write(writer).unwrap();
    println!("Proof saved to {}", opts.proof);
}

fn verify(opts: VerifyOpts) {
    let vk = reader::load_verification_key::<Bn256>(&opts.vk);
    let proof = reader::load_proof::<Bn256>(&opts.proof);
    let correct = plonk::verify(&vk, &proof).unwrap();
    if correct {
        println!("Proof is correct");
    } else {
        println!("Proof is invalid!");
        std::process::exit(400);
    }
}

fn generate_verifier(opts: GenerateVerifierOpts) {
    let vk = reader::load_verification_key::<Bn256>(&opts.vk);
    bellman_vk_codegen::render_verification_key(&vk, TEMPLATE_PATH, &opts.sol);
    println!("Contract saved to {}", opts.sol);
}

fn export_vk(opts: ExportVerificationKeyOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    println!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(&circuit_file),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup =
        plonk::SetupForProver::prepare_setup_for_prover(circuit.clone(), reader::load_key_monomial_form(&opts.srs_monomial_form), None)
            .expect("prepare err");
    let vk = setup.make_verification_key().unwrap();

    let path = Path::new(&opts.vk);
    assert!(!path.exists(), "path for saving verification key exists: {}", path.display());
    let writer = File::create(&opts.vk).unwrap();
    vk.write(writer).unwrap();
    println!("Verification key saved to {}", opts.vk);
}
