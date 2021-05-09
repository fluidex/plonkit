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
use plonkit::pb;
use plonkit::plonk;
use plonkit::reader;

#[cfg(feature = "server")]
mod server;

//static TEMPLATE_PATH: &str = "./contrib/template.sol";

/// A zkSNARK toolkit to work with circom zkSNARKs DSL in plonk proof system
#[derive(Clap)]
#[clap(version = "0.0.4")]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Analyse the circuit and output some stats
    Analyse(AnalyseOpts),
    /// Trusted locally set up Plonk universal srs in monomial form
    Setup(SetupOpts),
    /// Dump "SRS in lagrange form" from a "SRS in monomial form"
    DumpLagrange(DumpLagrangeOpts),
    /// Serve for SNARK proof
    Serve(ServerOpts),
    /// Generate a SNARK proof
    Prove(ProveOpts),
    /// Verify a SNARK proof
    Verify(VerifyOpts),
    /// Generate verifier smart contract
    GenerateVerifier(GenerateVerifierOpts),
    /// Export verifying key
    ExportVerificationKey(ExportVerificationKeyOpts),
}

/// A subcommand for analysing the circuit and outputting some stats
#[derive(Clap)]
struct AnalyseOpts {
    /// Circuit R1CS or JSON file [default: circuit.r1cs|circuit.json]
    #[clap(short = "c", long = "circuit")]
    circuit: Option<String>,
    /// Output file
    #[clap(short = "o", long = "output", default_value = "analyse.json")]
    output: String,
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

/// A subcommand for running a server and do SNARK proving
#[derive(Clap)]
struct ServerOpts {
    /// Server address
    #[clap(long = "address")]
    srv_addr: Option<String>,
    /// Source file for Plonk universal setup srs in monomial form
    #[clap(short = "m", long = "srs_monomial_form")]
    srs_monomial_form: String,
    /// Source file for Plonk universal setup srs in lagrange form
    #[clap(short = "l", long = "srs_lagrange_form")]
    srs_lagrange_form: Option<String>,
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
    #[clap(short = "w", long = "witness", default_value = "witness.wtns")]
    witness: String,
    /// Output file for proof BIN
    #[clap(short = "p", long = "proof", default_value = "proof.bin")]
    proof: String,
    /// Output file for proof json
    #[clap(short = "j", long = "proofjson", default_value = "proof.json")]
    proofjson: String,
    /// Output file for public input json
    #[clap(short = "i", long = "publicjson", default_value = "public.json")]
    publicjson: String,
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
    // Always print backtrace on panic.
    ::std::env::set_var("RUST_BACKTRACE", "1");
    match ::std::env::var("RUST_LOG") {
        Ok(value) => {
            if value.is_empty() {
                ::std::env::set_var("RUST_LOG", "info");
            }
        }
        Err(_) => ::std::env::set_var("RUST_LOG", "info"),
    }
    env_logger::init();

    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Analyse(o) => {
            analyse(o);
        }
        SubCommand::Setup(o) => {
            setup(o);
        }
        SubCommand::DumpLagrange(o) => {
            dump_lagrange(o);
        }
        SubCommand::Serve(o) => {
            prove_server(o);
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

fn analyse(opts: AnalyseOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    log::info!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(&circuit_file),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };
    let mut stats = plonk::analyse(circuit).expect("analyse failed");
    let writer = File::create(&opts.output).unwrap();
    serde_json::to_writer_pretty(writer, &stats).expect("write failed");
    stats.constraint_stats.clear();
    log::info!(
        "analyse result: {}",
        serde_json::to_string_pretty(&stats).unwrap_or_else(|_| "<failed>".to_owned())
    );
    log::info!("output to {}", opts.output);
}

fn setup(opts: SetupOpts) {
    let srs = plonk::gen_key_monomial_form::<Bn256>(opts.power).unwrap();
    let writer = File::create(&opts.srs_monomial_form).unwrap();
    srs.write(writer).unwrap();
    log::info!("srs_monomial_form saved to {}", opts.srs_monomial_form);
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
    log::info!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(&circuit_file),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup = plonk::SetupForProver::prepare_setup_for_prover(circuit, reader::load_key_monomial_form(&opts.srs_monomial_form), None)
        .expect("prepare err");

    let key_lagrange_form = setup.get_srs_lagrange_form_from_monomial_form();
    let writer = File::create(&opts.srs_lagrange_form).unwrap();
    key_lagrange_form.write(writer).unwrap();
    log::info!("srs_lagrange_form saved to {}", opts.srs_lagrange_form);
}

#[cfg(feature = "server")]
fn prove_server(opts: ServerOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    log::info!("Loading circuit from {}...", circuit_file);
    let circuit_base = CircomCircuit {
        r1cs: reader::load_r1cs(&circuit_file),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let srs_monomial_form = opts.srs_monomial_form;
    let srs_lagrange_form = opts.srs_lagrange_form;

    let builder = move || -> server::ProveCore {
        let setup = plonk::SetupForProver::prepare_setup_for_prover(
            circuit_base.clone(),
            reader::load_key_monomial_form(&srs_monomial_form),
            reader::maybe_load_key_lagrange_form(srs_lagrange_form),
        )
        .expect("prepare err");

        Box::new(move |witness: Vec<u8>, validate_only: bool| -> server::CoreResult {
            let mut circut = circuit_base.clone();
            match reader::load_witness_from_array::<Bn256>(witness) {
                Ok(witness) => circut.witness = Some(witness),
                err => return server::CoreResult::any_prove_error(err, validate_only),
            }

            if validate_only {
                match setup.validate_witness(circut) {
                    Ok(_) => server::CoreResult::success(validate_only),
                    err => server::CoreResult::any_prove_error(err, validate_only),
                }
            } else {
                let start = std::time::Instant::now();
                match setup.prove(circut) {
                    Ok(proof) => {
                        let elapsed = start.elapsed().as_secs_f64();

                        let ret = server::CoreResult::success(validate_only);
                        let mut mut_resp: pb::ProveResponse = ret.into();

                        let (inputs, serialized_proof) = bellman_vk_codegen::serialize_proof(&proof);
                        mut_resp.proof = serialized_proof.iter().map(ToString::to_string).collect();
                        mut_resp.inputs = inputs.iter().map(ToString::to_string).collect();
                        mut_resp.time_cost_secs = elapsed;

                        server::CoreResult::Prove(mut_resp)
                    }

                    err => server::CoreResult::any_prove_error(err, validate_only),
                }
            }
        })
    };

    log::info!("Starting server ... use CTRL+C to exit");
    server::run(server::ServerOptions {
        server_addr: opts.srv_addr,
        build_prove_core: Box::new(builder),
    });
}

#[cfg(not(feature = "server"))]
fn prove_server(opts: ServerOpts) {
    log::info!(
        "Binary is not built with server feature: {:?}, {:?}, {:?}, {}",
        opts.srv_addr,
        opts.circuit,
        opts.srs_lagrange_form,
        opts.srs_monomial_form
    );
}

fn prove(opts: ProveOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    log::info!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(&circuit_file),
        witness: Some(reader::load_witness_from_file::<Bn256>(&opts.witness)),
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup = plonk::SetupForProver::prepare_setup_for_prover(
        circuit.clone(),
        reader::load_key_monomial_form(&opts.srs_monomial_form),
        reader::maybe_load_key_lagrange_form(opts.srs_lagrange_form),
    )
    .expect("prepare err");

    log::info!("Proving...");
    let proof = setup.prove(circuit).unwrap();
    let writer = File::create(&opts.proof).unwrap();
    proof.write(writer).unwrap();
    log::info!("Proof saved to {}", opts.proof);

    cfg_if::cfg_if! {
        if #[cfg(feature = "solidity")] {
            let (inputs, serialized_proof) = bellman_vk_codegen::serialize_proof(&proof);
            let ser_proof_str = serde_json::to_string_pretty(&serialized_proof).unwrap();
            let ser_inputs_str = serde_json::to_string_pretty(&inputs).unwrap();
            std::fs::write(&opts.proofjson, ser_proof_str.as_bytes()).expect("save proofjson err");
            log::info!("Proof json saved to {}", opts.proofjson);
            std::fs::write(&opts.publicjson, ser_inputs_str.as_bytes()).expect("save publicjson err");
            log::info!("Public input json saved to {}", opts.publicjson);
        }
    }
}

fn verify(opts: VerifyOpts) {
    let vk = reader::load_verification_key::<Bn256>(&opts.vk);
    let proof = reader::load_proof::<Bn256>(&opts.proof);
    let correct = plonk::verify(&vk, &proof).unwrap();
    if correct {
        log::info!("Proof is valid.");
    } else {
        log::info!("Proof is invalid!");
        std::process::exit(400);
    }
}

fn generate_verifier(opts: GenerateVerifierOpts) {
    cfg_if::cfg_if! {
        if #[cfg(feature = "solidity")] {
            let vk = reader::load_verification_key::<Bn256>(&opts.vk);
            bellman_vk_codegen::render_verification_key_from_default_template(&vk, &opts.sol);
            log::info!("Contract saved to {}", opts.sol);
        } else {
            unimplemented!("you must enable `solidity` feature flag");
        }
    }
}

fn export_vk(opts: ExportVerificationKeyOpts) {
    let circuit_file = resolve_circuit_file(opts.circuit);
    log::info!("Loading circuit from {}...", circuit_file);
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(&circuit_file),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup = plonk::SetupForProver::prepare_setup_for_prover(circuit, reader::load_key_monomial_form(&opts.srs_monomial_form), None)
        .expect("prepare err");
    let vk = setup.make_verification_key().unwrap();

    //let path = Path::new(&opts.vk);
    //assert!(!path.exists(), "path for saving verification key exists: {}", path.display());
    let writer = File::create(&opts.vk).unwrap();
    vk.write(writer).unwrap();
    log::info!("Verification key saved to {}", opts.vk);
}
