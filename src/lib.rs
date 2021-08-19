#[macro_use]
extern crate serde;
#[macro_use]
extern crate hex_literal;
extern crate bellman_ce;
extern crate bellman_vk_codegen;
extern crate byteorder;
extern crate itertools;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;

pub mod circom_circuit;
pub mod plonk;
pub mod r1cs_file;
pub mod reader;
pub mod recursive;
pub mod transpile;
pub mod utils;

#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod pb {
    tonic::include_proto!("plonkitserver");
}

#[cfg(test)]
mod tests;