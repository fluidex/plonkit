#![allow(clippy::unit_arg)]

#[macro_use]
extern crate serde;
#[macro_use]
extern crate hex_literal;
extern crate franklin_crypto;
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

pub use franklin_crypto::bellman as bellman_ce;

#[cfg(test)]
mod tests;
