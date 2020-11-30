extern crate clap;

use clap::Clap;
use std::str;

#[derive(Clap, Debug, PartialEq, Clone)]
pub enum ProofSystem {
    Groth16,
    Plonk,
}

impl str::FromStr for ProofSystem {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "groth16" | "Groth16" | "gro16" | "Gro16" => Ok(Self::Groth16),
            "plonk" | "Plonk" | "PLONK" | "PlonK" => Ok(Self::Plonk),
            _ => Err("Invalid proof system"),
        }
    }
}

impl ProofSystem {
    pub fn aux_offset(&self) -> usize {
        match self {
            ProofSystem::Groth16 => 0,
            ProofSystem::Plonk => 1, // plonk uses 1st var internally
        }
    }
}
