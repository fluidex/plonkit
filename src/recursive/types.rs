#![allow(clippy::needless_range_loop)]

use bellman_ce::plonk::better_cs::keys::{read_fr_vec, write_fr_vec};
use franklin_crypto::bellman::pairing::bn256;
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use recursive_aggregation_circuit::circuit::RecursiveAggregationCircuitBn256;

// notice the life time in RecursiveAggregationCircuit is related to  series of param groups
// for most cases we could make the params static
type RecursiveCircuitProof<'a> = Proof<Bn256, RecursiveAggregationCircuitBn256<'a>>;

pub type RecursiveVerificationKey<'a> = VerificationKey<Bn256, RecursiveAggregationCircuitBn256<'a>>;

pub struct AggregatedProof {
    pub proof: RecursiveCircuitProof<'static>,
    pub individual_vk_inputs: Vec<bn256::Fr>, // flatten Vec<Vec<bn256::Fr>> into Vec<bn256::Fr>
    pub individual_num_inputs: usize,
    pub individual_vk_idxs: Vec<usize>,
    pub aggr_limbs: Vec<bn256::Fr>,
}

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

fn read_usize_vec<R: Read>(mut reader: R) -> std::io::Result<Vec<usize>> {
    let num_elements = reader.read_u64::<LittleEndian>()?;
    let mut elements = vec![];
    for _ in 0..num_elements {
        let el = reader.read_u64::<LittleEndian>()?;
        elements.push(el as usize);
    }

    Ok(elements)
}

fn write_usize_vec<W: Write>(p: &[usize], mut writer: W) -> std::io::Result<()> {
    writer.write_u64::<LittleEndian>(p.len() as u64)?;
    for p in p.iter() {
        writer.write_u64::<LittleEndian>(*p as u64)?;
    }
    Ok(())
}

impl AggregatedProof {
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        self.proof.write(&mut writer)?;
        write_fr_vec(&self.individual_vk_inputs, &mut writer)?;
        write_fr_vec(&self.aggr_limbs, &mut writer)?;
        write_usize_vec(&self.individual_vk_idxs, &mut writer)?;
        writer.write_u64::<LittleEndian>(self.individual_num_inputs as u64)?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let proof = RecursiveCircuitProof::<'static>::read(&mut reader)?;
        let vk_inputs = read_fr_vec::<bn256::Fr, _>(&mut reader)?;
        let aggr_limbs = read_fr_vec::<bn256::Fr, _>(&mut reader)?;
        let vk_idexs = read_usize_vec(&mut reader)?;
        let num_inputs = reader.read_u64::<LittleEndian>()? as usize;

        Ok(Self {
            proof,
            individual_vk_inputs: vk_inputs,
            individual_num_inputs: num_inputs,
            individual_vk_idxs: vk_idexs,
            aggr_limbs,
        })
    }
}
