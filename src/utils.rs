extern crate bellman_ce;
extern crate byteorder;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;

use bellman_ce::{
    groth16::Proof,
    pairing::{
        bn256::{Bn256, Fq12, G1Affine, G2Affine},
        ff::PrimeField,
        CurveAffine,
    },
};
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Num;
use std::fmt::Display;

pub fn repr_to_big<T: Display>(r: T) -> String {
    BigUint::from_str_radix(&format!("{}", r)[2..], 16).unwrap().to_str_radix(10)
}

pub fn repr_to_hex<T: Display>(r: T) -> String {
    format!("{}", r)[2..].to_string()
}

pub fn proof_to_hex(proof: &Proof<Bn256>) -> String {
    let a = proof.a.into_xy_unchecked();
    let b = proof.b.into_xy_unchecked();
    let c = proof.c.into_xy_unchecked();
    [a.0, a.1, b.0.c1, b.0.c0, b.1.c1, b.1.c0, c.0, c.1]
        .iter()
        .map(|e| repr_to_hex(e.into_repr()))
        .join("")
}

pub fn p1_to_vec(p: &G1Affine) -> Vec<String> {
    let xy = p.into_xy_unchecked();
    vec![
        repr_to_big(xy.0.into_repr()),
        repr_to_big(xy.1.into_repr()),
        if p.is_zero() { "0".to_string() } else { "1".to_string() },
    ]
}

pub fn p2_to_vec(p: &G2Affine) -> Vec<Vec<String>> {
    let xy = p.into_xy_unchecked();
    vec![
        vec![repr_to_big(xy.0.c0.into_repr()), repr_to_big(xy.0.c1.into_repr())],
        vec![repr_to_big(xy.1.c0.into_repr()), repr_to_big(xy.1.c1.into_repr())],
        if p.is_zero() {
            vec!["0".to_string(), "0".to_string()]
        } else {
            vec!["1".to_string(), "0".to_string()]
        },
    ]
}

pub fn pairing_to_vec(p: &Fq12) -> Vec<Vec<Vec<String>>> {
    vec![
        vec![
            vec![repr_to_big(p.c0.c0.c0.into_repr()), repr_to_big(p.c0.c0.c1.into_repr())],
            vec![repr_to_big(p.c0.c1.c0.into_repr()), repr_to_big(p.c0.c1.c1.into_repr())],
            vec![repr_to_big(p.c0.c2.c0.into_repr()), repr_to_big(p.c0.c2.c1.into_repr())],
        ],
        vec![
            vec![repr_to_big(p.c1.c0.c0.into_repr()), repr_to_big(p.c1.c0.c1.into_repr())],
            vec![repr_to_big(p.c1.c1.c0.into_repr()), repr_to_big(p.c1.c1.c1.into_repr())],
            vec![repr_to_big(p.c1.c2.c0.into_repr()), repr_to_big(p.c1.c2.c1.into_repr())],
        ],
    ]
}
