extern crate bellman_ce;
extern crate rand;
extern crate byteorder;
extern crate num_bigint;
extern crate num_traits;

use std::fmt::Display;
use num_bigint::BigUint;
use num_traits::Num;
use bellman_ce::pairing::{
    ff::PrimeField,
    CurveAffine,
    bn256::{
        G1Affine,
        G2Affine,
        Fq12,
    }
};

pub fn repr_to_big<T: Display>(r: T) -> String {
    BigUint::from_str_radix(&format!("{}", r)[2..], 16).unwrap().to_str_radix(10)
}

pub fn p1_to_vec(p: &G1Affine) -> Vec<String> {
    let xy = p.into_xy().unwrap();
    return vec![
        repr_to_big(xy.0.into_repr()),
        repr_to_big(xy.1.into_repr()),
        if p.is_zero() { "0".to_string() } else { "1".to_string() }
    ]
}

pub fn p2_to_vec(p: &G2Affine) -> Vec<Vec<String>> {
    let xy = p.into_xy().unwrap();
    return vec![
        vec![
            repr_to_big(xy.0.c0.into_repr()),
            repr_to_big(xy.0.c1.into_repr()),
        ],
        vec![
            repr_to_big(xy.1.c0.into_repr()),
            repr_to_big(xy.1.c1.into_repr()),
        ],
        if p.is_zero() {
            vec!["0".to_string(), "0".to_string()]
        } else {
            vec!["1".to_string(), "0".to_string()]
        }
    ]
}

pub fn pairing_to_vec(p: &Fq12) -> Vec<Vec<Vec<String>>> {
    return vec![
        vec![
            vec![
                repr_to_big(p.c0.c0.c0.into_repr()),
                repr_to_big(p.c0.c0.c1.into_repr()),
            ],
            vec![
                repr_to_big(p.c0.c1.c0.into_repr()),
                repr_to_big(p.c0.c1.c1.into_repr()),
            ],
            vec![
                repr_to_big(p.c0.c2.c0.into_repr()),
                repr_to_big(p.c0.c2.c1.into_repr()),
            ]
        ],
        vec![
            vec![
                repr_to_big(p.c1.c0.c0.into_repr()),
                repr_to_big(p.c1.c0.c1.into_repr()),
            ],
            vec![
                repr_to_big(p.c1.c1.c0.into_repr()),
                repr_to_big(p.c1.c1.c1.into_repr()),
            ],
            vec![
                repr_to_big(p.c1.c2.c0.into_repr()),
                repr_to_big(p.c1.c2.c1.into_repr()),
            ]
        ],
    ]
}