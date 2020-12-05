use num_bigint::BigUint;
use num_traits::Num;
use std::fmt::Display;

pub fn repr_to_big<T: Display>(r: T) -> String {
    BigUint::from_str_radix(&format!("{}", r)[2..], 16).unwrap().to_str_radix(10)
}
