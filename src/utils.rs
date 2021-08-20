use num_bigint::BigUint;
use num_traits::Num;
use std::fmt::Display;

pub fn repr_to_big<T: Display>(r: T) -> String {
    BigUint::from_str_radix(&format!("{}", r)[2..], 16).unwrap().to_str_radix(10)
}

#[cfg(test)]
mod tests {
    use super::repr_to_big;

    #[test]
    fn test_repr_to_big() {
        assert_eq!(
            repr_to_big("0x5d182c51bcfe99583d7075a7a0c10d96bef82b8a059c4bf8c5f6e7124cf2bba3"),
            "42107805128296840955128475693973618460424912398453449171839298387937674312611"
        )
    }
}
