pub mod key_writer;
pub mod key_reader;
pub mod key_data;
pub mod key_pair;

pub use key_pair::*;
pub use key_reader::*;
pub use key_writer::*;
pub use key_data::*;

use num_bigint::BigInt;
use num_traits::Zero;

#[derive(Debug, Clone)]
pub struct Key {
    pub base: BigInt,
    pub m: BigInt,
}

impl Default for Key {
    fn default() -> Self {
        Self { base: BigInt::zero(), m: BigInt::zero() }
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.m == other.m && self.base == other.base
    }
}

#[derive(Debug)]
pub struct KeySet {
    pub public: Key,
    pub private: Key,
}

#[derive(Debug)]
pub enum KeyError {
    ParseError(String),
    FormatError,
}

const BASE64_SPLIT: usize = 70;
