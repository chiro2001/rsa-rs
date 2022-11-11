use lazy_static::lazy_static;
use mut_static::MutStatic;
use num_cpus;
use crate::RSA;

lazy_static! {
    pub static ref CONFIG_DEF: RSA = RSA {
        mode: String::from("generate"),
        key: String::from("key"),
        input: String::from("stdin"),
        // input: String::from("data/lab2-Plaintext.txt"),
        output: String::from("stdout"),
        // output: String::from("data/data.tmp"),
        prime_min: 14, prime_max: 512,
        binary: false,
        rounds: 10,
        time_max: 1000,
        silent: false,
        threads: num_cpus::get(),
        retry: true,
        comment: String::from("RSA-RS COMMENT")
    };
    pub static ref SILENT: MutStatic<bool> =
        MutStatic::new();
        // MutStatic::from(false);
        // MutStatic::from(true);
}
