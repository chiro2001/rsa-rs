mod rsa;

pub use crate::rsa::*;
pub use crate::rsa::config::SILENT;
pub use crate::RSA;

use std::error::Error;
use clap::Parser;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rsa = RSA::parse();
    if rsa.output == "stdout" && (rsa.mode == "encode" || rsa.mode == "decode") {
        rsa.silent = true;
    }
    if !SILENT.is_set().unwrap() { SILENT.set(rsa.silent).unwrap(); }
    if !rsa.silent { println!("Run args: {:?}", rsa); }
    rsa.run()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs::File;
    use std::io;
    use num::Integer;
    use num_bigint::{BigInt, Sign, ToBigInt, ToBigUint};
    use num_traits::One;
    use crate::RSA;
    use crate::RunMode;
    use crate::rsa::config::CONFIG_DEF;
    use crate::rsa::keys::{Key, KeySet};

    #[test]
    fn gen_prime() -> Result<(), Box<dyn Error>> {
        let r = CONFIG_DEF.get();
        let low = 2.to_biguint().unwrap().pow(r.prime_min);
        let high = 2.to_biguint().unwrap().pow(r.prime_max);
        let prime = r.generate_prime(&low, &high).unwrap();
        println!("got prime: {:?}", prime);
        Ok(())
    }

    #[test]
    fn test_miller_rabin() -> Result<(), Box<dyn Error>> {
        let r = CONFIG_DEF.get();
        let res = (0xffffff00 as u32..0xffffffff as u32)
            .map(|x| (x, RSA::miller_rabin(&x.to_bigint().unwrap(), r.rounds).unwrap()))
            .filter(|x| x.1)
            .map(|x| x.0)
            .collect::<Vec<_>>();
        println!("result: {:?}", res);
        Ok(())
    }

    #[test]
    fn test_mod_reverse() -> Result<(), Box<dyn Error>> {
        let r = CONFIG_DEF.get();
        let low = 2.to_biguint().unwrap().pow(r.prime_min);
        let high = 2.to_biguint().unwrap().pow(r.prime_max);
        let (p, q) = (r.generate_prime(&low, &high)?, r.generate_prime(&low, &high)?);
        let f = RSA::euler(&p, &q);
        let mut e;
        loop {
            e = r.generate_prime(&1.to_biguint().unwrap(), &f.to_biguint().unwrap())?;
            if f.gcd(&e).is_one() { break; }
        }
        let d = RSA::mod_reverse(&e, &f);
        let res = (&d * &e) % &f;
        println!("(d * e) % f = {} % {} = {}", &d * &e, f, res);
        assert!(res.is_one());
        Ok(())
    }

    #[test]
    fn test_from_bytes() {
        let data = "114514".as_bytes();
        let d = BigInt::from_bytes_le(Sign::Plus, data);
        println!("{:?} => {:?}", data, d);
    }

    #[test]
    fn function_test() -> Result<(), Box<dyn Error>> {
        let r = CONFIG_DEF.get();
        let keys = r.generate_key()?;
        println!("get keys: {:?}", keys);
        let (key_public, key_private) = (keys.public, keys.private);
        let mut reader = File::open(&r.input).unwrap();
        let mut writer_temp = File::create(&r.output).unwrap();
        RSA::process(&mut reader, &mut writer_temp, RunMode::Encode, key_public, 1, false);
        let mut reader_temp = File::open(&r.output).unwrap();
        let mut writer = io::stdout();
        RSA::process(&mut reader_temp, &mut writer, RunMode::Decode, key_private, 1, false);
        println!("\nDone.");
        Ok(())
    }

    #[test]
    fn test_simple_data() -> Result<(), Box<dyn Error>> {
        let r = CONFIG_DEF.get();
        let (p, q) = (17.to_bigint().unwrap(), 11.to_bigint().unwrap());
        let f = (&q - 1.to_bigint().unwrap()) * (&p - 1.to_bigint().unwrap());
        let e = 7.to_bigint().unwrap();
        let d = RSA::mod_reverse(&e, &f);
        let n = &p * &q;
        r.check_key_set(&d, &e, &f);
        let keys = KeySet { public: Key { m: n.clone(), base: e }, private: Key { m: n.clone(), base: d } };
        println!("keys: {:?}", keys);
        let m = BigInt::from(88);
        let c = RSA::fast_modular_exponent(m.clone(), keys.public.base, keys.public.m);
        let m2 = RSA::fast_modular_exponent(c.clone(), keys.private.base, keys.private.m);
        println!("m={}, c={}, m2={}", m, c, m2);
        Ok(())
    }

    #[test]
    fn test_vec_push() {
        let mut v = vec![1, 2, 3, 4];
        v.push(0);
        v.append(&mut vec![5]);
        println!("v={:?}", v);
    }

    #[test]
    fn test_num_bits() {
        let n = BigInt::from(0x11234567855aai64);
        let l = n.to_bytes_le().1;
        let b = n.to_bytes_be().1;
        println!("n: {}, b: {:x?}, l: {:x?}", n, b, l);
    }
}