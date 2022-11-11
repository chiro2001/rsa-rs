use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::sync::mpsc;
use std::thread;
use chrono::Local;
use lazy_static::lazy_static;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_traits::*;
use crate::rsa::prime_gen::PrimeError::Timeout;
use crate::RSA;
use mut_static::MutStatic;
use crate::rsa::config::SILENT;

pub enum PrimeError {
    Timeout(i64)
}

impl PrimeError {
    fn display(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Timeout(time) => write!(f, "Generation timeout after {} ms", time)
        }
    }
}

impl Display for PrimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.display(f)
    }
}

impl Debug for PrimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.display(f)
    }
}

impl Error for PrimeError {}

lazy_static! {
    pub static ref PRIMES_CACHE: MutStatic<Vec<BigInt>> = MutStatic::from(Vec::new());
}

impl RSA {
    pub fn fast_modular_exponent(mut a: BigInt, mut q: BigInt, n: BigInt) -> BigInt {
        let mut r: BigInt = One::one();
        while q != Zero::zero() {
            if q.bit(0) { r = (r * &a) % &n; }
            q >>= 1;
            a = (&a * &a) % &n;
        }
        r
    }

    pub fn miller_rabin(n: &BigInt, rounds: u32) -> Result<bool, Box<dyn Error>> {
        if n.is_zero() { return Ok(true); }
        if !n.bit(0) || n.is_one() { return Ok(false); }
        let mut rng = rand::thread_rng();
        let mut d: BigInt = n - 1.to_bigint().unwrap();
        while d.bit(0) { d >>= 1; }
        let tmp = d.clone();
        for _ in 0..rounds {
            d = tmp.clone();
            let mut m = RSA::fast_modular_exponent(
                rng.gen_biguint_range(&Zero::zero(), &((n - 2.to_bigint().unwrap()).to_biguint().unwrap())).to_bigint().unwrap() + 2.to_bigint().unwrap(),
                d.clone(), n.clone());
            if m == One::one() { continue; } else {
                let mut pass = false;
                while d < *n {
                    if m == n - 1.to_bigint().unwrap() {
                        pass = true;
                        break;
                    }
                    m = (&m * &m) % n;
                    d <<= 1;
                }
                if !pass { return Ok(false); }
            }
        }
        Ok(true)
    }

    pub fn generate_prime(&self, low: &BigUint, high: &BigUint) -> Result<BigInt, PrimeError> {
        if !PRIMES_CACHE.read().unwrap().is_empty() {
            let prime = PRIMES_CACHE.write().unwrap().pop().unwrap().clone();
            if !SILENT.read().unwrap().clone() { println!("Use cached prime: {}", prime); }
            return Ok(prime);
        }
        let t: usize = self.threads;
        let l = (0..t).map(|_x| low.clone());
        let h = (0..t).map(|_x| high.clone());
        let (tx, rx) = mpsc::channel();
        let handles = l.zip(h).map(|x| {
            let tx = tx.clone();
            let (rounds, time_max) = (self.rounds, self.time_max);
            thread::spawn(move || {
                tx.send(RSA::generate_one_prime(&x.0, &x.1, rounds, time_max)).unwrap();
            })
        }).collect::<Vec<_>>();
        for _ in 0..t {
            match rx.recv().unwrap() {
                Ok(r) => PRIMES_CACHE.write().unwrap().push(r),
                _ => {}
            }
        }
        for handle in handles { handle.join().unwrap(); }
        if PRIMES_CACHE.read().unwrap().is_empty() {
            if self.retry {
                self.generate_prime(low, high)
            } else {
                Err(Timeout(self.time_max))
            }
        } else {
            Ok(PRIMES_CACHE.write().unwrap().pop().unwrap())
        }
    }

    pub fn generate_one_prime(low: &BigUint, high: &BigUint, rounds: u32, time_max: i64) -> Result<BigInt, PrimeError> {
        let mut rng = rand::thread_rng();
        let epoch = 0xf;
        let start = Local::now().timestamp_millis();
        let mut try_times = 0;
        loop {
            try_times += &epoch;
            for _ in 0..epoch {
                let test = rng.gen_biguint_range(&low, &high).to_bigint().unwrap();
                if RSA::miller_rabin(&test, rounds).unwrap() {
                    let now = Local::now().timestamp_millis();
                    let time = now - start;
                    if !SILENT.read().unwrap().clone() {
                        println!("Done generation in {} tries after {} ms", try_times, time);
                    }
                    return Ok(test);
                }
            }
            let now = Local::now().timestamp_millis();
            let time = now - start;
            if time > time_max {
                if !SILENT.read().unwrap().clone() {
                    println!("Failed generation in {} tries after {} ms", try_times, time);
                }
                return Err(Timeout(time));
            }
        }
    }
}