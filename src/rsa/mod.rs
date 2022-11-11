use std::error::Error;
use std::fs::File;
use std::{io, thread};
use std::io::{Cursor, Read, Write};
use num::Integer;
use clap::Parser;
use crossbeam_channel::{bounded, Receiver, Sender};
use num_bigint::{BigInt, Sign, ToBigInt, ToBigUint};
use num_traits::{One, Pow, Zero};
use indicatif::{ProgressBar, ProgressStyle};

pub mod config;
pub mod prime_gen;
pub mod keys;

use config::*;
use keys::*;
use prime_gen::*;

#[derive(Debug, Clone)]
pub enum RunMode {
    Generate,
    Encode,
    Decode,
    Test,
}

#[macro_export]
macro_rules! rsa_t {
    ($CONFIG: expr, $NAME: ident) => {
#[derive(Debug, Parser)]
pub struct $NAME {
    #[clap(short, long, value_parser, default_value = $CONFIG.mode.as_str(), help = "Run mode")]
    pub mode: String,
    #[clap(short, long, value_parser, default_value = $CONFIG.key.as_str(), help = "Key path, generate/detect `path' and `path.pub'")]
    pub key: String,
    #[clap(short, long, value_parser, default_value = $CONFIG.comment.as_str(), help = "Attach comment to key files")]
    pub comment: String,
    #[clap(long, value_parser, default_value_t = $CONFIG.binary, help = "Output key in binary format")]
    pub binary: bool,
    #[clap(short, long, value_parser, default_value = $CONFIG.input.as_str(), help = "Input filename")]
    pub input: String,
    #[clap(short, long, value_parser, default_value = $CONFIG.output.as_str(), help = "Output filename")]
    pub output: String,
    #[clap(long, value_parser, required = false, default_value_t = $CONFIG.prime_min, help = "Min prime bits")]
    pub prime_min: u32,
    #[clap(long, value_parser, required = false, default_value_t = $CONFIG.prime_max, help = "Max prime bits")]
    pub prime_max: u32,
    #[clap(short, long, value_parser, default_value_t = $CONFIG.rounds, help = "Miller Rabin calculate rounds")]
    pub rounds: u32,
    #[clap(long, value_parser, default_value_t = $CONFIG.time_max, help = "Max time in mill seconds that trying to generate a prime")]
    pub time_max: i64,
    #[clap(short, long, value_parser, default_value_t = $CONFIG.silent, help = "Disable log output")]
    pub silent: bool,
    #[clap(long, value_parser, default_value_t = $CONFIG.retry, help = "Retry when failed to generate primes")]
    pub retry: bool,
    #[clap(short, long, value_parser, default_value_t = $CONFIG.threads, help = "Calculate in <THREADS> threads")]
    pub threads: usize,
}
    };
}

rsa_t!(CONFIG_DEF, RSA);

impl RSA {
    pub fn get(&self) -> &RSA {
        self
    }

    pub fn copy(&self) -> RSA {
        RSA {
            prime_min: self.prime_min,
            prime_max: self.prime_max,
            input: self.input.clone(),
            output: self.output.clone(),
            binary: self.binary,
            rounds: self.rounds,
            time_max: self.time_max,
            mode: self.mode.clone(),
            silent: self.silent,
            key: self.key.clone(),
            threads: self.threads,
            retry: self.retry,
            comment: self.comment.clone(),
        }
    }

    pub fn set(&mut self, other: RSA) {
        *self = other;
    }

    pub fn reader(&self) -> Box<dyn Read> {
        match self.input.as_str() {
            "stdin" => Box::new(io::stdin()),
            f => Box::new(File::open(f).unwrap())
        }
    }

    pub fn writer(&mut self) -> Box<dyn Write> {
        match self.output.as_str() {
            "stdout" => {
                self.silent = true;
                Box::new(io::stdout())
            }
            f => Box::new(File::create(f).unwrap())
        }
    }

    fn run_mode(&self) -> RunMode {
        match self.mode.as_str() {
            "encode" => Ok(RunMode::Encode),
            "decode" => Ok(RunMode::Decode),
            "generate" => Ok(RunMode::Generate),
            "test" => Ok(RunMode::Test),
            _ => Err("Unknown run mode! available: generate(default), encode, decode, test")
        }.unwrap()
    }

    pub fn euler(p: &BigInt, q: &BigInt) -> BigInt { (p - 1.to_bigint().unwrap()) * (q - 1.to_bigint().unwrap()) }

    fn extended_euclid(a: &BigInt, b: &BigInt, x: &BigInt, y: &BigInt) -> (BigInt, BigInt, BigInt) {
        if b.is_zero() {
            return (a.clone(), 1.to_bigint().unwrap(), 0.to_bigint().unwrap());
        }
        let (d, x2, y2) = RSA::extended_euclid(b, &(a % b), y, x);
        return (d, y2.clone(), x2 - a / b * &y2);
    }

    pub fn mod_reverse(a: &BigInt, b: &BigInt) -> BigInt {
        let d = RSA::extended_euclid(a, b, &Zero::zero(), &One::one());
        if d.0.is_one() {
            (d.1 % b + b) % b
        } else {
            Zero::zero()
        }
    }

    pub fn generate_key(&self) -> Result<KeySet, PrimeError> {
        let low = 2.to_biguint().unwrap().pow(self.prime_min);
        let high = 2.to_biguint().unwrap().pow(self.prime_max);
        let (p, q) = (self.generate_prime(&low, &high)?, self.generate_prime(&low, &high)?);
        let n = &p * &q;
        let f = RSA::euler(&p, &q);
        let mut e;
        loop {
            e = self.generate_prime(&1.to_biguint().unwrap(), &f.to_biguint().unwrap())?;
            if f.gcd(&e).is_one() { break; }
        }
        let d = RSA::mod_reverse(&e, &f);
        self.check_key_set(&d, &e, &f);
        Ok(KeySet { public: Key { m: n.clone(), base: e }, private: Key { m: n.clone(), base: d } })
    }

    pub fn check_key_set(&self, d: &BigInt, e: &BigInt, f: &BigInt) {
        let res = (d * e) % f;
        if !self.silent {
            println!("(d * e) % f = {} % {} = {}", d * e, f, res);
        }
        assert!(res.is_one());
    }

    pub fn read_source(reader: &mut dyn Read, bytes: usize) -> Vec<u8> {
        let mut source = [0 as u8; 1];
        let mut res = Vec::new();
        loop {
            match reader.read(source.as_mut()) {
                Ok(n) => match n {
                    0 => break,
                    _ => {
                        res.push(source[0]);
                        if res.len() >= bytes { break; }
                    }
                },
                _ => break
            }
        }
        res
    }

    fn get_group_size_byte(n: &BigInt) -> usize { f64::pow(2 as f64, ((n.bits() as usize / 8) as f64).log2().ceil()) as usize / 2 }

    pub fn process(reader: &mut dyn Read, writer: &mut dyn Write, mode: RunMode, key: Key, threads: usize, silent: bool) {
        let group_size = RSA::get_group_size_byte(&key.m) * match mode {
            RunMode::Decode => 2,
            _ => 1
        };
        let source_len_target = match mode {
            RunMode::Encode => group_size,
            _ => group_size
        };
        let res_len_target = match mode {
            RunMode::Encode => group_size * 2,
            _ => group_size / 2
        };
        if !silent { println!("group size {}, input => output: {} => {}", group_size, source_len_target, res_len_target); }
        let mut source_data: Vec<Vec<u8>> = Vec::new();
        let mut filesize_data = match mode {
            RunMode::Decode => {
                let mut t = [0 as u8; 8];
                let n = reader.read(&mut t).unwrap();
                assert_eq!(n, 8, "Too small file!");
                u64::from_le_bytes(t)
            }
            _ => 0
        };
        loop {
            let source = RSA::read_source(reader, source_len_target);
            if source.is_empty() { break; }
            source_data.push(source);
        };
        let chunks = source_data.len();
        let filesize_read = source_data.iter().map(|v| v.len()).sum::<usize>() as u64;
        if filesize_data == 0 {
            filesize_data = filesize_read;
        }
        if !silent { println!("source chunk: {}", chunks); }
        let (map_tx, map_rx): (Sender<(usize, Key, Vec<u8>, RunMode)>, Receiver<(usize, Key, Vec<u8>, RunMode)>) = bounded(threads);
        let (reduce_tx, reduce_rx) = bounded(threads);
        let pb = match silent {
            true => None,
            false => Some(ProgressBar::new((source_data.len() * group_size) as u64)),
        };
        if let Some(pb) = &pb {
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap()
                .progress_chars("#>-"));
        }
        let handles = (0..threads).map(|_i| {
            let r = map_rx.clone();
            let s = reduce_tx.clone();
            thread::spawn(move || {
                loop {
                    match r.recv() {
                        Ok(r) => {
                            let (index, key, source, mode) = r;
                            let data = BigInt::from_bytes_le(Sign::Plus, source.as_slice());
                            let res = RSA::fast_modular_exponent(data.clone(), key.base.clone(), key.m.clone());
                            let mut res_data = res.to_bytes_le().1.clone();
                            let res_data_len = res_data.len();
                            match mode {
                                RunMode::Encode | RunMode::Decode => {
                                    let fill = res_len_target - res_data_len;
                                    if fill != 0 && chunks != index + 1 {
                                        // println!("fill {} bytes", fill);
                                        for _ in 0..fill { res_data.push(0); }
                                    }
                                }
                                _ => {}
                            };
                            if chunks != index + 1 { assert_eq!(res_len_target, res_data.len()); }
                            s.send((index, res_data)).unwrap();
                        }
                        _ => break
                    }
                }
            })
        }).collect::<Vec<_>>();
        let mut res_collect = Vec::new();
        for i in 0..source_data.len() {
            match reduce_rx.try_recv() {
                Ok(r) => {
                    res_collect.push(r);
                    if let Some(pb) = &pb {
                        pb.inc(group_size as u64);
                    }
                }
                _ => {}
            };
            map_tx.send((i, key.clone(), source_data[i].clone(), mode.clone())).unwrap();
        }
        drop(map_tx);
        let left = source_data.len() - res_collect.len();
        for _ in 0..left {
            let r = reduce_rx.recv().unwrap();
            res_collect.push(r);
            if let Some(pb) = &pb {
                pb.inc(group_size as u64);
            }
        }
        if let Some(pb) = &pb {
            pb.finish_with_message("Done");
        }
        for handle in handles { handle.join().unwrap(); }
        res_collect.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        for i in 0..res_collect.len() {
            assert_eq!(i, res_collect[i].0);
        }
        assert_eq!(res_collect.len(), source_data.len());
        if !silent { println!("read filesize: {filesize_read}, data filesize: {filesize_data} res chunk: {}", res_collect.len()); }
        let res_collect = res_collect.iter().map(|x| x.1.clone()).collect::<Vec<_>>();
        match mode {
            RunMode::Encode => {
                writer.write(&filesize_data.to_le_bytes()).unwrap();
            }
            _ => {}
        };
        for res_data in &res_collect {
            writer.write(&res_data).unwrap();
        }
        match mode {
            RunMode::Decode => for _ in 0..(filesize_data - res_collect.iter().map(|v| v.len()).sum::<usize>() as u64) {
                writer.write(&[0 as u8; 1]).unwrap();
            },
            _ => {}
        };
        writer.flush().unwrap();
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        match self.run_mode() {
            RunMode::Generate => {
                let key_set = self.generate_key()?;
                if !self.silent { println!("get keys: {:?}", key_set); }
                let mut key_pair = KeyPair {
                    public: KeyData::new_public(key_set.public, self.comment.clone()),
                    private: KeyData::new_private(key_set.private, self.comment.clone()),
                };
                key_pair.private.generate_header_footer_bits(self.prime_max as usize);
                key_pair.public.generate_header_footer_bits(self.prime_max as usize);
                if !self.silent { println!("get key_pair: {:?}", key_pair); }
                key_pair.save(self.key.clone(), !self.binary).unwrap();
                if !self.silent { println!("Generated key files: {}, {}", self.key.clone(), self.key.clone() + ".pub"); }
            }
            RunMode::Test => {
                let key_pair = KeyPair::from(self.key.clone());
                if key_pair.public == KeyData::default() || key_pair.private == KeyData::default() {
                    let key = if key_pair.public == KeyData::default() {
                        key_pair.private
                    } else {
                        key_pair.public
                    };
                    if !self.silent { print!("key infomation: "); }
                    key.info();
                } else {
                    key_pair.public.info();
                    key_pair.private.info();
                    if !self.silent { println!("start testing key pair"); }
                    if !self.silent { println!("get key_pair: {:?}", key_pair); }
                    assert_eq!(key_pair.public.key.m, key_pair.private.key.m);
                    let group_size = RSA::get_group_size_byte(&key_pair.public.key.m);
                    let res_len_target = |mode| match mode {
                        RunMode::Encode => 2 * group_size,
                        _ => group_size
                    };
                    let mut reader = if self.input != "stdin" { self.reader() } else { Box::new(File::open("/dev/random").unwrap()) };
                    let max_source_len = 1000;
                    let mut source_data: Vec<Vec<u8>> = Vec::new();
                    for _ in 0..max_source_len {
                        let source = RSA::read_source(&mut reader, group_size);
                        if source.is_empty() { break; }
                        source_data.push(source);
                    }
                    let pb = match self.silent {
                        true => None,
                        false => Some(ProgressBar::new((source_data.len() * group_size) as u64)),
                    };
                    if let Some(pb) = &pb {
                        pb.set_style(ProgressStyle::default_bar()
                            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap()
                            .progress_chars("#>-"));
                    }
                    let mut file_writer = if self.output != "stdout" {
                        Some(Box::new(File::create(self.output.as_str()).unwrap()))
                    } else { None };
                    for source in source_data {
                        let m = BigInt::from_bytes_le(Sign::Plus, &source);
                        let c = RSA::fast_modular_exponent(m.clone(), key_pair.public.key.base.clone(), key_pair.public.key.m.clone());
                        let m2 = RSA::fast_modular_exponent(c.clone(), key_pair.private.key.base.clone(), key_pair.private.key.m.clone());
                        assert_eq!(m, m2);
                        let mut buf: Vec<u8> = Vec::new();
                        let mut writer = Cursor::new(&mut buf);
                        writer.write_all(&c.to_bytes_le().1).unwrap();
                        let buf_len = (c.bits() as f64 / 8.0).ceil() as usize;
                        for _ in 0..(res_len_target(RunMode::Encode) - buf_len as usize) { writer.write(&[0]).unwrap(); }
                        writer.flush().unwrap();
                        assert_eq!(2 * group_size, buf.len());
                        let c2 = BigInt::from_bytes_le(Sign::Plus, &buf);
                        assert_eq!(c, c2);
                        let m3 = RSA::fast_modular_exponent(c2.clone(), key_pair.private.key.base.clone(), key_pair.private.key.m.clone());
                        assert_eq!(m2, m3);
                        assert_eq!(m2.to_bytes_le().1, m3.to_bytes_le().1);
                        let mut buf: Vec<u8> = Vec::new();
                        let mut writer = Cursor::new(&mut buf);
                        writer.write_all(&m3.to_bytes_le().1).unwrap();
                        let buf_len = (m3.bits() as f64 / 8.0).ceil() as usize;
                        for _ in 0..(res_len_target(RunMode::Decode) - buf_len as usize) { writer.write(&[0]).unwrap(); }
                        writer.flush().unwrap();
                        assert_eq!(source, buf);
                        if let Some(pb) = &pb {
                            pb.inc(group_size as u64);
                        }
                        if let Some(file_writer) = &mut file_writer {
                            file_writer.write_all(&buf).unwrap();
                            file_writer.flush().unwrap();
                        }
                    }
                    if let Some(pb) = &pb {
                        pb.finish_with_message("Test pass");
                    }
                    if !self.silent { println!("Test pass"); };
                }
            }
            RunMode::Encode | RunMode::Decode => {
                let mut reader = self.reader();
                let mut writer = self.writer();
                let path = match self.run_mode() {
                    RunMode::Decode => self.key.clone(),
                    _ => self.key.clone() + ".pub"
                };
                let key = KeyData::from(path);
                RSA::process(&mut reader, &mut writer, self.run_mode(), key.key, self.threads, self.silent);
                if !self.silent { println!("Done"); };
            }
        }
        Ok(())
    }
}
