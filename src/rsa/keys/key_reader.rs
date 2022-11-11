use std::fs::File;
use std::io;
use std::io::{BufRead, Cursor, Read, Seek, SeekFrom};
use num_bigint::{BigInt, Sign};
use crate::rsa::keys::{KeyError, Key};
use crate::rsa::keys::key_data::KeyData;

const READER_JUDGE_BUF: usize = 4;

pub struct KeyReader {
    reader: Box<dyn Read>,
    pub binary: Option<bool>,
    temp: [u8; READER_JUDGE_BUF],
    read_buf: Vec<u8>,
    res_buf: Vec<u8>,
    cur: u64,
    header: String,
    footer: String,
}

// static KEY_DEBUG: bool = true;
static KEY_DEBUG: bool = false;

impl KeyReader {
    pub fn new(reader: Box<dyn Read>) -> Self {
        let mut s = Self { reader, binary: None, temp: [0; READER_JUDGE_BUF], read_buf: vec![], res_buf: vec![], cur: 0, header: "".to_string(), footer: "".to_string() };
        s.judge_binary().unwrap();
        if !s.binary.unwrap() { s.parse_text().unwrap(); } else { s.res_buf.append(&mut s.read_buf); }
        if KEY_DEBUG {
            println!("res_buf: {:x?}", s.res_buf);
            if !s.binary.unwrap() { println!("res: {:?}", String::from_utf8(s.res_buf.clone())); }
        }
        s
    }

    pub fn read_all(&mut self) -> Vec<u8> {
        let mut content = Vec::new();
        if !self.binary.unwrap() {
            let mut data_reader = base64::read::DecoderReader::new(
                self,
                base64::STANDARD);
            data_reader.read_to_end(&mut content).unwrap();
        } else {
            self.read_to_end(&mut content).unwrap();
        }
        content
    }

    fn parse_text(&mut self) -> Result<(), KeyError> {
        let mut cur = Cursor::new(&self.read_buf);
        let mut line = String::new();
        while let Ok(n) = cur.read_line(&mut line) {
            if KEY_DEBUG { println!("line: {}", line); }
            if n > 0 {
                if !line.starts_with("-") {
                    for c in line.as_bytes() {
                        if *c != '\n' as u8 { self.res_buf.push(*c); }
                    }
                } else {
                    if line.contains("END") {
                        self.footer = line.replace("\n", "");
                    } else {
                        self.header = line.replace("\n", "");
                    }
                }
            } else { break; }
            line.clear();
        }
        // self.cur = Some(Cursor::new(self.res_buf.clone()));
        Ok(())
    }

    fn judge_binary(&mut self) -> Result<(), KeyError> {
        if self.binary.is_none() {
            match self.reader.read(&mut self.temp) {
                Ok(n) => match n {
                    READER_JUDGE_BUF => {
                        let count = self.temp.iter().filter(|x| x.is_ascii_graphic()).count();
                        self.binary = Some(count < READER_JUDGE_BUF);
                        if KEY_DEBUG { println!("binary: {:?}", self.binary); }
                        for t in self.temp { self.read_buf.push(t); }
                        if KEY_DEBUG { println!("count: {}, data: {:?}, temp: {:x?}, read_buf: {:x?}", count, String::from_utf8(self.temp.to_vec()), self.temp, self.read_buf); }
                        self.reader.read_to_end(&mut self.read_buf).unwrap();
                        Ok(())
                    }
                    _ => Err(KeyError::ParseError("Data length not enough".to_string()))
                },
                _ => Err(KeyError::ParseError("Read data error".to_string()))
            }
        } else {
            Ok(())
        }
    }
}

impl Read for KeyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.binary {
            Some(_) => {
                let mut reader = Cursor::new(&self.res_buf);
                reader.seek(SeekFrom::Start(self.cur)).unwrap();
                let res = reader.read(buf);
                match &res {
                    Ok(n) => self.cur += *n as u64,
                    _ => {}
                }
                res
            }
            None => panic!("Call `self.judge_binary()' first!")
        }
    }
}

impl From<String> for KeyData {
    fn from(path: String) -> Self {
        let file = File::open(path);
        match file {
            Err(_) => return KeyData::default(),
            _ => {}
        };
        let mut key_reader = KeyReader::new(Box::new(file.unwrap()));
        let content = key_reader.read_all();
        let mut cur = Cursor::new(&content);
        let mut len_base: [u8; 4] = [0; 4];
        let mut len_m: [u8; 4] = [0; 4];
        cur.read(&mut len_base).unwrap();
        cur.read(&mut len_m).unwrap();
        let (len_base, len_m) = (u32::from_le_bytes(len_base) as usize, u32::from_le_bytes(len_m) as usize);
        let mut data = Vec::new();
        cur.read_to_end(&mut data).unwrap();
        let mut content_base = Vec::new();
        let mut content_m = Vec::new();
        if KEY_DEBUG { println!("got content size: 0x{:x}, data size: 0x{:x}, base len: 0x{:x}, m len: 0x{:x}", content.len(), data.len(), len_base, len_m); }
        for i in 0..len_base {
            content_base.push(data[i]);
        }
        for i in len_base..(len_base + len_m) {
            content_m.push(data[i]);
        }
        let base = BigInt::from_bytes_le(Sign::Plus, content_base.as_slice());
        let m = BigInt::from_bytes_le(Sign::Plus, content_m.as_slice());
        let mut mode: [u8; 7] = [0; 7];
        let mut cur = Cursor::new(data);
        cur.seek(SeekFrom::Start((len_base + len_m) as u64)).unwrap();
        cur.read(&mut mode).unwrap();
        let mut comment = Vec::new();
        cur.read_to_end(&mut comment).unwrap();
        KeyData {
            mode: String::from_utf8(mode.to_vec()).unwrap(),
            comment: String::from_utf8(comment).unwrap(),
            key: Key { base, m },
            header: key_reader.header,
            footer: key_reader.footer,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs::File;
    use std::io::Read;
    use crate::rsa::keys::key_data::KeyData;
    use crate::rsa::keys::key_pair::KeyPair;
    use crate::rsa::keys::key_reader::KeyReader;

    #[test]
    fn test_binary() -> Result<(), Box<dyn Error>> {
        let reader = KeyReader::new(Box::new(File::open("build/linux/x86_64/release/rsa").unwrap()));
        println!("binary: {:?}", reader.binary);
        let reader = KeyReader::new(Box::new(File::open("data/test.pub").unwrap()));
        println!("binary: {:?}", reader.binary);
        Ok(())
    }

    #[test]
    fn test_base64() -> Result<(), Box<dyn Error>> {
        let mut reader = KeyReader::new(Box::new(File::open("data/test.pub").unwrap()));
        println!("binary: {:?}", reader.binary);
        let mut reader = base64::read::DecoderReader::new(&mut reader, base64::STANDARD);
        let mut res = Vec::new();
        reader.read_to_end(&mut res).unwrap();
        println!("res: {:x?}", res);
        Ok(())
    }

    #[test]
    fn test_load() -> Result<(), Box<dyn Error>> {
        let key = KeyData::from("data/test.pub".to_string());
        println!("got key data: {:?}", key);
        Ok(())
    }

    #[test]
    fn test_key_pair_load() -> Result<(), Box<dyn Error>> {
        let key_pair = KeyPair::from("data/test".to_string());
        println!("got pair: {:?}", key_pair);
        Ok(())
    }
}
