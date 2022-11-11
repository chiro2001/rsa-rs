use std::fs::File;
use std::io::{Cursor, Read, Write};
use crate::rsa::keys::{BASE64_SPLIT, KeyError};
use crate::rsa::keys::key_data::KeyData;

pub struct KeyWriter {
    writer: Box<dyn Write>,
    buffer: Vec<u8>,
    pub header: String,
    pub footer: String,
}

impl From<Box<(dyn Write + 'static)>> for KeyWriter {
    fn from(f: Box<(dyn Write + 'static)>) -> Self {
        Self::new(f)
    }
}

impl From<File> for KeyWriter {
    fn from(f: File) -> Self {
        Self::new(Box::new(f))
    }
}

impl From<Box<File>> for KeyWriter {
    fn from(f: Box<File>) -> Self {
        Self::new(f)
    }
}

impl KeyWriter {
    pub fn new(f: Box<dyn Write>) -> Self {
        KeyWriter {
            writer: f,
            buffer: vec![],
            header: "".to_string(),
            footer: "".to_string(),
        }
    }
}

impl Write for KeyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for b in buf { self.buffer.push(*b); }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut cur = Cursor::new(&self.buffer);
        self.writer.write_all(self.header.as_bytes()).unwrap();
        self.writer.write_all("\n".as_bytes()).unwrap();
        loop {
            let mut buf: [u8; BASE64_SPLIT] = [0; BASE64_SPLIT];
            let n = cur.read(&mut buf);
            match n {
                Ok(0) => break,
                Err(_) => break,
                _ => {}
            }
            let n = n.unwrap();
            self.writer.write_all(&buf[0..n]).unwrap();
            self.writer.write_all("\n".as_bytes()).unwrap();
        }
        self.writer.write_all(self.footer.as_bytes()).unwrap();
        self.writer.flush()
    }
}

impl KeyData {
    pub fn save(&mut self, path: String, base64_output: bool) -> Result<(), KeyError> {
        if self.footer.is_empty() && self.header.is_empty() {
            self.generate_header_footer();
        }
        let base = self.key.base.to_bytes_le().1;
        let m = self.key.m.to_bytes_le().1;
        let mut f: Box<dyn Write> = match base64_output {
            true => {
                let mut key_writer = KeyWriter::from(Box::new(File::create(path).unwrap()));
                key_writer.header = self.header.clone();
                key_writer.footer = self.footer.clone();
                Box::new(base64::write::EncoderWriter::new(
                    key_writer,
                    base64::STANDARD))
            }
            false => Box::new(File::create(path).unwrap())
        };
        let lens: [u32; 2] = [base.len() as u32, m.len() as u32];
        f.write_all(&lens[0].to_le_bytes()).unwrap();
        f.write_all(&lens[1].to_le_bytes()).unwrap();
        f.write_all(base.as_slice()).unwrap();
        f.write_all(m.as_slice()).unwrap();
        let mut mode = [0 as u8; 7];
        for (a, b) in mode.iter_mut().zip(self.mode.bytes()) {
            *a = b;
        }
        f.write_all(&mode).unwrap();
        f.write_all(self.comment.as_bytes()).unwrap();
        f.flush().unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use crate::rsa::config::CONFIG_DEF;
    use crate::rsa::keys::key_data::KeyData;
    use crate::rsa::keys::key_pair::KeyPair;

    #[test]
    fn key_pair_save_test() -> Result<(), Box<dyn Error>> {
        let rsa = CONFIG_DEF.get().copy();
        let key_set = rsa.generate_key().unwrap();
        let mut key_pair = KeyPair {
            public: KeyData::new_public(key_set.public, "Hello RSA!".to_string()),
            private: KeyData::new_private(key_set.private, "Hello RSA!".to_string()),
        };
        key_pair.save("data/test".to_string(), true).unwrap();
        Ok(())
    }
}