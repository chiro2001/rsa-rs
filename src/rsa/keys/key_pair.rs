use std::error::Error;
use crate::rsa::keys::key_data::*;

#[derive(Debug)]
pub struct KeyPair {
    pub public: KeyData,
    pub private: KeyData,
}

impl From<String> for KeyPair {
    fn from(path: String) -> Self {
        let path_public = path.clone() + ".pub";
        Self { public: KeyData::from(path_public), private: KeyData::from(path) }
    }
}

impl KeyPair {
    pub fn save(&mut self, path: String, base64_output: bool) -> Result<(), Box<dyn Error>> {
        let path_public = path.clone() + ".pub";
        self.public.save(path_public, base64_output).unwrap();
        self.private.save(path, base64_output).unwrap();
        Ok(())
    }
}