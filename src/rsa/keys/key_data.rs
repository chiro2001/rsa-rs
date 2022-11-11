use crate::rsa::keys::*;

#[derive(Debug)]
pub struct KeyData {
    pub(crate) mode: String,
    pub(crate) comment: String,
    pub(crate) key: Key,
    pub(crate) header: String,
    pub(crate) footer: String,
}

impl Default for KeyData {
    fn default() -> Self {
        Self {
            mode: "".to_string(),
            comment: "".to_string(),
            key: Key::default(),
            header: "".to_string(),
            footer: "".to_string(),
        }
    }
}

impl PartialEq for KeyData {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl KeyData {
    pub fn generate_header_footer(&mut self) {
        self.header = format!("-----BEGIN RSA-RS {} KEY-----", self.mode.to_uppercase());
        self.footer = format!("-----END RSA-RS {} KEY-----", self.mode.to_uppercase());
    }

    pub fn generate_header_footer_bits(&mut self, bits: usize) {
        self.header = format!("-----BEGIN RSA-{} {} KEY-----", bits, self.mode.to_uppercase());
        self.footer = format!("-----END RSA-{} {} KEY-----", bits, self.mode.to_uppercase());
    }

    pub fn new_public(key: Key, comment: String) -> Self {
        Self {
            mode: "PUBLIC_".to_string(),
            comment,
            key,
            header: "".to_string(),
            footer: "".to_string(),
        }
    }

    pub fn new_private(key: Key, comment: String) -> Self {
        Self {
            mode: "PRIVATE".to_string(),
            comment,
            key,
            header: "".to_string(),
            footer: "".to_string(),
        }
    }

    pub fn info(&self) {
        println!("{} key, comment: {}", self.mode, self.comment);
    }
}