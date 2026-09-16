use std::path::PathBuf;

use interop::{BoxError, TestCertificate};
use tempfile::TempDir;

pub struct CertificateFiles {
    _dir: TempDir,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl CertificateFiles {
    pub fn new(cert: &TestCertificate) -> Result<Self, BoxError> {
        let dir = TempDir::new()?;
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");

        std::fs::write(&cert_path, &cert.cert_pem)?;
        std::fs::write(&key_path, &cert.key_pem)?;

        Ok(Self {
            _dir: dir,
            cert_path,
            key_path,
        })
    }
}
